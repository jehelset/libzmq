/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"

#include <string.h>
#include <iostream>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "sspi_mechanism_base.hpp"
#include "sspi_server.hpp"
#include "wire.hpp"

#if defined(HAVE_SSPI)

// std::string sspi_server_mechanism_name(const options_t &options){
//     return "Kerberos;"
// }

zmq::sspi_server_t::sspi_server_t (session_base_t *session_,
                                       const std::string &peer_address_,
                                       const options_t &options_) :                                   
    mechanism_base_t (session_, options_),
    sspi_mechanism_base_t (session_, options_),
    zap_client_t (session_, peer_address_, options_),
    session (session_),
    peer_address (peer_address_),
    state (recv_next_token),
    security_context_established (false)
{
    maj_stat =
        AcquireCredentialsHandle(
            (LPSTR)principal_name.c_str(),
            (LPSTR)mechanism_name.c_str(),
            SECPKG_CRED_INBOUND,
            NULL,
            NULL,
            NULL,
            NULL,
            &cred,
            &cred_expiry
        );
    check_retcode (maj_stat);
    maj_stat = SEC_I_CONTINUE_NEEDED;
    // maj_stat = GSS_S_CONTINUE_NEEDED;
    // if (!options_.gss_principal.empty ()) {
    //     const std::string::size_type principal_size =
    //       options_.gss_principal.size ();
    //     principal_name = static_cast<char *> (malloc (principal_size + 1));
    //     assert (principal_name);
    //     memcpy (principal_name, options_.gss_principal.c_str (),
    //             principal_size + 1);
    //     // gss_OID name_type = convert_nametype (options_.gss_principal_nt);
    //     // if (acquire_credentials (principal_name, &cred, name_type) != 0)
    //     //     maj_stat = GSS_S_FAILURE;
    // }
}

zmq::sspi_server_t::~sspi_server_t ()
{
    //     gss_release_cred (&min_stat, &cred);

    // if (target_name)
    //     gss_release_name (&min_stat, &target_name);
}

int zmq::sspi_server_t::next_handshake_command (msg_t *msg_)
{
    if (state == send_ready) {
        int rc = produce_ready (msg_);
        if (rc == 0)
            state = recv_ready;

        return rc;
    }

    if (state != send_next_token) {
        errno = EAGAIN;
        return -1;
    }

    if (produce_next_token (msg_) < 0)
        return -1;

    if (maj_stat != SEC_I_CONTINUE_NEEDED && maj_stat != SEC_E_OK)
        return -1;

    if (maj_stat == SEC_E_OK) 
        security_context_established = true;

    state = recv_next_token;

    return 0;
}

int zmq::sspi_server_t::process_handshake_command (msg_t *msg_)
{
    if (state == recv_ready) {
        int rc = process_ready (msg_);
        if (rc == 0)
            state = connected;

        return rc;
    }

    if (state != recv_next_token) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }

    if (security_context_established) {
        //  Use ZAP protocol (RFC 27) to authenticate the user.
        //  Note that rc will be -1 only if ZAP is not set up, but if it was
        //  requested and it does not work properly the program will abort.
        bool expecting_zap_reply = false;
        int rc = session->zap_connect ();
        if (rc == 0) {
            send_zap_request ();
            rc = receive_and_process_zap_reply ();
            if (rc != 0) {
                if (rc == -1)
                    return -1;
                expecting_zap_reply = true;
            }
        }
        state = expecting_zap_reply ? expect_zap_reply : send_ready;
        return 0;
    }

    if (process_next_token (msg_) < 0)
        return -1;

    accept_context ();
    state = send_next_token;

    errno_assert (msg_->close () == 0);
    errno_assert (msg_->init () == 0);

    return 0;
}

void zmq::sspi_server_t::send_zap_request ()
{
    zap_client_t::send_zap_request ("SSPI", 4, (uint8_t*)&context , sizeof(decltype(context)));
}

int zmq::sspi_server_t::encode (msg_t *msg_)
{
    zmq_assert (state == connected);

    if (do_encryption)
        return encode_message (msg_);

    return 0;
}

int zmq::sspi_server_t::decode (msg_t *msg_)
{
    zmq_assert (state == connected);

    if (do_encryption)
        return decode_message (msg_);

    return 0;
}

int zmq::sspi_server_t::zap_msg_available ()
{
    if (state != expect_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        state = send_ready;
    return rc == -1 ? -1 : 0;
}

zmq::mechanism_t::status_t zmq::sspi_server_t::status () const
{
    return state == connected ? mechanism_t::ready : mechanism_t::handshaking;
}

int zmq::sspi_server_t::produce_next_token (msg_t *msg_)
{
    if (send_tok.pvBuffer != 0) { // Client expects another token
        if (produce_initiate (msg_, send_tok.pvBuffer, send_tok.cbBuffer) < 0)
            return -1;
        FreeContextBuffer(send_tok.pvBuffer);
    }

    if (maj_stat != SEC_E_OK && maj_stat != SEC_I_CONTINUE_NEEDED) {
        // if (context != GSS_C_NO_CONTEXT)
        //     gss_delete_sec_context (&min_stat, &context, GSS_C_NO_BUFFER);
        return -1;
    }

    return 0;
}

int zmq::sspi_server_t::process_next_token (msg_t *msg_)
{
    if (maj_stat == SEC_I_CONTINUE_NEEDED) {
        recv_tok.cbBuffer = 0;
        recv_tok.BufferType = SECBUFFER_TOKEN;
        recv_tok.pvBuffer = NULL;
        recv_tok_desc.ulVersion = SECBUFFER_VERSION;
        recv_tok_desc.cBuffers = 1;
        recv_tok_desc.pBuffers = &recv_tok;
        if (process_initiate (msg_, &recv_tok.pvBuffer, recv_tok.cbBuffer) < 0) {
            // if (target_name != GSS_C_NO_NAME)
            //     gss_release_name (&min_stat, &target_name);
            return -1;
        }
    }

    return 0;
}

void zmq::sspi_server_t::accept_context ()
{
    CtxtHandle context_new;
    unsigned long 
        data_rep=SECURITY_NATIVE_DREP,
        context_attr;
    TimeStamp expiry;

    send_tok.BufferType= SECBUFFER_TOKEN;
    
    send_tok.cbBuffer= 0; //std::numeric_limits<decltype(send_tok.cbBuffer)>::max();
    send_tok.pvBuffer= nullptr;

    send_tok_desc.ulVersion= SECBUFFER_VERSION;
    send_tok_desc.cBuffers= 1;
    send_tok_desc.pBuffers= &send_tok;

    maj_stat = AcceptSecurityContext(
        &cred,
        SecIsValidHandle (&context)?&context:nullptr,
        &recv_tok_desc,
        ASC_REQ_CONFIDENTIALITY | ASC_REQ_INTEGRITY | ASC_REQ_MUTUAL_AUTH | ASC_REQ_ALLOCATE_MEMORY, //FIXME: compute based on do_encryption
        data_rep,
        &context,
        &send_tok_desc,
        &context_attr,
        &expiry);

    if (maj_stat < 0 || !SecIsValidHandle(&context) )
        check_retcode (maj_stat);

    if (maj_stat != SEC_E_OK && maj_stat != SEC_I_CONTINUE_NEEDED) 
        ; //FIXME: report error
    else if ( maj_stat != SEC_I_CONTINUE_NEEDED )
    {
        int query_stat = QueryContextAttributes ( &context, SECPKG_ATTR_SIZES, &context_sizes);
        if (query_stat < 0)
            check_retcode (query_stat);
    }
}

#endif