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

#include <array>
#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "sspi_mechanism_base.hpp"
#include "wire.hpp"

#if defined(HAVE_SSPI)

namespace zmq
{

std::string sspi_principal_name (const options_t &options)
{
    std::string buffer;
    buffer.resize(256);
    ULONG size=buffer.size();
    GetUserNameEx(NameUserPrincipal,(LPSTR)buffer.data(),&size);
    buffer.resize(size);
    return buffer;
}

std::string sspi_mechanism_name (const options_t &options)
{
    return MICROSOFT_KERBEROS_NAME_A;
}

}
zmq::sspi_mechanism_base_t::sspi_mechanism_base_t (
  session_base_t *session_, const options_t &options_) :
    mechanism_base_t (session_, options_),
    // send_tok (),
    // recv_tok (),
    /// FIXME remove? in_buf (),
    //target_name (GSS_C_NO_NAME),
    principal_name ( sspi_principal_name (options_)),
    mechanism_name ( sspi_mechanism_name (options_)),
    
    maj_stat (0),//maj_stat (GSS_S_COMPLETE),
    min_stat (0),
    init_sec_min_stat (0),
    // ret_flags (0),
    //gss_flags (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG),
    sspi_flags (ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT),
    // cred (GSS_C_NO_CREDENTIAL),
    // context (GSS_C_NO_CONTEXT),
    do_encryption (!options_.gss_plaintext)
{
    
  SecInvalidateHandle(&cred);
  SecInvalidateHandle(&context);
}

zmq::sspi_mechanism_base_t::~sspi_mechanism_base_t ()
{
    if (SecIsValidHandle (&context))
        DeleteSecurityContext (&context);
    if (SecIsValidHandle (&cred))
        FreeCredentialsHandle (&cred);
}

int zmq::sspi_mechanism_base_t::encode_message (msg_t *msg_)
{

    // int state;
    // gss_buffer_desc plaintext;
    // gss_buffer_desc wrapped;

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;
    if (msg_->flags () & msg_t::command)
        flags |= 0x02;

    // plaintext.value = plaintext_buffer;
    // plaintext.length = msg_->size () + 1;

    std::array<SecBuffer,3> tmp_buf;
    SecBufferDesc tmp_buf_desc;
    tmp_buf_desc.cBuffers = 3;
    tmp_buf_desc.pBuffers = tmp_buf.data();
    tmp_buf_desc.ulVersion = SECBUFFER_VERSION;

    tmp_buf[0].BufferType = SECBUFFER_TOKEN;
    tmp_buf[0].cbBuffer = context_sizes.cbSecurityTrailer;
    tmp_buf[0].pvBuffer = malloc(context_sizes.cbSecurityTrailer);

    // This buffer holds the application data.
    tmp_buf[1].BufferType = SECBUFFER_DATA;
    tmp_buf[1].cbBuffer = msg_->size () + 1;
    tmp_buf[1].pvBuffer = malloc (msg_->size () + 1);
    alloc_assert (static_cast<uint8_t *> (malloc (msg_->size () + 1)));
    ((uint8_t *)(tmp_buf[1].pvBuffer))[0] = flags;
    memcpy ((uint8_t *)tmp_buf[1].pvBuffer + 1, msg_->data (), msg_->size ());

    tmp_buf[2].BufferType = SECBUFFER_PADDING;
    tmp_buf[2].cbBuffer = context_sizes.cbBlockSize;
    tmp_buf[2].pvBuffer = malloc(tmp_buf[2].cbBuffer);

    maj_stat = EncryptMessage(&context, do_encryption ? 0 : SECQOP_WRAP_NO_ENCRYPT , &tmp_buf_desc, 0);
    zmq_assert (maj_stat == SEC_E_OK);

    // Re-initialize msg_ for wrapped text
    int rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (8 + 4 + tmp_buf[0].cbBuffer+tmp_buf[1].cbBuffer+tmp_buf[2].cbBuffer);
    zmq_assert (rc == 0);

    uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());

    // Add command string
    memcpy (ptr, "\x07MESSAGE", 8);
    ptr += 8;

    // Add token length
    {
      uint32_t l=0;
      for(auto &b:tmp_buf)
        l+=static_cast<uint32_t>(b.cbBuffer);
      put_uint32 (ptr, l);
    }
    ptr += 4;

    // Add wrapped token value
    for(auto &b:tmp_buf)
    {
      memcpy (ptr, b.pvBuffer, b.cbBuffer);
      ptr += b.cbBuffer;
      free(b.pvBuffer);
      b.cbBuffer=0;
    }

    return 0;
}

int zmq::sspi_mechanism_base_t::decode_message (msg_t *msg_)
{
    const uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    // Get command string
    if (bytes_left < 8 || memcmp (ptr, "\x07MESSAGE", 8)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 8;
    bytes_left -= 8;

    // Get token length
    if (bytes_left < 4) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }

    uint32_t length = get_uint32 (ptr);
    ptr += 4;
    bytes_left -= 4;

    // Get token value
    if (bytes_left < length) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }

    std::array<SecBuffer,2> tmp;

    //FIXME: use inplace instead - jeh
    std::vector<uint8_t> buf((uint8_t *)ptr,((uint8_t *)ptr)+length);
    // This buffer is for SSPI.
    tmp[0].BufferType = SECBUFFER_STREAM;
    tmp[0].pvBuffer = (void *)buf.data();
    tmp[0].cbBuffer = length;

    // This buffer holds the application data.
    tmp[1].BufferType = SECBUFFER_DATA;
    tmp[1].cbBuffer = 0;
    tmp[1].pvBuffer = NULL;
    
    SecBufferDesc tmp_desc;
    tmp_desc.cBuffers = tmp.size();
    tmp_desc.pBuffers = tmp.data();
    tmp_desc.ulVersion = SECBUFFER_VERSION; 
    
    ULONG qop;
    maj_stat = DecryptMessage(&context,&tmp_desc,0,&qop);

    // Unwrap the token value
    if (maj_stat != SEC_E_OK) {
        //gss_release_buffer (&min_stat, &plaintext);
        //free (wrapped.value);
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        check_retcode (maj_stat) ;
        return -1;
    }
    //zmq_assert (state);
    //check qop match with do_encryption

    // TODO: instead of malloc/memcpy, can we just do: wrapped.value = ptr;
    // const size_t alloc_length = wrapped.length ? wrapped.length : 1;
    // wrapped.value = static_cast<char *> (malloc (alloc_length));
    // alloc_assert (wrapped.value);
    if (length) {
        //memcpy (wrapped.value, ptr, wrapped.length);
        ptr += length;
        bytes_left -= length;
    }


    // Re-initialize msg_ for plaintext
    rc = msg_->close ();
    zmq_assert (rc == 0);

    length = tmp[1].cbBuffer ;
    rc = msg_->init_size (length - 1);
    zmq_assert (rc == 0);

    const uint8_t flags = static_cast<char *> (tmp[1].pvBuffer)[0];
    if (flags & 0x01)
        msg_->set_flags (msg_t::more);
    if (flags & 0x02)
        msg_->set_flags (msg_t::command);

    memcpy (msg_->data (), static_cast<char *> (tmp[1].pvBuffer) + 1, length - 1);

    //gss_release_buffer (&min_stat, &plaintext);
    //free (wrapped.value);

    if (bytes_left > 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int zmq::sspi_mechanism_base_t::produce_initiate (msg_t *msg_,
                                                    void *token_value_,
                                                    unsigned long token_length_)
{
    zmq_assert (token_value_);
    zmq_assert (token_length_ <= 0xFFFFFFFFUL);

    const size_t command_size = 9 + 4 + token_length_;

    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());

    // Add command string
    memcpy (ptr, "\x08INITIATE", 9);
    ptr += 9;

    // Add token length
    put_uint32 (ptr, static_cast<uint32_t> (token_length_));
    ptr += 4;

    // Add token value
    memcpy (ptr, token_value_, token_length_);
    ptr += token_length_;

    return 0;
}

int zmq::sspi_mechanism_base_t::process_initiate (msg_t *msg_,
                                                    void **token_value_,
                                                    unsigned long &token_length_)
{
    zmq_assert (token_value_);

    const uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    // Get command string
    if (bytes_left < 9 || memcmp (ptr, "\x08INITIATE", 9)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 9;
    bytes_left -= 9;

    // Get token length
    if (bytes_left < 4) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }
    token_length_ = get_uint32 (ptr);
    ptr += 4;
    bytes_left -= 4;

    // Get token value
    if (bytes_left < token_length_) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }

    *token_value_ =
      static_cast<char *> (malloc (token_length_ ? token_length_ : 1));
    alloc_assert (*token_value_);

    if (token_length_) {
        memcpy (*token_value_, ptr, token_length_);
        ptr += token_length_;
        bytes_left -= token_length_;
    }

    if (bytes_left > 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int zmq::sspi_mechanism_base_t::produce_ready (msg_t *msg_)
{
    make_command_with_basic_properties (msg_, "\5READY", 6);

    if (do_encryption)
        return encode_message (msg_);

    return 0;
}

int zmq::sspi_mechanism_base_t::process_ready (msg_t *msg_)
{
    if (do_encryption) {
        const int rc = decode_message (msg_);
        if (rc != 0)
            return rc;
    }

    const unsigned char *ptr = static_cast<unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    if (bytes_left < 6 || memcmp (ptr, "\x05READY", 6)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;
    rc = parse_metadata (ptr, bytes_left);
    if (rc == -1)
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);

    return rc;
}

// const gss_OID zmq::sspi_mechanism_base_t::convert_nametype (int zmq_nametype)
// {
// //     switch (zmq_nametype) {
// //         case ZMQ_sspi_NT_HOSTBASED:
// //             return GSS_C_NT_HOSTBASED_SERVICE;
// //         case ZMQ_sspi_NT_USER_NAME:
// //             return GSS_C_NT_USER_NAME;
// //         case ZMQ_sspi_NT_KRB5_PRINCIPAL:
// // #ifdef GSS_KRB5_NT_PRINCIPAL_NAME
// //             return (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME;
// // #else
// //             return GSS_C_NT_USER_NAME;
// // #endif
// //     }
//     return NULL;
// }

// int zmq::sspi_mechanism_base_t::acquire_credentials (char *service_name_,
//                                                        gss_cred_id_t *cred_,
//                                                        gss_OID name_type_)
// {
//     // OM_uint32 maj_stat;
//     // OM_uint32 min_stat;
//     // gss_name_t server_name;

//     // gss_buffer_desc name_buf;
//     // name_buf.value = service_name_;
//     // name_buf.length = strlen ((char *) name_buf.value) + 1;

//     // maj_stat = gss_import_name (&min_stat, &name_buf, name_type_, &server_name);

//     // if (maj_stat != GSS_S_COMPLETE)
//     //     return -1;

//     // maj_stat = gss_acquire_cred (&min_stat, server_name, 0, GSS_C_NO_OID_SET,
//     //                              GSS_C_BOTH, cred_, NULL, NULL);

//     // if (maj_stat != GSS_S_COMPLETE)
//     //     return -1;

//     // gss_release_name (&min_stat, &server_name);

//     return 0;
// }

void zmq::sspi_mechanism_base_t::check_retcode (int retcode) const
{
  if(retcode==SEC_E_OK)
    return;
  switch(retcode){
    #define ZMQ_MACRO(id) case SEC_E_##id:  printf (#id ## "\n"); break; 
    ZMQ_MACRO(INSUFFICIENT_MEMORY)
    ZMQ_MACRO(INVALID_HANDLE)
    ZMQ_MACRO(UNSUPPORTED_FUNCTION)
    ZMQ_MACRO(TARGET_UNKNOWN)
    ZMQ_MACRO(INTERNAL_ERROR)
    ZMQ_MACRO(SECPKG_NOT_FOUND)
    ZMQ_MACRO(NOT_OWNER)
    ZMQ_MACRO(CANNOT_INSTALL)
    ZMQ_MACRO(INVALID_TOKEN)
    ZMQ_MACRO(CANNOT_PACK)
    ZMQ_MACRO(QOP_NOT_SUPPORTED)
    ZMQ_MACRO(NO_IMPERSONATION)
    ZMQ_MACRO(LOGON_DENIED)
    ZMQ_MACRO(UNKNOWN_CREDENTIALS)
    ZMQ_MACRO(NO_CREDENTIALS)
    ZMQ_MACRO(INCOMPLETE_MESSAGE)
    ZMQ_MACRO(OUT_OF_SEQUENCE)
    ZMQ_MACRO(MESSAGE_ALTERED)
    ZMQ_MACRO(NO_AUTHENTICATING_AUTHORITY)
    ZMQ_MACRO(BAD_PKGID)
    ZMQ_MACRO(CONTEXT_EXPIRED)
    ZMQ_MACRO(INCOMPLETE_CREDENTIALS)
    ZMQ_MACRO(BUFFER_TOO_SMALL)
    ZMQ_MACRO(WRONG_PRINCIPAL)
    ZMQ_MACRO(TIME_SKEW)
    ZMQ_MACRO(UNTRUSTED_ROOT)
    ZMQ_MACRO(ILLEGAL_MESSAGE)
    ZMQ_MACRO(CERT_UNKNOWN)
    ZMQ_MACRO(CERT_EXPIRED)
    ZMQ_MACRO(ENCRYPT_FAILURE)
    ZMQ_MACRO(DECRYPT_FAILURE)
    ZMQ_MACRO(ALGORITHM_MISMATCH)
    ZMQ_MACRO(SECURITY_QOS_FAILED)
    ZMQ_MACRO(UNFINISHED_CONTEXT_DELETED)
    ZMQ_MACRO(NO_TGT_REPLY)
    ZMQ_MACRO(NO_IP_ADDRESSES)
    ZMQ_MACRO(WRONG_CREDENTIAL_HANDLE)
    ZMQ_MACRO(CRYPTO_SYSTEM_INVALID)
    ZMQ_MACRO(MAX_REFERRALS_EXCEEDED)
    ZMQ_MACRO(MUST_BE_KDC)
    ZMQ_MACRO(STRONG_CRYPTO_NOT_SUPPORTED)
    ZMQ_MACRO(TOO_MANY_PRINCIPALS)
    ZMQ_MACRO(NO_PA_DATA)
    ZMQ_MACRO(PKINIT_NAME_MISMATCH)
    ZMQ_MACRO(SMARTCARD_LOGON_REQUIRED)
    ZMQ_MACRO(SHUTDOWN_IN_PROGRESS)
    ZMQ_MACRO(KDC_INVALID_REQUEST)
    ZMQ_MACRO(KDC_UNABLE_TO_REFER)
    ZMQ_MACRO(KDC_UNKNOWN_ETYPE)
    ZMQ_MACRO(UNSUPPORTED_PREAUTH)
    ZMQ_MACRO(DELEGATION_REQUIRED)
    ZMQ_MACRO(BAD_BINDINGS)
    ZMQ_MACRO(MULTIPLE_ACCOUNTS)
    ZMQ_MACRO(NO_KERB_KEY)
    ZMQ_MACRO(CERT_WRONG_USAGE)
    ZMQ_MACRO(DOWNGRADE_DETECTED)
    ZMQ_MACRO(SMARTCARD_CERT_REVOKED)
    ZMQ_MACRO(ISSUING_CA_UNTRUSTED)
    ZMQ_MACRO(REVOCATION_OFFLINE_C)
    ZMQ_MACRO(PKINIT_CLIENT_FAILURE)
    ZMQ_MACRO(SMARTCARD_CERT_EXPIRED)
    ZMQ_MACRO(NO_S4U_PROT_SUPPORT)
    ZMQ_MACRO(CROSSREALM_DELEGATION_FAILURE)
    ZMQ_MACRO(REVOCATION_OFFLINE_KDC)
    ZMQ_MACRO(ISSUING_CA_UNTRUSTED_KDC)
    ZMQ_MACRO(KDC_CERT_EXPIRED)
    ZMQ_MACRO(KDC_CERT_REVOKED)
    ZMQ_MACRO(INVALID_PARAMETER)
    ZMQ_MACRO(DELEGATION_POLICY)
    ZMQ_MACRO(POLICY_NLTM_ONLY)
    ZMQ_MACRO(NO_CONTEXT)
    ZMQ_MACRO(PKU2U_CERT_FAILURE)
    ZMQ_MACRO(MUTUAL_AUTH_FAILED)
    #undef ZMQ_MACRO
    default: throw std::runtime_error("unknown error");
  }
}

#endif