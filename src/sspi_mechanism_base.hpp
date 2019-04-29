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

#ifndef __ZMQ_SSPI_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_SSPI_MECHANISM_BASE_HPP_INCLUDED__
#ifndef HAVE_SSPI
#define HAVE_SSPI
#endif
#if defined(HAVE_SSPI)

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <security.h>

#include "mechanism_base.hpp"
#include "options.hpp"

namespace zmq
{
class msg_t;

/// Commonalities between clients and servers are captured here.
/// For example, clients and servers both need to produce and
/// process context-level sspi tokens (via INITIATE commands)
/// and per-message sspi tokens (via MESSAGE commands).
class sspi_mechanism_base_t : public virtual mechanism_base_t
{
  public:
    sspi_mechanism_base_t (session_base_t *session_,
                             const options_t &options_);
    virtual ~sspi_mechanism_base_t () = 0;

  protected:
    //  Produce a context-level sspi token (INITIATE command)
    //  during security context initialization.
    int produce_initiate (msg_t *msg_, void *data_, unsigned long data_len_);

    //  Process a context-level sspi token (INITIATE command)
    //  during security context initialization.
    int process_initiate (msg_t *msg_, void **data_, unsigned long &data_len_);

    // Produce a metadata ready msg (READY) to conclude handshake
    int produce_ready (msg_t *msg_);

    // Process a metadata ready msg (READY)
    int process_ready (msg_t *msg_);

    //  Encode a per-message sspi token (MESSAGE command) using
    //  the established security context.
    int encode_message (msg_t *msg_);

    //  Decode a per-message sspi token (MESSAGE command) using
    //  the  established security context.
    int decode_message (msg_t *msg_);

    //  Convert ZMQ_GSSAPI_NT values to gssapi name_type
    //static const gss_OID convert_nametype (int zmq_name_type_);

    //  Acquire security context credentials from the
    //  underlying mechanism.
    // static int acquire_credentials (char *principal_name_,
    //                                 gss_cred_id_t *cred_,
    //                                 gss_OID name_type_);

    void check_retcode(int)const;

  protected:
    //  Opaque sspi token for outgoing data
    SecBufferDesc send_tok_desc;
    SecBuffer     send_tok;

    //  Opaque sspi token for incoming data
    SecBufferDesc recv_tok_desc;
    SecBuffer     recv_tok;


    //  Opaque sspi representation of principal
    //gss_name_t target_name;

    //  Human-readable principal name
    std::string principal_name;

    //  Human-readable mechanism name
    std::string mechanism_name;

    //  Status code returned by sspi functions
    SECURITY_STATUS maj_stat;

    //  Status code returned by the underlying mechanism
    SECURITY_STATUS min_stat;

    //  Status code returned by the underlying mechanism
    //  during context initialization
    SECURITY_STATUS init_sec_min_stat;

    //  Flags returned by sspi (ignored)
    //OM_uint32 ret_flags;

    //  Flags returned by sspi (ignored)
    unsigned long sspi_flags;

    //  Credentials used to establish security context
    CredHandle cred;

    //  Opaque sspi representation of the security context
    CtxtHandle context;

    // Credential life time
    TimeStamp cred_expiry;

    //  If true, use gss to encrypt messages. If false, only utilize gss for auth.
    bool do_encryption;
};
}

#endif

#endif
