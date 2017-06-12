/*
 * Copyright (c) 2015, Ford Motor Company
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the name of the Ford Motor Company nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "security_manager/crypto_manager_impl.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <ctime>
#include <fstream>
#include <sstream>
#include <stdio.h>

#include "security_manager/security_manager.h"
#include "utils/logger.h"
#include "utils/atomic.h"
#include "utils/file_system.h"
#include "utils/macro.h"
#include "utils/scope_guard.h"

#define TLS1_1_MINIMAL_VERSION 0x1000103fL
#define CONST_SSL_METHOD_MINIMAL_VERSION 0x00909000L
// Ubuntu 16.04 - 0x1000207fL "OpenSSL 1.0.2g-fips  1 Mar 2016"
// The SSLv3 context is NULL
// Ubuntu 14.04 - 0x1000106fL "OpenSSL 1.0.1f 6 Jan 2014"
// The SSLv3 context is not NULL
#define SSL3_MAXIMAL_VERSION 0x1000106fL

namespace security_manager {

CREATE_LOGGERPTR_GLOBAL(logger_, "SecurityManager")

uint32_t CryptoManagerImpl::instance_count_ = 0;
sync_primitives::Lock CryptoManagerImpl::instance_lock_;

// Handshake verification callback
// Used for debug outpute only
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

namespace {
void free_ctx(SSL_CTX** ctx) {
  if (ctx) {
    SSL_CTX_free(*ctx);
    *ctx = NULL;
  }
}
}  // namespace

CryptoManagerImpl::CryptoManagerImpl(
    const utils::SharedPtr<const CryptoManagerSettings> set)
    : settings_(set), context_(NULL) {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(instance_lock_);
  instance_count_++;
  if (instance_count_ == 1) {
    LOG4CXX_DEBUG(logger_, "Openssl engine initialization");
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
  }
}

CryptoManagerImpl::~CryptoManagerImpl() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(instance_lock_);
  LOG4CXX_DEBUG(logger_, "Deinitilization");
  if (!context_) {
    LOG4CXX_WARN(logger_, "Manager is not initialized");
  } else {
    SSL_CTX_free(context_);
  }
  instance_count_--;
  if (instance_count_ == 0) {
    LOG4CXX_DEBUG(logger_, "Openssl engine deinitialization");
    EVP_cleanup();
    ERR_free_strings();
  }
}

bool CryptoManagerImpl::Init() {
  LOG4CXX_AUTO_TRACE(logger_);

  const Mode mode = get_settings().security_manager_mode();
  const bool is_server = (mode == SERVER);
  if (is_server) {
    LOG4CXX_DEBUG(logger_, "Server mode");
  } else {
    LOG4CXX_DEBUG(logger_, "Client mode");
  }
  LOG4CXX_DEBUG(logger_,
                "Peer verification "
                    << (get_settings().verify_peer() ? "enabled" : "disabled"));
  LOG4CXX_DEBUG(logger_,
                "CA certificate file is \"" << get_settings().ca_cert_path()
                                            << '"');

#if OPENSSL_VERSION_NUMBER < CONST_SSL_METHOD_MINIMAL_VERSION
  SSL_METHOD* method;
#else
  const SSL_METHOD* method;
#endif
  switch (get_settings().security_manager_protocol_name()) {
    case SSLv3:
#if OPENSSL_VERSION_NUMBER > SSL3_MAXIMAL_VERSION
      LOG4CXX_WARN(logger_,
                   "OpenSSL has no valid SSLv3 context with version higher "
                   "than 1.0.1, set TLSv1.0");
      method = is_server ? TLSv1_server_method() : TLSv1_client_method();
#else
      method = is_server ? SSLv3_server_method() : SSLv3_client_method();
#endif
      break;
    case TLSv1:
      method = is_server ? TLSv1_server_method() : TLSv1_client_method();
      break;
    case TLSv1_1:
#if OPENSSL_VERSION_NUMBER < TLS1_1_MINIMAL_VERSION
      LOG4CXX_WARN(
          logger_,
          "OpenSSL has no TLSv1.1 with version lower 1.0.1, set TLSv1.0");
      method = is_server ? TLSv1_server_method() : TLSv1_client_method();
#else
      method = is_server ? TLSv1_1_server_method() : TLSv1_1_client_method();
#endif
      break;
    case TLSv1_2:
#if OPENSSL_VERSION_NUMBER < TLS1_1_MINIMAL_VERSION
      LOG4CXX_WARN(
          logger_,
          "OpenSSL has no TLSv1.2 with version lower 1.0.1, set TLSv1.0");
      method = is_server ? TLSv1_server_method() : TLSv1_client_method();
#else
      method = is_server ? TLSv1_2_server_method() : TLSv1_2_client_method();
#endif
      break;
    default:
      LOG4CXX_ERROR(logger_,
                    "Unknown protocol: "
                        << get_settings().security_manager_protocol_name());
      return false;
  }
  if (context_) {
    free_ctx(&context_);
  }
  context_ = SSL_CTX_new(method);
  if (!context_) {
    const unsigned long error = ERR_get_error();
    UNUSED(error);
    LOG4CXX_ERROR(logger_,
                  "Could not create \""
                      << (is_server ? "server" : "client")
                      << "\" SSL method \"'"
                      << get_settings().security_manager_protocol_name()
                      << "\"', err 0x" << std::hex << error << " \""
                      << ERR_reason_error_string(error) << '"');
    return false;
  }

  utils::ScopeGuard guard = utils::MakeGuard(free_ctx, &context_);

  // Disable SSL2 as deprecated
  SSL_CTX_set_options(context_, SSL_OP_NO_SSLv2);

  set_certificate(get_settings().certificate_data());

  if (get_settings().ciphers_list().empty()) {
    LOG4CXX_WARN(logger_, "Empty ciphers list");
  } else {
    LOG4CXX_DEBUG(logger_, "Cipher list: " << get_settings().ciphers_list());
    if (!SSL_CTX_set_cipher_list(context_,
                                 get_settings().ciphers_list().c_str())) {
      LOG4CXX_ERROR(
          logger_,
          "Could not set cipher list: " << get_settings().ciphers_list());
      return false;
    }
  }

  if (get_settings().ca_cert_path().empty()) {
    LOG4CXX_WARN(logger_, "Setting up empty CA certificate location");
  }

  LOG4CXX_DEBUG(logger_, "Setting up CA certificate location");
  const int result = SSL_CTX_load_verify_locations(
      context_, NULL, get_settings().ca_cert_path().c_str());

  if (!result) {
    const unsigned long error = ERR_get_error();
    UNUSED(error);
    LOG4CXX_WARN(logger_,
                 "Wrong certificate file '"
                     << get_settings().ca_cert_path() << "', err 0x" << std::hex
                     << error << " \"" << ERR_reason_error_string(error)
                     << '"');
  }

  guard.Dismiss();

  const int verify_mode =
      get_settings().verify_peer()
          ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
          : SSL_VERIFY_NONE;
  LOG4CXX_DEBUG(logger_,
                "Setting up peer verification in mode: " << verify_mode);
  SSL_CTX_set_verify(context_, verify_mode, &verify_callback);
  return true;
}

bool CryptoManagerImpl::is_initialized() const {
  return context_;
}

bool CryptoManagerImpl::OnCertificateUpdated(const std::string& data) {
  LOG4CXX_AUTO_TRACE(logger_);
  if (!is_initialized()) {
    LOG4CXX_WARN(logger_, "Not initialized");
    return false;
  }

  return set_certificate(data);
}

SSLContext* CryptoManagerImpl::CreateSSLContext() {
  if (context_ == NULL) {
    LOG4CXX_ERROR(logger_, "Not initialized");
    return NULL;
  }

  SSL* conn = SSL_new(context_);
  if (conn == NULL) {
    LOG4CXX_ERROR(logger_, "SSL context was not created - " << LastError());
    return NULL;
  }

  if (get_settings().security_manager_mode() == SERVER) {
    SSL_set_accept_state(conn);
  } else {
    SSL_set_connect_state(conn);
  }
  return new SSLContextImpl(conn,
                            get_settings().security_manager_mode(),
                            get_settings().maximum_payload_size());
}

void CryptoManagerImpl::ReleaseSSLContext(SSLContext* context) {
  delete context;
}

std::string CryptoManagerImpl::LastError() const {
  const unsigned long openssl_error_id = ERR_get_error();
  std::stringstream string_stream;
  if (openssl_error_id == 0) {
    string_stream << "no openssl error occurs";
  } else {
    const char* error_string = ERR_reason_error_string(openssl_error_id);
    string_stream << "error: 0x" << std::hex << openssl_error_id << ", \""
                  << std::string(error_string ? error_string : "") << '"';
  }
  if (!is_initialized()) {
    string_stream << ", initialization is not completed";
  }
  return string_stream.str();
}

bool CryptoManagerImpl::IsCertificateUpdateRequired(
    const time_t system_time, const time_t certificates_time) const {
  LOG4CXX_AUTO_TRACE(logger_);

  const double seconds = difftime(certificates_time, system_time);

  LOG4CXX_DEBUG(
      logger_, "Certificate UTC time: " << asctime(gmtime(&certificates_time)));
  LOG4CXX_DEBUG(logger_, "Host UTC time: " << asctime(gmtime(&system_time)));
  LOG4CXX_DEBUG(logger_, "Seconds before expiration: " << seconds);

  return seconds <= (get_settings().update_before_hours() * 60 * 60);
}

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
  if (!preverify_ok) {
    const int error = X509_STORE_CTX_get_error(ctx);
    if (error == X509_V_ERR_CERT_NOT_YET_VALID ||
        error == X509_V_ERR_CERT_HAS_EXPIRED) {
      // return success result code instead of error because date
      // will be checked within SSLContextImpl
      return 1;
    }

    LOG4CXX_WARN(logger_,
                 "Certificate verification failed with error "
                     << error << " \"" << X509_verify_cert_error_string(error)
                     << '"');
  }
  return preverify_ok;
}

bool CryptoManagerImpl::set_certificate(const std::string& cert_data) {
  LOG4CXX_AUTO_TRACE(logger_);
  if (cert_data.empty()) {
    LOG4CXX_WARN(logger_, "Empty certificate data");
    return false;
  }

  LOG4CXX_DEBUG(logger_,
                "Updating certificate and key from base64 data: \" "
                    << cert_data);

  BIO* bio_cert =
      BIO_new_mem_buf(const_cast<char*>(cert_data.c_str()), cert_data.length());

  utils::ScopeGuard bio_guard = utils::MakeGuard(BIO_free, bio_cert);
  UNUSED(bio_guard)

  X509* cert = NULL;
  PEM_read_bio_X509(bio_cert, &cert, 0, 0);

  EVP_PKEY* pkey = NULL;
  if (1 == BIO_reset(bio_cert)) {
    PEM_read_bio_PrivateKey(bio_cert, &pkey, 0, 0);
  } else {
    LOG4CXX_WARN(logger_,
                 "Unabled to reset BIO in order to read private key, "
                     << LastError());
  }

  if (NULL == cert || NULL == pkey) {
    LOG4CXX_WARN(logger_,
                 "Either certificate or key not valid, " << LastError());
    return false;
  }

  if (!SSL_CTX_use_certificate(context_, cert)) {
    LOG4CXX_WARN(logger_, "Could not use certificate, " << LastError());
    return false;
  }

  if (!SSL_CTX_use_PrivateKey(context_, pkey)) {
    LOG4CXX_ERROR(logger_, "Could not use key, " << LastError());
    return false;
  }
  if (!SSL_CTX_check_private_key(context_)) {
    LOG4CXX_ERROR(logger_, "Could not check private key, " << LastError());
    return false;
  }

  LOG4CXX_INFO(logger_, "Certificate and key data successfully updated");
  return true;
}

}  // namespace security_manager
