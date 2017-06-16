/*
 * Copyright (c) 2016, Ford Motor Company
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

#include "gtest/gtest.h"
#include <ctime>
#include <fstream>
#include <string>
#include <iterator>
#include <limits>

#include "security_manager/security_manager_impl.h"
#include "security_manager/crypto_manager_impl.h"
#include "security_manager/mock_security_manager_settings.h"
#include "utils/shared_ptr.h"
#include "utils/make_shared.h"

#ifdef __QNXNTO__
#include <openssl/ssl3.h>
#else
#include <openssl/tls1.h>
#endif

using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::NiceMock;

namespace {
const size_t kUpdatesBeforeHour = 24;
const std::string kAllCiphers = "ALL";
const std::string kCaCertPath = "";

const security_manager::Protocol kTestProtocol = security_manager::TLSv1_2;
#ifdef __QNXNTO__
const std::string kFordCipher = SSL3_TXT_RSA_DES_192_CBC3_SHA;
#else
// Used cipher from ford protocol requirement
const std::string kFordCipher = TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384;
#endif
}

namespace test {
namespace components {
namespace crypto_manager_test {

class CryptoManagerTest : public testing::Test {
 protected:
  static void SetUpTestCase() {
    std::ifstream certificate_file("server/spt_credential.pem");
    ASSERT_TRUE(certificate_file.is_open())
        << "Could not open certificate data file";

    const std::string certificate(
        (std::istreambuf_iterator<char>(certificate_file)),
        std::istreambuf_iterator<char>());
    ASSERT_FALSE(certificate.empty()) << "Certificate data file is empty";
    certificate_data_base64_ = certificate;
  }

  void SetUp() OVERRIDE {
    ASSERT_FALSE(certificate_data_base64_.empty());
    mock_security_manager_settings_ = utils::MakeShared<
        NiceMock<security_manager_test::MockCryptoManagerSettings> >();
    utils::SharedPtr<security_manager::CryptoManagerSettings> scrypto =
        utils::SharedPtr<security_manager::CryptoManagerSettings>::
            static_pointer_cast<security_manager::CryptoManagerSettings>(
                mock_security_manager_settings_);
    crypto_manager_ = new security_manager::CryptoManagerImpl(scrypto);
  }

  void TearDown() OVERRIDE {
    delete crypto_manager_;
  }
  void InitSecurityManager() {
    SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
    const bool crypto_manager_initialization = crypto_manager_->Init();
    ASSERT_TRUE(crypto_manager_initialization);
  }

  void SetInitialValues(security_manager::Mode mode,
                        security_manager::Protocol protocol,
                        const std::string& cipher) {
    ON_CALL(*mock_security_manager_settings_, security_manager_mode())
        .WillByDefault(Return(mode));
    ON_CALL(*mock_security_manager_settings_, security_manager_protocol_name())
        .WillByDefault(Return(protocol));
    ON_CALL(*mock_security_manager_settings_, certificate_data())
        .WillByDefault(ReturnRef(certificate_data_base64_));
    ON_CALL(*mock_security_manager_settings_, ciphers_list())
        .WillByDefault(ReturnRef(cipher));
    ON_CALL(*mock_security_manager_settings_, ca_cert_path())
        .WillByDefault(ReturnRef(kCaCertPath));
    ON_CALL(*mock_security_manager_settings_, verify_peer())
        .WillByDefault(Return(false));
  }

  static std::string certificate_data_base64_;
  security_manager::CryptoManager* crypto_manager_;

  utils::SharedPtr<NiceMock<security_manager_test::MockCryptoManagerSettings> >
      mock_security_manager_settings_;
};
std::string CryptoManagerTest::certificate_data_base64_;

TEST_F(CryptoManagerTest, UsingBeforeInit) {
  ASSERT_FALSE(crypto_manager_->is_initialized());
  EXPECT_TRUE(crypto_manager_->CreateSSLContext() == NULL);
  EXPECT_EQ(
      std::string("no openssl error occurs, initialization is not completed"),
      crypto_manager_->LastError());
}

TEST_F(CryptoManagerTest, WrongInit) {
  // Unknown protocol version
  security_manager::Protocol UNKNOWN = security_manager::UNKNOWN;

  EXPECT_CALL(*mock_security_manager_settings_, security_manager_mode())
      .WillRepeatedly(Return(security_manager::SERVER));
  EXPECT_CALL(*mock_security_manager_settings_,
              security_manager_protocol_name()).WillOnce(Return(UNKNOWN));
  EXPECT_FALSE(crypto_manager_->Init());

  EXPECT_FALSE(crypto_manager_->is_initialized());
  EXPECT_NE(std::string(), crypto_manager_->LastError());
  // Unexistent cipher value
  const std::string invalid_cipher = "INVALID_UNKNOWN_CIPHER";
  EXPECT_CALL(*mock_security_manager_settings_,
              security_manager_protocol_name()).WillOnce(Return(kTestProtocol));
  EXPECT_CALL(*mock_security_manager_settings_, certificate_data())
      .WillOnce(ReturnRef(certificate_data_base64_));
  EXPECT_CALL(*mock_security_manager_settings_, ciphers_list())
      .WillRepeatedly(ReturnRef(invalid_cipher));
  EXPECT_FALSE(crypto_manager_->Init());

  EXPECT_FALSE(crypto_manager_->is_initialized());
  EXPECT_NE(std::string(), crypto_manager_->LastError());
}

//  #ifndef __QNXNTO__
TEST_F(CryptoManagerTest, CorrectInit) {
  // Empty cert and key values for SERVER
  SetInitialValues(security_manager::SERVER, kTestProtocol, kFordCipher);
  EXPECT_TRUE(crypto_manager_->Init());
  EXPECT_TRUE(crypto_manager_->is_initialized());

  // Recall init
  SetInitialValues(security_manager::CLIENT, kTestProtocol, kFordCipher);
  EXPECT_TRUE(crypto_manager_->Init());

  EXPECT_TRUE(crypto_manager_->is_initialized());

  // Cipher value
  SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
  EXPECT_TRUE(crypto_manager_->Init());
  EXPECT_TRUE(crypto_manager_->is_initialized());
}
// #endif  // __QNX__

TEST_F(CryptoManagerTest, ReleaseSSLContext_Null) {
  EXPECT_NO_THROW(crypto_manager_->ReleaseSSLContext(NULL));
}

TEST_F(CryptoManagerTest, CreateReleaseSSLContext) {
  const size_t max_payload_size = 1000u;
  SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
  EXPECT_TRUE(crypto_manager_->Init());
  EXPECT_CALL(*mock_security_manager_settings_, security_manager_mode())
      .Times(2)
      .WillRepeatedly(Return(security_manager::CLIENT));
  EXPECT_CALL(*mock_security_manager_settings_, maximum_payload_size())
      .Times(1)
      .WillRepeatedly(Return(max_payload_size));

  security_manager::SSLContext* context = crypto_manager_->CreateSSLContext();
  EXPECT_TRUE(context);
  EXPECT_NO_THROW(crypto_manager_->ReleaseSSLContext(context));
}

TEST_F(CryptoManagerTest, OnCertificateUpdated) {
  InitSecurityManager();
  EXPECT_TRUE(crypto_manager_->OnCertificateUpdated(certificate_data_base64_));
}

TEST_F(CryptoManagerTest, OnCertificateUpdated_UpdateNotRequired) {
  size_t updates_before = 0;

  SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
  bool crypto_manager_initialization = crypto_manager_->Init();
  ASSERT_TRUE(crypto_manager_initialization);

  crypto_manager_->OnCertificateUpdated(certificate_data_base64_);

  // Create Context
  security_manager::SSLContext* ssl_context =
      crypto_manager_->CreateSSLContext();
  EXPECT_TRUE(ssl_context);

  struct tm year_2020 = {0};
  year_2020.tm_year = 120;
  year_2020.tm_mday = 1;
  time_t cert_due_time = mktime(&year_2020);
  ssl_context->GetCertificateDueDate(cert_due_time);

  EXPECT_CALL(*mock_security_manager_settings_, update_before_hours())
      .WillOnce(Return(updates_before));

  struct tm year_2015 = {0};
  year_2015.tm_year = 115;
  year_2015.tm_mday = 1;
  time_t system_time = mktime(&year_2015);
  EXPECT_FALSE(
      crypto_manager_->IsCertificateUpdateRequired(system_time, cert_due_time));

  // Release
  crypto_manager_->ReleaseSSLContext(ssl_context);

  size_t max_updates_ = std::numeric_limits<size_t>::max();
  SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
  EXPECT_CALL(*mock_security_manager_settings_, update_before_hours())
      .WillOnce(Return(max_updates_));
  crypto_manager_initialization = crypto_manager_->Init();
  ASSERT_TRUE(crypto_manager_initialization);

  // Create Context
  ssl_context = crypto_manager_->CreateSSLContext();
  EXPECT_TRUE(ssl_context);

  ssl_context->GetCertificateDueDate(cert_due_time);
  EXPECT_TRUE(
      crypto_manager_->IsCertificateUpdateRequired(cert_due_time, system_time));
  // Release
  crypto_manager_->ReleaseSSLContext(ssl_context);
}

TEST_F(CryptoManagerTest, OnCertificateUpdated_NotInitialized) {
  EXPECT_FALSE(crypto_manager_->OnCertificateUpdated(certificate_data_base64_));
}

TEST_F(CryptoManagerTest, OnCertificateUpdated_NullString) {
  InitSecurityManager();
  EXPECT_FALSE(crypto_manager_->OnCertificateUpdated(std::string()));
}

TEST_F(CryptoManagerTest, OnCertificateUpdated_MalformedSign) {
  InitSecurityManager();

  std::string certificate = certificate_data_base64_;
  ASSERT_FALSE(certificate.empty());

  // Corrupt the middle symbol
  certificate[certificate.size() / 2] = '?';

  EXPECT_FALSE(crypto_manager_->OnCertificateUpdated(certificate));
}

TEST_F(CryptoManagerTest, OnCertificateUpdated_WrongInitFolder) {
  SetInitialValues(security_manager::CLIENT, kTestProtocol, kAllCiphers);
  const bool crypto_manager_initialization = crypto_manager_->Init();
  ASSERT_TRUE(crypto_manager_initialization);

  const std::string wrong_certificate_data = "wrong_data";

  EXPECT_FALSE(crypto_manager_->OnCertificateUpdated(wrong_certificate_data));
}

}  // namespace crypto_manager_test
}  // namespace components
}  // namespace test
