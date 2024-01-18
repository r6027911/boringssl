
#include "ssl_ja3.h"


#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include <openssl/base.h>
#include "../internal.h"
#include <sstream>
#include <openssl/span.h>

using std::string;
using std::filesystem::current_path;



namespace ja3 {


void SSL_ja3::LogMessage(std::string str) {
  Log(str);
  std::cout << str << std::endl;
}

void SSL_ja3::Log(std::string str) {
  if (!file_log_.is_open()) {
    file_log_.open(current_path() += ("/SSL_JA3_log.txt"),
                   std::ios::out | std::ios::app | std::ios::binary);
  }

  file_log_ << str << std::endl;
}


void SSL_ja3::InitFromFile() {
  LogMessage("SSL_ja3::InitFromFile");
  if (was_init_ == false) {
    std::ifstream fingerStream(current_path() += "/finger.txt",
                               std::ios::binary);
    std::string finger_data;
    std::vector<char> bytes((std::istreambuf_iterator<char>(fingerStream)),
                            (std::istreambuf_iterator<char>()));
    if (bytes.size() != 0) {
      // TODO add code, init params from code
      InitForString(std::string(bytes.data(), bytes.size()));
      // InitForTesting();
      was_init_ = true;
    }
  }
}



static inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

static inline void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

static inline void trim(std::string &s) {
  rtrim(s);
  ltrim(s);
}



void SSL_ja3::InitForString(std::string str) {
  trim(str);
  std::vector<std::string> first = split_string(str, ',');

  need_check = first[0] == "1";

  version_ = std::stoi(first[1]);

  std::vector<std::string> ciphers = split_string(first[2], '-');
  cipher_suites_ = convert_str_to_unit16(ciphers);

  std::vector<std::string> exts = split_string(first[3], '-');
  custom_ext_ = convert_str_to_unit16(exts);

  std::vector<std::string> groups_lists = split_string(first[4], '-');
  custom_supported_group_list_ = convert_str_to_unit16(groups_lists);

  std::vector<std::string> points_lists = split_string(first[5], '-');
  custom_points_ = convert_str_to_unit8(points_lists);

  
}

std::vector<std::string> SSL_ja3::split_string(std::string str, char delim) {
  std::stringstream line;
  line.str(str);

  std::string segment;
  std::vector<std::string> seglist;

  while (std::getline(line, segment, delim)) {
    seglist.push_back(segment);
  }

  return seglist;
}

std::vector<std::uint16_t> SSL_ja3::convert_str_to_unit16(
    std::vector<std::string> &strs) {
  std::vector<std::uint16_t> result;
  for (std::string code : strs) {
    std::uint16_t cph = std::stoi(code);
    result.push_back(cph);
  }
  return result;
}

std::vector<uint8_t> SSL_ja3::convert_str_to_unit8(
    std::vector<std::string> &strs) {
  std::vector<uint8_t> result;
  for (std::string code : strs) {
    uint8_t cph = std::stoi(code);
    result.push_back(cph);
  }
  return result;
}

std::uint16_t SSL_ja3::ssl_cipher_get_value(const SSL_CIPHER *cipher) {
  std::uint32_t id = cipher->id;
  // All OpenSSL cipher IDs are prefaced with 0x03. Historically this referred
  // to SSLv2 vs SSLv3.
  assert((id & 0xff000000) == 0x03000000);
  return id & 0xffff;
}



std::vector<std::uint16_t> SSL_ja3::ssl_ja3_validate_ciphers() {
  std::vector<std::uint16_t> notValidCiphers;
  bssl::Span<const SSL_CIPHER> bsslCiphers = bssl::AllCiphers();

  for (auto ja3CipherId : cipher_suites_) {
    auto is_cipher_valid = [ja3CipherId, bsslCiphers, this] {
      for (auto &bsslCipher : bsslCiphers) {
        std::uint16_t bsslCipherId = SSL_ja3::ssl_cipher_get_value(&bsslCipher);
        if (bsslCipherId == ja3CipherId) {
          return true;
        }
      }
      return false;
    };

    if (!is_cipher_valid()) {
      notValidCiphers.push_back(ja3CipherId);
    }
  }

  return notValidCiphers;
}

std::vector<std::uint16_t> SSL_ja3::ssl_ja3_validate_extensions() {
  std::vector<std::uint16_t> notValidExtensions;
  for (auto ja3ExtId : custom_ext_) {
    if (!bssl::is_tls_extension_exists(ja3ExtId)) {
      notValidExtensions.push_back(ja3ExtId);
    }
  }
  return notValidExtensions;
}


bool SSL_ja3::isExtensionActive(uint16_t extId) {
  for (uint16_t activeId : custom_ext_) {
    if (extId == activeId) {
      //std::cout << "extId: " << extId << std::endl; 
      return true;
    }
  }
  return false;
}



void SSL_ja3::InitForTesting() {
  version_ = 771;
  // 4865,  4866,  4867,  49196, 49195, 49188, 49187, 49162, 49161,
  // 52393, 49200, 49199, 49192, 49191, 49172, 49171, 52392, 157,
  // 156,   61,    60,    53,    47,    49160, 49170, 10
  cipher_suites_.push_back(4865);
  cipher_suites_.push_back(4866);
  cipher_suites_.push_back(4867);
  cipher_suites_.push_back(49196);
  cipher_suites_.push_back(49195);
  cipher_suites_.push_back(49188);
  cipher_suites_.push_back(49188);
  cipher_suites_.push_back(49187);
  cipher_suites_.push_back(49162);
  cipher_suites_.push_back(49161);
  cipher_suites_.push_back(52393);
  cipher_suites_.push_back(49200);
  cipher_suites_.push_back(49199);
  cipher_suites_.push_back(49192);
  cipher_suites_.push_back(49191);
  cipher_suites_.push_back(49172);
  cipher_suites_.push_back(49171);
  cipher_suites_.push_back(52392);
  cipher_suites_.push_back(157);
  cipher_suites_.push_back(156);
  cipher_suites_.push_back(61);
  cipher_suites_.push_back(60);
  cipher_suites_.push_back(53);
  cipher_suites_.push_back(47);
  cipher_suites_.push_back(49160);
  cipher_suites_.push_back(49170);
  cipher_suites_.push_back(10);

  // 65281, 0, 23, 13, 5, 18, 16, 11, 51, 45, 43, 10, 21
  custom_ext_.push_back(65281);
  custom_ext_.push_back(0);
  custom_ext_.push_back(23);
  custom_ext_.push_back(13);
  custom_ext_.push_back(5);
  custom_ext_.push_back(18);
  custom_ext_.push_back(16);
  custom_ext_.push_back(11);
  custom_ext_.push_back(51);
  custom_ext_.push_back(45);
  custom_ext_.push_back(43);
  custom_ext_.push_back(10);
  custom_ext_.push_back(21);

  // 29, 23, 24, 25;
  custom_supported_group_list_.push_back(29);
  custom_supported_group_list_.push_back(23);
  custom_supported_group_list_.push_back(24);
  custom_supported_group_list_.push_back(25);
}

const unsigned char tls13_aes128gcmsha256_id[] = {0x13, 0x01};
const unsigned char tls13_aes256gcmsha384_id[] = {0x13, 0x02};
static bssl::UniquePtr<BIO> session_out;
static bssl::UniquePtr<SSL_SESSION> resume_session;
FILE *g_keylog_file;





static void KeyLogCallback(const SSL *ssl, const char *line) {
  fprintf(g_keylog_file, "%s\n", line);
  fflush(g_keylog_file);
}

static void InfoCallback(const SSL *ssl, int type, int value) {
  switch (type) {
    case SSL_CB_HANDSHAKE_START:
      fprintf(stderr, "Handshake started.\n");
      break;
    case SSL_CB_HANDSHAKE_DONE:
      fprintf(stderr, "Handshake done.\n");
      break;
    case SSL_CB_CONNECT_LOOP:
      fprintf(stderr, "Handshake progress: %s\n", SSL_state_string_long(ssl));
      break;
  }
}


unsigned int SSL_ja3::pskCallback(SSL *ssl, const char *hint, char *identity,
                         unsigned max_identity_len, uint8_t *psk,
                         unsigned max_psk_len) {

  return 1;
}




void SSL_ja3::configureExtensions(SSL *const ssl) {
    SSL_CTX *const ctx = ssl->ctx.get();

    ja3::compression::enableBrotli(ctx);
    ja3::compression::enableZlib(ctx);
    ja3::compression::enableZstd(ctx);

    SSL_enable_ocsp_stapling(ssl);
    SSL_enable_tls_channel_id(ssl);
    SSL_enable_signed_cert_timestamps(ssl);

    SSL_CTX_enable_signed_cert_timestamps(ssl->ctx.get());
    SSL_CTX_enable_ocsp_stapling(ssl->ctx.get());
    SSL_CTX_enable_tls_channel_id(ssl->ctx.get());
    SSL_CTX_set_grease_enabled(ssl->ctx.get(),1);

    SSL_set_alps_use_new_codepoint(ssl, 1);

    SSL_set_tls_channel_id_enabled(ssl, 1);
   
    SSL_CTX_set_session_cache_mode(ssl->ctx.get(), SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_permute_extensions(ssl->ctx.get(), 1);

    SSL_set_psk_client_callback(ssl, pskCallback);
    SSL_set_tlsext_host_name(ssl,"tls.peet.ws");

    const uint8_t kALPNProtos[] = { 
        8, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, //http/1.1
        2, 0x68, 0x32}; //h2

    SSL_CTX_set_alpn_protos(ssl->ctx.get(), kALPNProtos, sizeof(kALPNProtos));
    SSL_set_alpn_protos(ssl, kALPNProtos, sizeof(kALPNProtos));

    string sesOutFile = (current_path() += "/session-out").string();
    session_out.reset(BIO_new_file(sesOutFile.c_str(), "wb"));
    SSL_CTX_set_info_callback(ssl->ctx.get(), InfoCallback);

    string keylog_file = (current_path() += "/SSLKEYLOGFILE").string();
    g_keylog_file = fopen(keylog_file.c_str(), "a");
    if (g_keylog_file == nullptr) {
      perror("fopen");
      return;
    }
    SSL_CTX_set_keylog_callback(ssl->ctx.get(), KeyLogCallback);
    //SSL_set_psk_client_callback(ssl, pskCallback);
    //SSL_CTX_set_psk_client_callback(ctx, pskCallback);


     if (isExtensionActive(TLSEXT_TYPE_pre_shared_key)) {
      SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
      SSL_SESSION *session = SSL_SESSION_new(ctx);
      SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION);
      
     const SSL_CIPHER *cipher = SSL_get_cipher_by_value(
          0xC036);
      std::vector<uint8_t> ticket;
      char hex_characters[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
      for (int i = 0; i <= 250; i++) {
        ticket.push_back(hex_characters[rand() % 16]);
      }
      SSL_SESSION_set_ticket(session, ticket.data(), ticket.size());
      session->cipher = cipher;
      SSL_CTX_add_session(ctx, session);
      SSL_set_session(ssl, session);
    }/**/


   SSL_set_max_proto_version(ssl,version_);//TLS1_2_VERSION
   SSL_CTX_set_max_proto_version(ssl->ctx.get(), version_); //TLS1_2_VERSION
      

}

} 
