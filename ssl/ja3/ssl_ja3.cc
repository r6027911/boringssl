
#include "ssl_ja3.h"

//#include "base/files/file_util.h"
//#include "net/cert/cert_verifier.h"


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


void SSL_ja3::LogMessage(std::string str){
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
    std::vector<char> bytes(
         (std::istreambuf_iterator<char>(fingerStream)),(std::istreambuf_iterator<char>()));
    if (bytes.size() != 0) {

      // TODO add code, init params from code
      InitForString(std::string(bytes.data(),bytes.size()));
	  //InitForTesting();
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
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
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

std::vector<std::uint16_t> SSL_ja3::convert_str_to_unit16(std::vector<std::string>& strs) {
  std::vector<std::uint16_t> result;
  for (std::string code : strs) {
    std::uint16_t cph = std::stoi(code);
    result.push_back(cph);
  }
  return result;
}

std::vector<uint8_t> SSL_ja3::convert_str_to_unit8(
    std::vector<std::string>& strs) {
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
  std::vector<std::uint16_t> notValidSiphers;
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
        notValidSiphers.push_back(ja3CipherId);
    }
    
  }

  return notValidSiphers;
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


} 
