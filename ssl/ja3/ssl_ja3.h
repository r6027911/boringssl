
#ifndef NET_SSL_SSL_JA3_H_
#define NET_SSL_SSL_JA3_H_

#include <stdint.h>
#include <cstdint>
#include <string>
#include <vector>

#include <fstream>
#include <openssl/base.h>
#include "../internal.h"



namespace ja3 {

class SSL_ja3 {

 public:

  SSL_ja3(const SSL_ja3&) = delete;
  SSL_ja3& operator = (const SSL_ja3&) = delete;

  static SSL_ja3& getInstance(){
    static SSL_ja3 instance;   

    return instance;
  }

  std::vector<std::uint16_t> ssl_ja3_validate_ciphers();
  std::vector<std::uint16_t> ssl_ja3_validate_extensions();

  void InitFromFile();
  void InitForTesting();
  void InitForString(std::string str);
  void LogMessage(std::string str);
  void Log(std::string str);
  uint16_t ssl_cipher_get_value(const SSL_CIPHER *cipher);
  uint16_t GetVersion() { return version_; }
  void SetVersion(uint16_t version) { version_ = version; }
  
  bool need_check = true;
  uint16_t version_ = 0;
  std::vector<uint16_t> cipher_suites_;
  std::vector<uint16_t> custom_ext_;
  std::vector<uint16_t> custom_supported_group_list_;
  std::vector<uint8_t> custom_points_;
  

 private:
   SSL_ja3() = default;
  ~SSL_ja3() = default;

  std::vector<std::string> split_string(std::string str, char delim);
  std::vector<std::uint16_t> convert_str_to_unit16(std::vector<std::string>& strs);
  std::vector<std::uint8_t> convert_str_to_unit8(std::vector<std::string>& strs);
 
  bool was_init_ = false;
  std::ofstream file_log_;
};


} 

#endif  
