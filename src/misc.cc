#include "eics.hh"

void eics::eics_openssl_error_log(const std::wstring &file, int line) {
   int ec;
   while((ec = ERR_get_error())) {
      LOG(error) << L"(" << file << L":" << line << L") " << ERR_lib_error_string(ec) << L":" << ERR_func_error_string(ec) << L":" << ERR_reason_error_string(ec);
   }
}
