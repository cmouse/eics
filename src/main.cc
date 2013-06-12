#include "eics.hh"

eics::Log::TLogLevel eics::Log::minLogLevel = eics::Log::debug;

std::string makeHexDump(const std::string& str)
{
  char tmp[5];
  std::string ret;
  ret.reserve((int)(str.size()*2.2));

  for(std::string::size_type n=0;n<str.size();++n) {
    sprintf(tmp,"%02x", (unsigned char)str[n]);
    ret+=tmp;
  }
  return ret;
}

int main(int argc, char * const argv[]) {
  // setup locale based on user's choice
  std::locale::global( std::locale("") );

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  eics::Processor proc;
  proc.configure("policy.conf");
  proc.check();

  return 0;
}
