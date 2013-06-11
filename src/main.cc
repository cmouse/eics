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
  int gerr;
  if ((gerr = gnutls_global_init()) != GNUTLS_E_SUCCESS) {
     LOG(error) << L"(main.cc:" <<  __LINE__ << L") " << gnutls_strerror(gerr);
     return 1;
  }

  // setup locale based on user's choice
  std::locale::global( std::locale("") );

  eics::Processor proc;
  proc.configure("policy.conf");
  proc.check();

  gnutls_global_deinit();
  return 0;
}
