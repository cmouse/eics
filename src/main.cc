#include "eics.hh"
#include <boost/program_options.hpp>

eics::Log::TLogLevel eics::Log::minLogLevel = eics::Log::debug;
namespace bpo = boost::program_options;

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

  bpo::options_description desc("Allowed options");
  desc.add_options() 
     ("help", "this message")
     ("policy", bpo::value<std::string>()->default_value(SYSCONFDIR "/policy.conf"), "policy file to load")
     ("init", "initialize database")
     ("check", "compare database to filesystem")
     ("update", "compare and update database")
     ("test", "run test run to show matched files")
  ;

  bpo::variables_map vm;
  bpo::store(bpo::parse_command_line(argc, argv, desc), vm);
  bpo::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << std::endl;
    return 1;
  }
 
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  // parse command line arguments

  eics::Processor proc;
  proc.configure(vm["policy"].as<std::string>());
/*  if (vm.count("init")) 
    proc.init(); 
  else */ if (vm.count("check"))
    proc.check();
/*  else if (vm.count("update")) 
    proc.update();
  else if (vm.count("test")) 
    proc.test(); */
  else {
    LOG(error) << L"(main.cc:" << __LINE__ << L") No operation given";
    std::cout << desc << std::endl;
    return 1;
  }
  return 0;
}
