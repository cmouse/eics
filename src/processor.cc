#include "eics.hh"

bool eics::Processor::configure(const boost::filesystem::path& configFile) {
   if (this->_policy.load(configFile) == false) return false;
   boost::filesystem::path key_path;
   std::wstring param;
   if (_policy.get(L"publickey", param) == false) {
      LOG(error) << "(keys.cc: " << __LINE__ << L") missing configuration parameter Publickey";
      return false;
   }
   key_path = param;
   if (this->_keys.loadPublicKey(key_path) == false) return false;
   if (_policy.get(L"privatekey", param) == false) {
      LOG(error) << "(keys.cc: " << __LINE__ << L") missing configuration parameter PrivateKey";
      return false;
   }
   key_path = param;
   if (this->_keys.loadPrivateKey(key_path) == false) return false;
   if (this->scanFileSystems() == false) return false;
   return true;
}

bool eics::Processor::check() {
   // spawn thread per filesystem when we have room

   return false;
}
