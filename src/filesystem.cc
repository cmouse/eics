#include "eics.hh"

// determine all filesystems under rootpath
bool eics::Processor::scanFileSystems() {
   std::wstring rootPath;
   boost::filesystem::path path;
   boost::system::error_code ec;
   boost::filesystem::recursive_directory_iterator end;

   if (_policy.get(L"rootpath", rootPath) == false) {
      LOG(error) << L"(filesystem.cc:" << __LINE__ << L") missing required configuration value RootPath";
      return false;
   }

   try {
      path = rootPath;
      path.normalize();

      for(boost::filesystem::recursive_directory_iterator fsiter(path); fsiter != end;) {
          // keep track of filesystems by rdev
          try {
            fsiter++;
          } catch (boost::filesystem::filesystem_error &fserr) {
             std::string error0 = fserr.code().message();
             std::wstring error;
             error.assign(error0.begin(), error0.end());
             LOG(warn) << L"(filesystem.cc:" << __LINE__ << L") " << error << L": \"" << fserr.path1().wstring() << L"\"";
             fsiter.no_push();
             fsiter++;
          } catch (std::exception &ex) {
             LOG(error) << L"(filesystem.cc:" << __LINE__ << L") " << ex.what();
             return false;
          }
      }
   } catch (boost::filesystem::filesystem_error &fserr) {
      std::string error0 = fserr.code().message();
      std::wstring error;
      error.assign(error0.begin(), error0.end());
      LOG(error) << L"(filesystem.cc:" << __LINE__ << L") " << error << L": \"" << fserr.path1().wstring() << L"\"";
      return false;
   } catch (std::exception &ex) {
      LOG(error) << L"(filesystem.cc:" << __LINE__ << L") " << ex.what();
      return false;
   }

   return true;
}
