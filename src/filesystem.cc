#include "eics.hh"
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h> 
#endif

// determine all filesystems under rootpath
bool eics::Processor::scanFileSystems() {
   std::wstring rootPath;
   boost::filesystem::path path;
   boost::filesystem::recursive_directory_iterator end;
   struct stat st;
   struct statfs vfsst;

   if (_policy.get(L"rootpath", rootPath) == false) {
      LOG(error) << L"(filesystem.cc:" << __LINE__ << L") missing required configuration value RootPath";
      return false;
   }

   // use /proc/mounts (if available) to populate filesystem information
#ifdef HAVE_STATFS
   path = L"/proc";
   if (boost::filesystem::exists(path)) {
      // check that it is a special filesystem
      if (!statfs(path.string().c_str(), &vfsst) && vfsst.f_type == 0x9fa0) { // PROC_SUPER_MAGIC
          // it is a proc filesystem, we can use it
          std::string mp;
          std::ifstream mounts("/proc/mounts");
          while(std::getline(mounts, mp).good()) {
              std::vector<std::string> data; 
              boost::split(data, mp, boost::is_any_of(L" "));
              // first come, first serve
              if (data.size() < 2) continue;
              path = data[1];
              lstat(data[1].c_str(), &st);
              if (_filesystems.find(st.st_dev) == _filesystems.end()) {
                 _filesystems[st.st_dev].setRoot(path);
                 LOG(debug) << L"(filesystem.cc:" << __LINE__ << L") found new filesystem at " << path.wstring();
              } else if ( _filesystems[st.st_dev].path() != path) {
                 LOG(debug) << L"(filesystem.cc:" << __LINE__ << L") possible bind mount at " << path.wstring();
              }
          }
          return true;
      }
   } 
#endif

   try {
      path = rootPath;
      path.normalize();

      // mark as filesystem
      lstat(path.string().c_str(), &st);
       _filesystems[st.st_dev].setRoot(path);

      for(boost::filesystem::recursive_directory_iterator fsiter(path); fsiter != end;) {
          // keep track of filesystems by rdev
          try {
             if (!boost::filesystem::is_symlink((*fsiter).path()) && boost::filesystem::is_directory((*fsiter).path())) {
                lstat((*fsiter).path().string().c_str(), &st);
                if (_filesystems.find(st.st_dev) == _filesystems.end()) {
                   // new file system found
                   LOG(debug) << L"(filesystem.cc:" << __LINE__ << L") found new filesystem at " << (*fsiter).path().wstring();
                   _filesystems[st.st_dev].setRoot((*fsiter).path());
                   std::cout << st.st_rdev << std::endl;
                } 
             }
             if (boost::filesystem::is_symlink((*fsiter).symlink_status())) {
                fsiter.no_push();
             }
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
