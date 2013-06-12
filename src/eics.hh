#include "config.h"
#include <iostream>
#include <string>
extern "C" {
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#if GNUTLS_VERSION_NUMBER < 0x030100
int gnutls_load_file(const char* filename, gnutls_datum_t * data);
void gnutls_unload_file(gnutls_datum_t data);
#endif
};
#include <map>
#include <bitset>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <bitset>
#include <iomanip>
#include <locale>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>

#define LOG(level) \
if (eics::Log::level > eics::Log::getLogLevel()) \
;\
else \
eics::Log(eics::Log::level).get()

#define EICS_POLICY_BITS 16

// definitions

namespace eics {
   class PathPolicy;
   class Policy;

   typedef std::bitset<EICS_POLICY_BITS> PolicyBits;
   typedef std::map<std::wstring, std::wstring> GlobalPolicy;
   typedef std::map<std::wstring, PathPolicy> FsPolicy;

  class Log {
  public:
     enum TLogLevel { error = 0, warn = 1, info = 2, debug = 3 };
     Log(TLogLevel level) : logLevel(level) { };
     ~Log();
     std::wstringstream& get() { return buf; };

     static TLogLevel getLogLevel() { return Log::minLogLevel; };
     static void setLogLevel(TLogLevel value) { Log::minLogLevel = value; };
   private:
     std::wstringstream buf;
     TLogLevel logLevel;
     static TLogLevel minLogLevel;
   };
 
  class PathPolicy {
  public:
     PathPolicy() {};
     PathPolicy(const boost::filesystem::path &path, const PolicyBits &policy) { this->_path = path; this->_policy = policy; };
     PathPolicy(const boost::filesystem::path &path, const std::wstring &policyString) { this->_path = path; this->_policyString = policyString; };
     PathPolicy& operator=(const PathPolicy &other) { this->_path = other.path(); this->_policy = other.policy(); this->_policyString = other.policyString(); return *this; };
     ~PathPolicy() {};

     const boost::filesystem::path& path() const { return this->_path; };
     const PolicyBits& policy() const { return this->_policy; };
     const std::wstring policyString() const { return this->_policyString; };

     bool hashSet() const { return this->policy().test(Hash); };
     bool accessTimeSet() const { return this->policy().test(AccessTime); };
     bool allowNewerSet() const { return this->policy().test(AllowNewer); };
     bool allowOlderSet() const { return this->policy().test(AllowOlder); };
     bool allowGrowSet() const { return this->policy().test(AllowGrow); };
     bool allowShrinkSet() const { return this->policy().test(AllowShrink); };
     bool timeSet() const { return this->policy().test(Time); };
     bool aclSet() const { return this->policy().test(Acl); };
     bool attrSet() const { return this->policy().test(Attr); };
     bool matchInodeSet() const { return this->policy().test(MatchInode); };
     bool matchNameSet() const { return this->policy().test(MatchName); };
     enum TPolicyFlag { Hash = 0, AccessTime = 1, AllowNewer = 2, AllowOlder = 3, AllowGrow = 4, AllowShrink = 5, Time = 6, Acl = 7, Attr = 8, MatchInode = 9, MatchName = 10, Skip = 11, Children = 12};

     void setPolicy(const PolicyBits& newPolicy) { this->_policy = newPolicy; };
     void setPolicyString(const std::wstring &policyString) { this->_policyString = policyString; };
  private:
     boost::filesystem::path _path;
     std::wstring _policyString;
     PolicyBits _policy;
  };

  class Policy {
  public:
     Policy();
     ~Policy();

     bool load(const boost::filesystem::path &file);
     const PathPolicy& findPolicy(const boost::filesystem::path &path) const;
     bool get(const std::wstring &key, std::wstring &value) const { GlobalPolicy::const_iterator iter = global_policy.find(key); if (iter == global_policy.end()) return false; else value = iter->second; return true; };
  private:
     bool parseOptions(const std::wstring &options, const PolicyBits &in, PolicyBits &out);
     bool createOrUpdatePolicy(const boost::filesystem::path &path, const std::wstring &policyString);
     GlobalPolicy global_policy;
     FsPolicy fs_policy;
  };

  class Filesystem {
  public:
    Filesystem() {};
    ~Filesystem() {};
    const boost::filesystem::path& path() const { return this->_root; };
    void setRoot(const boost::filesystem::path &newRoot) { this->_root = newRoot; };
  private:
     boost::filesystem::path _root;
  };

  class DatabaseEntry {
  public:
     DatabaseEntry() {};
     ~DatabaseEntry() {};
  };

  class Database {
  public:
     Database() {};
     ~Database() {};
  };

  class Keys {
  public:
     Keys() {};
     ~Keys() {};
     bool loadPublicKey(const boost::filesystem::path &pubkey_path);
  private:
     gnutls_pubkey_t pubkey;
     gnutls_privkey_t privkey;
  };

  class Report {
  public:
     Report() {};
     ~Report() {};
  };

  class Processor {
  public:
     Processor() {};
     ~Processor() {};
     bool configure(const boost::filesystem::path &configFile) { 
       if (this->_policy.load(configFile) == false) return false;
       boost::filesystem::path pubkey_path;
       std::wstring param;
       if (_policy.get(L"publickeypath", param) == false) {
          LOG(error) << "(keys.cc: " << __LINE__ << L") missing configuration parameter PublickeyPath";
          return false;
       }
       pubkey_path = param;
       if (this->_keys.loadPublicKey(pubkey_path) == false) return false;
       if (this->scanFileSystems() == false) return false;
       return true;
     };

     bool initialize();
     bool check() { return false; };
     bool update();

     bool loadDatabase();
     bool writeDatabase();
     
     Report& report() { return this->_report; };
  private:
     bool scanFileSystems();

     Database _database;
     Policy _policy;
     std::map<dev_t, Filesystem> _filesystems;
     Report _report;
     Keys _keys;
  };

  bool eics_hash_file(const std::string &file, gnutls_digest_algorithm_t algo, std::string &result);

};
