#include "eics.hh"

#define POLICY_PARSE_FLAG(x) if ( boost::iequals(flagName, L###x) ) { \
   out.set(PathPolicy::x, val); \
   continue; \
} 

namespace eics {

Policy::Policy()
{
};

Policy::~Policy()
{
};

bool Policy::parseOptions(const std::wstring &options, const PolicyBits &in, PolicyBits &out) 
{
   // allowed keywords: Hash, AccessTime, AllowNewer, AllowOlder, AllowGrow, AllowShrink (these two disable Hash)
   //                   Time, Acl, Attr, MatchInode, MatchName

   std::vector<std::wstring> tok;
   boost::split(tok, options, boost::is_any_of(L" \t"));
   out = in; // initialize with previous

   BOOST_FOREACH(std::wstring &flag, tok) {
      bool val = (flag[0] != '-');
      std::wstring flagName;
      if (flag[0] == '+' || flag[0] == '-') {
         flagName = flag.substr(1);
      } else flagName = flag;

      if (flagName.empty()) continue;

      POLICY_PARSE_FLAG(Hash);
      POLICY_PARSE_FLAG(AccessTime);
      POLICY_PARSE_FLAG(AllowNewer);
      POLICY_PARSE_FLAG(AllowOlder);
      POLICY_PARSE_FLAG(AllowGrow);
      POLICY_PARSE_FLAG(AllowShrink);
      POLICY_PARSE_FLAG(Time);
      POLICY_PARSE_FLAG(Acl);
      POLICY_PARSE_FLAG(Attr);
      POLICY_PARSE_FLAG(MatchInode);
      POLICY_PARSE_FLAG(MatchName);
      POLICY_PARSE_FLAG(Skip);
      POLICY_PARSE_FLAG(Children);

      LOG(error) << L"(policy.cc:" << __LINE__ << L") Invalid policy flag '" << flagName << "' used"; 
      return false;
   }

   return true;
}

bool Policy::createOrUpdatePolicy(const boost::filesystem::path &path, const std::wstring &policyString)
{
    FsPolicy::iterator node;
    // lookup or add
    node = fs_policy.find(path.wstring());
    if (node == fs_policy.end()) {
       fs_policy[path.wstring()] = PathPolicy(path,policyString);
       LOG(debug) << L"(policy.cc:" << __LINE__ << L") Create policy for path '" << path.wstring() << L"' = '" << policyString << L"'";
    } else {
       node->second.setPolicyString(policyString);
       LOG(debug) <<  L"(policy.cc:" << __LINE__ << L") Update policy for path '" << path.wstring() << L"' = '" << policyString << L"'";
    }
    return true;
}

const PathPolicy& Policy::findPolicy(const boost::filesystem::path &path) const {
    // iterate all and return the longest suitable match
    FsPolicy::const_iterator iter;
    boost::filesystem::path search = path;

    while(search != path.root_path()) {
       iter = fs_policy.find(search.wstring());
       if (iter != fs_policy.end()) return iter->second;
       search = search.branch_path();
    }

    iter = fs_policy.find(path.root_path().wstring());
    return iter->second;
}

bool Policy::load(const boost::filesystem::path &file) 
{    
   bool inPathContext=false;
   ssize_t linenumber=0;
   std::wstring line;
   boost::filesystem::path path;
   PolicyBits rootPolicy(0);

   LOG(debug) << L"(policy.cc:" << __LINE__ << L") Loading policy file " << file;

   std::wifstream policyFile(file.string().c_str(), std::wifstream::in);

   if (!policyFile.is_open()) {
     LOG(error) << L"(policy.cc:" << __LINE__ << L") cannot open file " << file;
     return false;
   }

   // create default policy
   boost::filesystem::path rootPath(L"/");
   createOrUpdatePolicy(rootPath, L"");

   while(std::getline (policyFile, line).good()) {
      linenumber++;
      // find where line starts and ends
      size_t lineStart = line.find_first_not_of(std::wstring(L" \t\r\n"));
      size_t lineStop = line.find_last_not_of(std::wstring(L" \t\r\n"));

      if (lineStart == std::wstring::npos && lineStop == std::wstring::npos) continue; // skip empty lines
      if (lineStart == std::wstring::npos) lineStart = 0;
      if (lineStop == std::wstring::npos) lineStop = line.size();

      line = line.substr(lineStart, lineStop - lineStart + 1);
      if (line[0] == '#') continue; // skip comments
   
      size_t paramPos = line.find_first_of(std::wstring(L" \t\r\n"), lineStart);

      if (paramPos == std::wstring::npos) {
         if (inPathContext && line[0] == '<') {
            if (boost::iequals(line, L"</location>")) {
              inPathContext = false;
              continue;
            } else {
              LOG(error) << L"(policy.cc:" << __LINE__ << L") Cannot understand closing tag '" << line.substr(2, line.size()-2-1) << L"' at line " << linenumber;
              return false;
            }
         } 
         LOG(error) << L"(policy.cc:" << __LINE__ << L") Syntax error at line " << linenumber;
         return false;
      }

      std::wstring key = line.substr(0, paramPos);
      std::transform(key.begin(), key.end(), key.begin(), ::towlower); // lowercase key
      std::wstring param = line.substr(paramPos+1);

      if (line[0] == '<' && !inPathContext) {
         if (key.compare(L"<location") == 0) {
           // this is a location specifier
           inPathContext = true;
           path = param.substr(0, param.size()-1);
           path.normalize();
           LOG(debug) << L"(policy.cc:" << __LINE__ << L") new path " << path.wstring() << L" found";
           continue;
         } else {
           LOG(error) << L"(policy.cc:" << __LINE__ << L") Cannot understand tag '" << key.substr(1) << L"' at line " << linenumber;
           return false;
         }
      }

      if (inPathContext && key == L"options") {
         createOrUpdatePolicy( path, param );
         continue;
      }

      if (key == L"loglevel") {
         if (boost::iequals(param, L"debug")) Log::setLogLevel(Log::debug);
         if (boost::iequals(param, L"info")) Log::setLogLevel(Log::info);
         if (boost::iequals(param, L"warn")) Log::setLogLevel(Log::warn);
         if (boost::iequals(param, L"error")) Log::setLogLevel(Log::error);
      }

      if (param[0] == '"') {
         size_t param_end = param.find_last_of(L"\"");
         if (param_end == std::wstring::npos) {
           LOG(error) << L"(policy.cc:" << __LINE__ << L") Missing closing \" at line " << linenumber;
           return false;
         }
      
         param = param.substr(1, param_end-1);
      }
      
      global_policy[key] = param;

      LOG(debug) << L"(policy.cc:" << __LINE__ << L") eics_global_policy[" << key << L"] = " << param;
   }


   PathPolicy pol = findPolicy(rootPath);
   if (parseOptions(pol.policyString(), rootPolicy, rootPolicy) == false) {
      return false;
   }
   pol.setPolicy(rootPolicy); 

   // rewrite policy into bitmap
   BOOST_FOREACH(FsPolicy::value_type &node, fs_policy) {
      PolicyBits newPolicy;
      if (parseOptions(node.second.policyString(), rootPolicy, newPolicy) == false) return false;
      node.second.setPolicy(newPolicy);
      LOG(debug) << L"(policy.cc:" << __LINE__ << L") setting policy for '" << node.second.path() << "' = 0x" << std::setbase(16) << node.second.policy().to_ulong();
      rootPolicy = newPolicy;
   }
   return true;
};

};
