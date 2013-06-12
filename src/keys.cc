#include "eics.hh"

bool eics::Keys::loadPublicKey(const boost::filesystem::path& pubkey_path) {
   BIO *in = BIO_new_file(pubkey_path.string().c_str(), "rb");

   if (in == NULL) {
      eics::eics_openssl_error_log(L"keys.cc", __LINE__);
      return false;
   }

   // load key from BIO 
   PEM_read_bio_PUBKEY(in, &pubkey, eics_pass_cb, NULL);

   if (!pubkey) {
      eics::eics_openssl_error_log(L"keys.cc", __LINE__);
   } else {
      LOG(debug) << L"(keys.cc:" << __LINE__ << L") loaded public key from " << pubkey_path.wstring();
   }
   BIO_free(in);

   return pubkey != NULL; 
}

bool eics::Keys::loadPrivateKey(const boost::filesystem::path& privkey_path) {
   BIO *in = BIO_new_file(privkey_path.string().c_str(), "rb");

   if (in == NULL) {
      eics::eics_openssl_error_log(L"keys.cc", __LINE__);
      return false;
   }

   // load key from BIO
   PEM_read_bio_PrivateKey(in, &privkey, eics_pass_cb, NULL);

   if (!privkey) {
      eics::eics_openssl_error_log(L"keys.cc", __LINE__);
   } else {
      LOG(debug) << L"(keys.cc:" << __LINE__ << L") loaded private key from " << privkey_path.wstring();
   }

   BIO_free(in);

   return privkey != NULL;
}
