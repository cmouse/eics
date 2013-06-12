#include "eics.hh"

bool eics::Keys::loadPublicKey(const boost::filesystem::path& pubkey_path) {
   gnutls_datum_t datum;
   int gerr;

   gerr = gnutls_load_file(pubkey_path.string().c_str(), &datum);
   if (gerr) {
       LOG(error) << "(keys.cc: " << __LINE__ << L") " << gnutls_strerror(gerr);
       return false;
   }

   gerr = gnutls_pubkey_import(pubkey, &datum, GNUTLS_X509_FMT_PEM);
   gnutls_unload_file(datum);

   if (gerr) {
       LOG(error) << "(keys.cc: " << __LINE__ << L") " << gnutls_strerror(gerr);
       return false;
   }
   LOG(debug) << "(keys.cc: " << __LINE__ << L") loaded public key from " << pubkey_path.wstring();

   return true; 
}
