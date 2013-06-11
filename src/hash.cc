#include "eics.hh"

bool eics_hash_file(const std::string &file, gnutls_digest_algorithm_t algo, std::string &result)
{ 
   std::ifstream file_in;
   char buffer[4096];
   size_t rlen;
   gnutls_hash_hd_t ctx;
   int gerr;

   try {
      file_in.open(file.c_str(), std::ifstream::in | std::ifstream::binary);
   } catch (std::ios_base::failure &file_open_ex) {
      // FIXME: Log this
      return false;
   }

   if ((gerr = gnutls_hash_init(&ctx, algo)) != 0) {
      // FIXME: Log this
      return false;
   }

   rlen = 0;

   while(file_in) {
      file_in.read(buffer, sizeof buffer);
      rlen = file_in.gcount(); 
      gnutls_hash(ctx, buffer, rlen);
   }

   rlen = gnutls_hash_get_len(algo);
   gnutls_hash_deinit(ctx, buffer);
   result.assign(buffer, rlen);

   return true;
}
