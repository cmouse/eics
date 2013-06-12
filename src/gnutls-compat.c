#include <errno.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#if GNUTLS_VERSION_NUMBER < 0x030100
int gnutls_load_file(const char* filename, gnutls_datum_t * data) {
  FILE *in;
  struct stat st;
  off_t len;
  void *tmp;

  in = fopen(filename, "rb");
  if (in == NULL) { 
     return GNUTLS_E_FILE_ERROR;
  }
 
  if (fstat(fileno(in), &st)) {
     fclose(in);
     return GNUTLS_E_FILE_ERROR;
  }
  
  tmp = gnutls_malloc(st.st_size);
  len = fread(tmp, 1, st.st_size, in);

  if (len < st.st_size) {
     gnutls_free(tmp); 
     fclose(in);
     return GNUTLS_E_FILE_ERROR;
  }

  fclose(in);
  
  data->data = tmp;
  data->size = st.st_size;

  return GNUTLS_E_SUCCESS;
}

void gnutls_unload_file (gnutls_datum_t data) {
  gnutls_free(data.data);
}

#endif
