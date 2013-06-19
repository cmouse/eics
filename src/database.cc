#include "eics.hh"

#define MAGIC 0xE1C50004 // eics 0004
#define HASH_SIZE 316201 

struct database_header_s {
   uint32_t magic;
   uint64_t dbsize;
   ssize_t policy_size;
   unsigned char policy_hash[64]; 
   time_t last_updated;
   ssize_t binary_size;
   unsigned char binary_hash[64]; 
} __attribute__((packed));

struct database_storage_node {
        database_storage_node() { next = NULL; };
        eics::DatabaseEntry *entry;
        struct database_storage_node *next;
};

// two lookups, these take space about 2 or 5 megabytes heap (32 or 64 bit system)
static struct database_storage_node** ptr_by_dev_ino = 0;
static struct database_storage_node** ptr_by_dev_name = 0;

namespace eics {

Database::Database() {
    if (ptr_by_dev_ino == 0) {
       ptr_by_dev_ino = new struct database_storage_node*[HASH_SIZE];
    }
    if (ptr_by_dev_name == 0) {
       ptr_by_dev_name = new struct database_storage_node*[HASH_SIZE];
    }

    // and now we have a database
};

Database::~Database() {
    if (ptr_by_dev_name != 0) 
      delete [] ptr_by_dev_name;
    if (ptr_by_dev_ino != 0) 
      delete [] ptr_by_dev_ino;
}

DatabaseEntry* Database::find(dev_t dev, const std::wstring& name) 
{
   struct database_storage_node *ptr;

   size_t idx, len;
   const wchar_t *tmpname = name.c_str();
   len = wcslen(tmpname);

   // calculate index
   idx = static_cast<size_t>( eics_crc64((const unsigned char*)tmpname, len*sizeof(wchar_t)) % HASH_SIZE );
   ptr = ptr_by_dev_name[idx];

   if (ptr == NULL || ptr->entry == NULL) // not found at all
     return NULL;

   while(ptr) {
      if (ptr->entry->device() == dev && ptr->entry->path() == name) 
        break;
      ptr = ptr->next;
   }

   return ptr->entry;
}

DatabaseEntry* Database::find(dev_t dev, ino_t ino) 
{
   // similar to above
   struct database_storage_node *ptr;
   size_t idx;
   idx = ( dev ^ ino ) % HASH_SIZE;
   ptr = ptr_by_dev_ino[idx];

   if (ptr == NULL || ptr->entry == NULL) // not found
     return NULL;

   while(ptr) {
      if (ptr->entry->device() == dev && ptr->entry->inode() == ino)
        break;
      ptr = ptr->next;
   }

   return ptr->entry;
}

DatabaseEntry* Database::create(dev_t dev, ino_t ino, const std::wstring& name)
{
   struct database_storage_node *ptr;
   struct database_storage_node *dn_node = new database_storage_node;
   struct database_storage_node *di_node = new database_storage_node;
   DatabaseEntry *entry = new DatabaseEntry();

   size_t dn_idx, di_idx, len;
   const wchar_t *tmpname = name.c_str();
   len = wcslen(tmpname);

   dn_node->entry = entry;
   di_node->entry = entry;

   // calculate index
   dn_idx = static_cast<size_t>( eics_crc64((const unsigned char*)tmpname, len*sizeof(wchar_t)) % HASH_SIZE );
   di_idx = ( dev ^ ino ) % HASH_SIZE;

   if (ptr_by_dev_name[dn_idx] == NULL) {
      ptr_by_dev_name[dn_idx] = dn_node;
   } else {
      ptr = ptr_by_dev_name[dn_idx];
      while(ptr->next != NULL) ptr = ptr->next;
      ptr->next = dn_node;
   }

   if (ptr_by_dev_ino[di_idx] == NULL) {
      ptr_by_dev_ino[di_idx] = di_node;
   } else {
      ptr = ptr_by_dev_ino[di_idx];
      while(ptr->next != NULL) ptr = ptr->next;
      ptr->next = di_node;
   }

   return entry;
}

};
