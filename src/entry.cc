#include "eics.hh"

struct database_entry_header_s {
    size_t nlen;
    uint8_t is_hashed; 
    struct stat st;
} __attribute__((packed));


