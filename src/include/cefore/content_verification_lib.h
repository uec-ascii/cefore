/*
 * Content Verification Library
 */
#ifndef CEFORE_CONTENT_VERIFICATION_LIB_H
#define CEFORE_CONTENT_VERIFICATION_LIB_H

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t, uint32_t */

typedef struct _node {
    unsigned char* data;
    unsigned int data_len;
    struct _node* next;
} Node;

typedef struct _hashmap {
    Node** table;
    size_t size;
} HashMap;

int init_hashmap(HashMap* map, size_t size);
int free_hashmap(HashMap* map);
size_t hash_index(const unsigned char* hashkey, size_t map_size);
int insert_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len);
int exists_in_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len);
int verify_content(HashMap* map, const unsigned char* name, uint16_t name_len, const unsigned char* payload, uint16_t payload_len);
int compute_sha256(const unsigned char* data, size_t data_len, unsigned char* out_hash);

#endif /* CEFORE_CONTENT_VERIFICATION_LIB_H */