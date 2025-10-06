struct _node {
    unsigned char* data;
    unsigned int data_len;
    struct _node* next;
} typedef Node;

struct _hashmap {
    Node** table;
    size_t size;
} typedef HashMap;

int init_hashmap(HashMap* map, size_t size);
int free_hashmap(HashMap* map);
size_t hash_index(const unsigned char* hashkey, size_t map_size);
int insert_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len);
int exists_in_hashmap(HashMap* map, const unsigned char* hashkey);
int verify_content(unsigned char* msg, uint16_t msg_len);
int compute_sha256(const unsigned char* data, size_t data_len, unsigned char* out_hash);