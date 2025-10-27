#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>    /* memcpy, memcmp */
#include <openssl/sha.h>
#include <cefore/content_verification_lib.h>

int init_hashmap(HashMap* map, size_t size) {
    if (map == NULL || size == 0) {
        return -1; // 無効な引数
    }
    map->size = size;
    map->table = calloc(size, sizeof(Node*));
    if (map->table == NULL) {
        return -1; // メモリ確保失敗
    }
    return 0; // 成功
}

int free_hashmap(HashMap* map) {
    if (map == NULL) {
        return -1; // 無効な引数
    }
    for (size_t i = 0; i < map->size; i++) {
        Node* current = map->table[i];
        while (current != NULL) {
            Node* temp = current;
            current = current->next;
            free(temp->data);
            free(temp);
        }
    }
    free(map->table);
    map->table = NULL;
    map->size = 0;
    return 0; // 成功
}

size_t hash_index(const unsigned char* hashkey, size_t map_size) {
    /* 先頭4バイトを整数化してインデックス化（アラインメント未定義を避ける） */
    uint32_t v = 0;
    memcpy(&v, hashkey, sizeof(uint32_t));
    return (size_t)(v % (uint32_t)map_size);
}

int insert_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len) {
    if (map == NULL || map->table == NULL) {
        FILE *log_file = fopen("/tmp/content_verification.log", "a");
        fprintf(log_file, "The hash map is not initialized.\n");
        fclose(log_file);
        return -1; // ハッシュマップが初期化されていない
    }
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    fprintf(log_file, "Insert Hashmap\nhashkey: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(log_file, "%02x", hashkey[i]);
    }
    fprintf(log_file, "\ndata: ");
    fwrite(data, 1, data_len, log_file);
    fprintf(log_file, "\ndata_len: %zu\n", data_len);
    // hashkeyにはSHA-256のハッシュ値が入る前提。SHA-256の前半32ビットを切り出して整数とし、ハッシュマップの長さで割った余りをインデックスとする
    size_t hash = hash_index(hashkey, map->size);
    fprintf(log_file, "Hash Index: %zu\n", hash);
    fclose(log_file);
    // 新しいノードを作成してリストの先頭に追加
    Node* new_node = malloc(sizeof(Node));
    if (new_node == NULL) {
        return -1; // メモリ確保失敗
    }
    new_node->data = malloc(data_len);
    if (new_node->data == NULL) {
        free(new_node);
        return -1; // メモリ確保失敗
    }
    memcpy(new_node->data, data, data_len);
    new_node->data_len = data_len;
    new_node->next = map->table[hash];
    map->table[hash] = new_node;
    return 0; // 成功
}

int exists_in_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len) {
    if (map == NULL || map->table == NULL) {
        return 0; // ハッシュマップが初期化されていない
    }
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    fprintf(log_file, "Exists in HashMap\nhashkey: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(log_file, "%02x", hashkey[i]);
    }
    fprintf(log_file, "\ndata: ");
    fwrite(data, 1, data_len, log_file);
    fprintf(log_file, "\ndata_len: %zu\n", data_len);
    size_t hash = hash_index(hashkey, map->size);
    fprintf(log_file, "Hash Index: %zu\n", hash);
    Node* current = map->table[hash];
    while (current != NULL) {
        fprintf(log_file, "Comparing with entry data: ");
        for (size_t i = 0; i < current->data_len; i++) {
            fprintf(log_file, "%02x", current->data[i]);
        }
        fprintf(log_file, "\n");
        if (memcmp(current->data, data, data_len) == 0) {
            // 見つかった場合、1を返す
            fprintf(log_file, "Match found\n");
            fclose(log_file);
            return 1; // 存在する
        }
        current = current->next;
    }
    fprintf(log_file, "No match found\n");
    fclose(log_file);
    return 0; // 存在しない
}


int verify_content(HashMap* map, const unsigned char* name, uint16_t name_len, uint32_t chunk_num, const unsigned char* payload, uint16_t payload_len) {
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
        return -1;
    }

    if (name_len == 0 || payload_len == 0) {
        fprintf(log_file, "名前またはペイロードの長さが0です。検証をスキップします。\n");
        fclose(log_file);
        // 名前またはペイロードの長さが0なら何もしない
        return -1;
    }

    fprintf(log_file, "Verifying Content\n");
    fprintf(log_file, "Name: ");
    fwrite(name, 1, name_len, log_file);
    fprintf(log_file, "\nName Length: %u\n", name_len);
    fprintf(log_file, "Chunk Number: %u\n", chunk_num);
    fprintf(log_file, "Payload Length: %u\n", payload_len);
    fprintf(log_file, "Payload: ");
    fwrite(payload, 1, payload_len, log_file);
    fprintf(log_file, "\n");

    // payloadをopenssh/sha.hのSHA256でハッシュ化
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(payload, payload_len, hash) != 0) {
        fprintf(log_file, "SHA256の計算に失敗しました\n");
        fclose(log_file);
        return -1;
    }

    fprintf(log_file, "\n[SHA256 Hash]\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(log_file, "%02x", hash[i]);
    }
    fprintf(log_file, "\n");

    
    // コンテンツ検証
    // chunk_numの10進数での桁数
    int chunk_num_digits = snprintf(NULL, 0, "%u", chunk_num);
    size_t packet_info_len = name_len + 1 + chunk_num_digits + 1;
    unsigned char* packet_info = malloc(packet_info_len);
    if(packet_info == NULL){
        fprintf(log_file, "メモリ確保に失敗しました\n");
        fclose(log_file);
        return -1;
    }
    // packet_infoにname（バイナリ）をコピー
    memcpy(packet_info, name, name_len);
    // ':'を追加
    packet_info[name_len] = ':';
    // chunk_numを文字列で連結
    snprintf((char*)(packet_info + name_len + 1), packet_info_len - name_len - 1, "%u", chunk_num);
    // packet_infoをハッシュ化
    fprintf(log_file, "[Packet Info]\n");
    fwrite(packet_info, 1, packet_info_len, log_file);
    fprintf(log_file, "\n");
    fclose(log_file);
    int ret = 0;
    if (exists_in_hashmap(map, hash, packet_info, packet_info_len) == 1) {
        log_file = fopen("/tmp/content_verification.log", "a");
        fprintf(log_file, "コンテンツはデータベースに一致します。\n");
    } else {
        log_file = fopen("/tmp/content_verification.log", "a");
        fprintf(log_file, "コンテンツはデータベースに一致しません。\n");
        ret = -1;
    }
    fprintf(log_file, "----------\n");
    fclose(log_file);
    free(packet_info);
    return ret;
}

int compute_sha256(const unsigned char* data, size_t data_len, unsigned char* out_hash){
    SHA256_CTX sha256;
    if (SHA256_Init(&sha256) == 0) {
        return -1;
    }
    if (SHA256_Update(&sha256, data, data_len) == 0) {
        return -1;
    }
    if (SHA256_Final(out_hash, &sha256) == 0) {
        return -1;
    }
    return 0;
}