#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cefore/cef_frame.h>
#include <openssl/sha.h>
#include "content_verification_lib.h"

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
    return (*(uint32_t*)hashkey) % map_size;
}

int insert_hashmap(HashMap* map, const unsigned char* hashkey, const unsigned char* data, size_t data_len) {
    if (map == NULL || map->table == NULL) {
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


int verify_content(HashMap* map, const unsigned char* msg, uint16_t msg_len, uint32_t chunk_num){
    if (msg_len == 0)
    {
        // メッセージの長さが0なら何もしない
        return -1;
    }

    // msgをパース
    uint16_t name_offset, name_len, payload_offset, payload_len;
    uint8_t* payload; // ペイロードの開始ポインタ
    cef_frame_payload_parse(
        msg,
        msg_len,
        &name_offset,
        &name_len,
        &payload_offset,
        &payload_len
    );
    payload = msg + payload_offset;
    if (payload == NULL || name_len == 0 || payload_len == 0)
    {
        // ペイロードの開始ポインタがNULL、nameまたはpayloadの長さが0なら何もしない
        return -1;
    }
    // とりあえずログを出力するだけの例
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
        return -1;
    }
    fprintf(log_file, "Verifying Content\n");
    fprintf(log_file, "Message: ");
    fwrite(msg, 1, msg_len, log_file);
    fprintf(log_file, "\nMessage Length: %u\n", msg_len);
    fprintf(log_file, "Name: ");
    fwrite(msg + name_offset, 1, name_len, log_file);
    fprintf(log_file, "\nName Length: %u\n", name_len);
    fprintf(log_file, "Payload: ");
    fwrite(payload, 1, payload_len, log_file);
    fprintf(log_file, "\nPayload Length: %u\n", payload_len);
    fprintf(log_file, "Chunk Number: %u\n", chunk_num);
    // payloadをコピー
    memcpy(payload, msg + payload_offset, payload_len);

    // nameをバッファにコピー（バイナリとして扱う）
    unsigned char name_buf[name_len];
    memcpy(name_buf, msg + name_offset, name_len);

    // payloadをopenssh/sha.hのSHA256でハッシュ化
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(payload, payload_len, hash) != 0) {
        fprintf(log_file, "SHA256の計算に失敗しました\n");
        fclose(log_file);
        return -1;
    }

    fprintf(log_file, "[Content Entry Info]\nname:%s:%u\n[Payload]\n",
        name_buf, name_len
    );
    fwrite(payload, 1, payload_len, log_file);
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
        return -1;
    }
    // packet_infoにname_buf（バイナリ）をコピー
    memcpy(packet_info, name_buf, name_len);
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
    fclose(log_file);
    fprintf(log_file, "----------\n");
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