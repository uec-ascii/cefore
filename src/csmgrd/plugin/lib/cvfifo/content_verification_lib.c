#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <csmgrd/csmgrd_plugin.h>

int verify_content(CsmgrdT_Content_Entry* entry){
    // とりあえずログを出力するだけの例
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
        return;
    }

    // msgとnameを文字列として扱うために各lenまでをコピーしてヌル終端する
    unsigned char msg_buf[entry->msg_len + 1];
    unsigned char name_buf[entry->name_len + 1];
    memcpy(msg_buf, entry->msg, entry->msg_len);
    memcpy(name_buf, entry->name, entry->name_len);
    // 1文字ずつ確認していき、ヌル終端が最後以外にあったら半角スペースで置き換える
    for (size_t i = 0; i < entry->msg_len; i++) {
        if (msg_buf[i] == '\0' && i != entry->msg_len - 1) {
            msg_buf[i] = ' ';
        }
    }
    for (size_t i = 0; i < entry->name_len; i++) {
        if (name_buf[i] == '\0' && i != entry->name_len - 1) {
            name_buf[i] = ' ';
        }
    }
    msg_buf[entry->msg_len] = '\0';
    name_buf[entry->name_len] = '\0';

    fprintf(log_file, "[Content Entry Info]\nmsg:%s:%u\nname:%s:%u\npay_len:%u\nchunk_num:%u\ncache_time:%lu\nexpiry:%lu\nnode:%u\nins_time:%lu\nversion:%s:%u\n\n[Parsed Payload]\n",
        msg_buf, entry->msg_len,
        name_buf, entry->name_len,
        entry->pay_len,
        entry->chunk_num,
        entry->cache_time,
        entry->expiry,
        entry->node.s_addr,
        entry->ins_time,
        entry->version, entry->ver_len
    );

    uint8_t* payload = (uint8_t*)malloc(entry->pay_len);
    if (payload == NULL) {
        fprintf(log_file, "メモリ確保に失敗しました\n");
        fclose(log_file);
        return -1;
    }

    if (get_payload(entry, payload) == 0) {
        fwrite(payload, 1, entry->pay_len, log_file);
        fprintf(log_file, "\n");
    } else {
        fprintf(log_file, "ペイロードの取得に失敗しました\n");
    }

    free(payload);

    fprintf(log_file, "[EOP]\n\n");

    fclose(log_file);


    return 0;
}

int get_payload(CsmgrdT_Content_Entry* entry, uint8_t* payload_out){
    if(entry->pay_len==0){
        // payloadの長さが0なら何もしない
        payload_out[0] = 0;
        return -1;
    }

    uint16_t name_offset, name_len, payload_offset, payload_len;
    uint8_t* payload_ptr; // ペイロードの開始ポインタ

    cef_frame_payload_parse(
        entry->msg,
        entry->msg_len,
        &name_offset,
        &name_len,
        &payload_offset,
        &payload_len
    );

    // ペイロードの開始ポインタを取得
    payload_ptr = entry->msg + payload_offset;

    // ペイロードをコピー
    memcpy(payload_out, payload_ptr, entry->pay_len);

    return 0;
}