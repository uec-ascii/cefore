#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_frame.h>

int verify_content(CsmgrdT_Content_Entry* entry){
    // とりあえずログを出力するだけの例
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
        return;
    }

    uint8_t* payload = (uint8_t*)malloc(entry->pay_len);
    if (payload == NULL) {
        fprintf(log_file, "メモリ確保に失敗しました\n");
        fclose(log_file);
        return -1;
    }

    if (get_payload(entry, payload) == 0) {
        verify_content(entry->name, entry->name_len, payload, entry->pay_len);
        free(payload);
        fclose(log_file);
    } else {
        fprintf(log_file, "ペイロードの取得に失敗しました\n");
    }


    return 0;
}

int verify_content(unsigned char* name, uint16_t name_len, uint8_t* payload, uint16_t pay_len){
    if (name_len == 0 || pay_len == 0)
    {
        // nameまたはpayloadの長さが0なら何もしない
        return -1;
    }

    // とりあえずログを出力するだけの例
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
        return -1;
    }

    unsigned char name_buf[name_len + 1];
    memcpy(name_buf, name, name_len);
    if(name_buf==NULL){
        fprintf(log_file, "メモリ確保に失敗しました\n");
        fclose(log_file);
        return -1;
    }
    for (size_t i = 0; i < name_len; i++) {
        if (name_buf[i] == '\0' && i != name_len - 1) {
            name_buf[i] = ' ';
        }
    }
    name_buf[name_len] = '\0';

    fprintf(log_file, "[Content Entry Info]\nname:%s:%u\n[Payload]\n\n",
        name_buf, name_len
    );
    fwrite(payload, 1, pay_len, log_file);
    fprintf(log_file, "\n[EOP]\n\n");

    fclose(log_file);

    free(name_buf);

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