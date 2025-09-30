#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cefore/cef_frame.h>

int verify_content(unsigned char* msg, uint16_t msg_len){
    if (msg_len == 0)
    {
        // メッセージの長さが0なら何もしない
        return -1;
    }

    // とりあえずログを出力するだけの例
    FILE *log_file = fopen("/tmp/content_verification.log", "a");
    if (log_file == NULL) {
        perror("ログファイルを開けませんでした");
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
    memcpy(payload, msg + payload_offset, payload_len);
    
    // nameをコピーしてヌル終端を追加
    unsigned char name_buf[name_len + 1];
    if(name_buf==NULL){
        fprintf(log_file, "メモリ確保に失敗しました\n");
        fclose(log_file);
        return -1;
    }
    memcpy(name_buf, name_offset + msg, name_len);
    // ヌル文字をスペースに置換（途中にヌル文字があるとログ出力が途切れるため）
    for (size_t i = 0; i < name_len; i++) {
        if (name_buf[i] == '\0' && i != name_len - 1) {
            name_buf[i] = ' ';
        }
    }
    name_buf[name_len] = '\0';

    fprintf(log_file, "[Content Entry Info]\nname:%s:%u\n[Payload]\n\n",
        name_buf, name_len
    );
    fwrite(payload, 1, payload_len, log_file);
    fprintf(log_file, "\n[EOP]\n\n");

    fclose(log_file);

    free(name_buf);

    return 0;
}