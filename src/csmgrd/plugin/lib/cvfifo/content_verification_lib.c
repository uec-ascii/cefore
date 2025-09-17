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

    fprintf(log_file, "Hello, World!\n");

    // msgとnameを文字列として扱うために各lenまでをコピーしてヌル終端する
    char msg_buf[entry->msg_len + 1];
    char name_buf[entry->name_len + 1];
    memcpy(msg_buf, entry->msg, entry->msg_len);
    memcpy(name_buf, entry->name, entry->name_len);
    msg_buf[entry->msg_len] = '\0';
    name_buf[entry->name_len] = '\0';

    fprintf(log_file, "msg:%s:%u\nname:%s:%u\npay_len:%u\nchunk_num:%u\ncache_time:%lu\nexpiry:%lu\nnode:%u\nins_time:%lu\nversion:%s:%u\n",
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
    fclose(log_file);

    return 0;
}