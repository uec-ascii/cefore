#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_frame.h>

int verify_content(CsmgrdT_Content_Entry* entry);
int verify_content(unsigned char* name, uint16_t name_len, uint8_t* payload, uint16_t pay_len);
int get_payload(CsmgrdT_Content_Entry* entry, char* payload_out);