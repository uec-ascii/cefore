#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_frame.h>

int verify_content(CsmgrdT_Content_Entry* entry);
int get_payload(CsmgrdT_Content_Entry* entry, char* payload_out);