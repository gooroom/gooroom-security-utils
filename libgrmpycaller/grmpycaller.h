/*
* Author: Hyun-min Kim <hmkim@hancom.com>
*/

#ifndef PYCALLER_H
#define PYCALLER_H

#define VERIFY_SUCCESS                  0
#define FILE_OPEN_ERROR                 -1
#define READ_PUBKEY_FROM_CERT_ERROR     -2
#define DIGEST_VERIFY_INIT_ERROR        -3
#define DIGEST_VERIFY_UPDATE_ERROR      -4
#define DIGEST_VERIFY_FINAL_ERROR       -5

#define PYTHONPATH  "PYTHONPATH=/usr/lib/gooroom-security-utils/pycaller/"
#define MODULE_NAME "pycaller"
#define FUNC_NAME "do_task"

#ifdef __cplusplus
extern "C" {
int verify_signature(const char *file_path);
char* do_task(const char *task);
}
#else
int verify_signature(const char *file_path);
char* do_task(const char *task);
#endif //__cplusplus

#endif //PYCALLER_H
