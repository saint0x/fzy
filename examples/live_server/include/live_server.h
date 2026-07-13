#ifndef FOZZY_LIVE_SERVER_H
#define FOZZY_LIVE_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*fz_callback_i32_v0)(int32_t arg);
int32_t fz_host_init(void);
int32_t fz_host_shutdown(void);
int32_t fz_host_cleanup(void);
int32_t fz_host_last_error_code(void);
int32_t fz_host_last_error_class(void);
const char* fz_host_last_error_message(void);
int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);
int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);

typedef struct model_types_UserRow {
    int32_t id;
    int32_t version;
} model_types_UserRow;

typedef enum model_types_HttpState {
    model_types_HttpState_Listening = 0,
    model_types_HttpState_Draining = 1,
} model_types_HttpState;

/* no exported extern "C" functions found */

#ifdef __cplusplus
}
#endif

#endif
