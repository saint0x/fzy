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
int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);
int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);

uint32_t server_hash32(const uint8_t* ptr_borrowed, size_t len);
int32_t server_write(int32_t fd, const uint8_t* ptr_borrowed, size_t len);

#ifdef __cplusplus
}
#endif

#endif
