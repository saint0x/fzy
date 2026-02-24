#ifndef FOZZY_EXHIBIT_H
#define FOZZY_EXHIBIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t add(int32_t left, int32_t right);
uint32_t checksum(const uint8_t* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
