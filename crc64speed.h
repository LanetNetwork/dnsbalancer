#ifndef CRC64SPEED_H
#define CRC64SPEED_H
#include "crcspeed.h"
#include "stdbool.h"

/* Does not require init */
uint64_t crc64(uint64_t crc, const void *data, const uint64_t len);

/* All other crc functions here require _init() before usage. */
bool crc64speed_init(void);
uint64_t crc64_lookup(uint64_t crc, const void *in_data, const uint64_t len);
uint64_t crc64speed(uint64_t crc, const void *s, const uint64_t l);

#endif
