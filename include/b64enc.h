/**
 * @file b64enc.h
 * @brief Function prototypes for @p b64enc.c
 */
#pragma once

#include <stdint.h>
#include <stdlib.h>

char *b64enc(const uint8_t *in, size_t len);
