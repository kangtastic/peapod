#pragma once

/* Length of the resulting Base64-encoded string, including
 * the null terminator, from an input of length len.
 */
#define b64len(len) (4 * ((len) / 3) + 5)

char *b64enc(const uint8_t *in, size_t len);
