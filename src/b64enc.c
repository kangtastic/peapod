/**
 * @file b64enc.c
 * @brief Base64 encoder
 */

#include "b64enc.h"

/**
 * @brief The length of the resulting Base64-encoded string, including the null
 *        terminator, from an input of length @p len
 */
#define b64len(len) (4 * ((len) / 3) + 5)

/** @brief Base64 index table. */
static const char b64[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

/**
 * @brief Base64 encoder
 *
 * @param in Data to be Base64-encoded
 * @param len The length of @p in
 * @return A newly allocated C string with the Base64-encoded contents of @p in
 *         if successful, or @p NULL if unsuccessful
 * @note If successful, caller is responsible for <tt>free(3)</tt>ing the result
 */
char *b64enc(const uint8_t *in, size_t len)
{
	char *ret = malloc(b64len(len));
	if (ret == NULL)
		return NULL;

	size_t i = 0;
	size_t j = 0;
	for (; j + 2 < len; j += 3) {
		ret[i++] = b64[in[j] >> 2];
		ret[i++] = b64[(in[j] & 0x3) << 4 | (in[j + 1] & 0xf0) >> 4];
		ret[i++] = b64[(in[j + 1] & 0xf) << 2 |
			       (in[j + 2] & 0xc0) >> 6];
		ret[i++] = b64[in[j + 2] & 0x3f];
	}
	if (len - j == 1) {
		ret[i++] = b64[in[j] >> 2];
		ret[i++] = b64[(in[j] & 0x3) << 4];
		ret[i++] = '=';
		ret[i++] = '=';
	} else if (len - j == 2) {
		ret[i++] = b64[in[j] >> 2];
		ret[i++] = b64[(in[j] & 0x3) << 4 | (in[j + 1] & 0xf0) >> 4];
		ret[i++] = b64[(in[j + 1] & 0xf) << 2];
		ret[i++] = '=';
	}
	ret[i] = '\0';

	return ret;
}
