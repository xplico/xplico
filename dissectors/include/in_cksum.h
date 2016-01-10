/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id:  $
 */

typedef struct {
	const unsigned char *ptr;
	int	len;
} vec_t;

extern int in_cksum(const vec_t *vec, int veclen);

