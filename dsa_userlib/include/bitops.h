 /*
  * Bitmap operation functions
  */

#ifndef __BITOPS_H__
#define __BITOPS_H__


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__GNUC__)
#define  BITOPS_BUILTIN_USE 1
#endif


/**
 * BITOPS_DIV_ROUND_UP - calculate quotient of integer division (round up)
 * @numerator: side effect free expression for numerator of division
 * @denominator: side effect free expression for denominator of division
 *
 * numerator and denominator must be from a type which can store
 * denominator + numerator without overflow. denominator must be larger than 0
 * and numerator must be positive.
 *
 * WARNING @numerator expression must be side-effect free
 */
#define BITOPS_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/**
 * BITS_PER_BYTE - number of bits per byte/char
 */
#define BITS_PER_BYTE	8

/**
 * BITS_PER_LONG - number of bits per long
 */
#define BITS_PER_LONG (sizeof(unsigned long) * BITS_PER_BYTE)

/**
 * BIT - return unsigned long with a bit set
 * @x: Bit which should be set
 */
#define BIT(x) (1UL << (x))

/**
 * BITS_TO_LONGS - return number of longs to save at least bit 0..(bits - 1)
 * @bits: number of required bits
 */
#define BITS_TO_LONGS(bits) \
	BITOPS_DIV_ROUND_UP(bits, BITS_PER_LONG)

/**
 * DECLARE_BITMAP - declare bitmap to store at least bit 0..(bits -1)
 * @bitmap: name for the new bitmap
 * @bits: number of required bits
 */
#define DECLARE_BITMAP(bitmap, bits) \
	unsigned long bitmap[BITS_TO_LONGS(bits)]

/**
 * GENMASK - return unsigned long with a bits set in the range [@h, @l]
 * @h: most significant bit which should be set
 * @l: least significant bit it which should be set
 *
 * WARNING this macro cannot be used to set all bits to 1 via
 * GENMASK(BITS_PER_LONG - 1, 0). Following must always be true:
 * (@h - @l) < (BITS_PER_LONG - 1). Also @h must always be larger or equal to
 * @l and never larger than (BITS_PER_LONG - 1). @l must always be larger than
 * or equal to 0.
 *
 * WARNING @l expression must be side-effect free
 */
#define GENMASK(h, l) (((1UL << ((h) - (l) + 1)) - 1) << (l))

/**
 * BITMAP_FIRST_WORD_MASK - return unsigned long mask for least significant long
 * @start: offset to first bits
 *
 * All bits which can be modified in the least significant unsigned long for
 * offset @start in the bitmap will be set to 1. All other bits will be set to
 * zero
 */
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % BITS_PER_LONG))

/**
 * BITMAP_LAST_WORD_MASK - return unsigned long mask for most significant long
 * @bits: number of bits in complete bitmap
 *
 * All bits which can be modified in the most significant unsigned long in the
 * bitmap will be set to 1. All other bits will be set to zero
 */
#define BITMAP_LAST_WORD_MASK(bits) (~0UL >> (-(bits) % BITS_PER_LONG))

/**
 * bitops_ffs() - find (least significant) first set bit plus one
 * @x: unsigned long to check
 *
 * Return: plus-one index of first set bit; zero when x is zero
 */
static __inline__ size_t bitops_ffs(unsigned long x)
{
#ifdef BITOPS_BUILTIN_USE
	return __builtin_ffsl(x);
#else
	size_t i = 1;
	size_t shift = 0;
	unsigned long t;

	if (x == 0)
		return 0;

	t = ~0UL;
	shift = BITS_PER_LONG;

	shift /= 2;
	t >>= shift;

	while (shift) {
		if ((t & x) == 0) {
			i += shift;
			x >>= shift;
		}

		shift /= 2;
		t >>= shift;
	}

	return i;
#endif
}

/**
 * bitops_ffz() - find (least significant) first zero bit plus one
 * @x: unsigned long to check
 *
 * Return: plus-one index of first zero bit; zero when x is ULONG_MAX
 */
#define bitops_ffz(x) bitops_ffs(~(x))

/**
 * hweight8() - number of set bits in an uint8_t
 * @x: uint8_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight8(uint8_t x)
{
	static const uint8_t m1 = UINT8_C(0x55);
	static const uint8_t m2 = UINT8_C(0x33);

	/* x = (x & m1) + ((x >>  1) & m1); */
	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >>  2) & m2);
	x += x >> 4;

	return x & 0x0f;
}

/**
 * hweight16() - number of set bits in an uint16_t
 * @x: uint16_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight16(uint16_t x)
{
	static const uint16_t m1 = UINT16_C(0x5555);
	static const uint16_t m2 = UINT16_C(0x3333);
	static const uint16_t m4 = UINT16_C(0x0f0f);

	/* x = (x & m1) + ((x >>  1) & m1); */
	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >>  2) & m2);
	x = (x + (x >> 4)) & m4;
	x += x >> 8;

	return x & 0x1f;
}

/**
 * hweight32() - number of set bits in an uint32_t
 * @x: uint32_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight32(uint32_t x)
{
	static const uint32_t m1 = UINT32_C(0x55555555);
	static const uint32_t m2 = UINT32_C(0x33333333);
	static const uint32_t m4 = UINT32_C(0x0f0f0f0f);

	/* x = (x & m1) + ((x >>  1) & m1); */
	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >>  2) & m2);
	x = (x + (x >> 4)) & m4;
	x += x >> 8;
	x += x >> 16;

	return x & 0x3f;
}

/**
 * hweight64() - number of set bits in an uint64_t
 * @x: uint64_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight64(uint64_t x)
{
	if (BITS_PER_LONG >= 64) {
		static const uint64_t m1 = UINT64_C(0x5555555555555555);
		static const uint64_t m2 = UINT64_C(0x3333333333333333);
		static const uint64_t m4 = UINT64_C(0x0f0f0f0f0f0f0f0f);

		/* x = (x & m1) + ((x >>  1) & m1); */
		x -= (x >> 1) & m1;
		x = (x & m2) + ((x >>  2) & m2);
		x = (x + (x >> 4)) & m4;
		x += x >> 8;
		x += x >> 16;
		x += x >> 32;

		return x & 0x7f;
	} else {
		return hweight32((uint32_t)x) + hweight32((uint32_t)(x >> 32));
	}
}

/**
 * hweight_long() - number of set bits in an unsigned long
 * @x: unsigned long to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight_long(unsigned long x)
{
#ifdef BITOPS_BUILTIN_USE
	return __builtin_popcountl(x);
#else
	size_t i;

	if (BITS_PER_LONG == 64)
		return hweight64((uint64_t)x);

	if (BITS_PER_LONG == 32)
		return hweight32((uint32_t)x);

	for (i = 0; x; i++)
		x &= x - 1;

	return i;
#endif
}

/**
 * bitops_rol8() - Rotate uint8_t to the left
 * @x: uint8_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint8_t
 */
static __inline__ uint8_t bitops_rol8(uint8_t x, size_t n)
{
	return (x << n) | (x >> ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_rol16() - Rotate uint16_t to the left
 * @x: uint16_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint16_t
 */
static __inline__ uint16_t bitops_rol16(uint16_t x, size_t n)
{
	return (x << n) | (x >> ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_rol32() - Rotate uint32_t to the left
 * @x: uint32_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint32_t
 */
static __inline__ uint32_t bitops_rol32(uint32_t x, size_t n)
{
	return (x << n) | (x >> ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_rol64() - Rotate uint64_t to the left
 * @x: uint64_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint64_t
 */
static __inline__ uint64_t bitops_rol64(uint64_t x, size_t n)
{
	return (x << n) | (x >> ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_rol_long() - Rotate unsigned long to the left
 * @x: unsigned long to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated unsigned long
 */
static __inline__ unsigned long bitops_rol_long(unsigned long x, size_t n)
{
	return (x << n) | (x >> ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_ror8() - Rotate uint8_t to the right
 * @x: uint8_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint8_t
 */
static __inline__ uint8_t bitops_ror8(uint8_t x, size_t n)
{
	return (x >> n) | (x << ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_ror16() - Rotate uint16_t to the right
 * @x: uint16_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint16_t
 */
static __inline__ uint16_t bitops_ror16(uint16_t x, size_t n)
{
	return (x >> n) | (x << ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_ror32() - Rotate uint32_t to the right
 * @x: uint32_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint32_t
 */
static __inline__ uint32_t bitops_ror32(uint32_t x, size_t n)
{
	return (x >> n) | (x << ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_ror64() - Rotate uint64_t to the right
 * @x: uint64_t to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated uint64_t
 */
static __inline__ uint64_t bitops_ror64(uint64_t x, size_t n)
{
	return (x >> n) | (x << ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitops_ror_long() - Rotate unsigned long to the right
 * @x: unsigned long to rotate
 * @n: number of bits to rotate
 *
 * Return: rotated unsigned long
 */
static __inline__ unsigned long bitops_ror_long(unsigned long x, size_t n)
{
	return (x >> n) | (x << ((BITS_PER_BYTE * sizeof(x)) - n));
}

/**
 * bitmap_zero() - Initializes bitmap with zero
 * @bitmap: bitmap to modify
 * @bits: number of bits
 *
 * Initializes all bits to zero. This also includes the overhead bits in the
 * last unsigned long which will not be used.
 */
static __inline__ void bitmap_zero(unsigned long *bitmap, size_t bits)
{
	memset(bitmap, 0, BITS_TO_LONGS(bits) * sizeof(unsigned long));
}

/**
 * bitmap_fill() - Initializes bitmap with one
 * @bitmap: bitmap to modify
 * @bits: number of bits
 *
 * Initializes all modifiable bits to one. The overhead bits in the last
 * unsigned long will be set to zero.
 */
static __inline__ void bitmap_fill(unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);

	if (l > 1)
		memset(bitmap, 0xff, (l - 1) * sizeof(unsigned long));

	bitmap[l - 1] = BITMAP_LAST_WORD_MASK(bits);
}

/**
 * set_bit() - Set bit in bitmap to one
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 */
static __inline__ void set_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;

	bitmap[l] |= 1UL << b;
}

/**
 * clear_bit() - Set bit in bitmap to zero
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 */
static __inline__ void clear_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;

	bitmap[l] &= ~(1UL << b);
}

/**
 * change_bit() - Toggle bit in bitmap
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 */
static __inline__ void change_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;

	bitmap[l] ^= 1UL << b;
}

/**
 * test_bit() - Get state of bit
 * @bit: address of bit to test
 * @bitmap: bitmap to test
 *
 * Return: true when bit is one and false when bit is zero
 */
static __inline__ bool test_bit(size_t bit, const unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;

	return !!(bitmap[l] & (1UL << b));
}

/**
 * test_and_set_bit() - Set bit in bitmap to one and return old state
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 *
 * Return: true when bit was one and false when bit was zero
 */
static __inline__ bool test_and_set_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;
	bool old;

	old = !!(bitmap[l] & (1UL << b));
	bitmap[l] |= 1UL << b;

	return old;
}

/**
 * test_and_clear_bit() - Set bit in bitmap to zero and return old state
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 *
 * Return: true when bit was one and false when bit was zero
 */
static __inline__ bool test_and_clear_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;
	bool old;

	old = !!(bitmap[l] & (1UL << b));
	bitmap[l] &= ~(1UL << b);

	return old;
}

/**
 * test_and_change_bit() - Toggle bit in bitmap and return old state
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 *
 * Return: true when bit was one and false when bit was zero
 */
static __inline__ bool test_and_change_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;
	bool old;

	old = !!(bitmap[l] & (1UL << b));

	bitmap[l] ^= 1UL << b;

	return old;
}

/**
 * bitmap_set() - Set bit range in bitmap
 * @bitmap: bitmap to modify
 * @start: start of bits to modify
 * @bits: number of bits to modify
 *
 * Sets @bits number of bits in @bitmap starting at @start.
 */
static __inline__ void bitmap_set(unsigned long *bitmap, size_t start,
				  size_t bits)
{
	size_t i;
	size_t end = start + bits;
	size_t l = end / BITS_PER_LONG;
	unsigned long mask = BITMAP_FIRST_WORD_MASK(start);
	size_t mask_bits = BITS_PER_LONG - (start % BITS_PER_LONG);

	for (i = start / BITS_PER_LONG; i < l; i++) {
		bitmap[i] |= mask;
		bits -= mask_bits;

		mask = ~0UL;
		mask_bits = BITS_PER_LONG;
	}

	if (bits)
		bitmap[l] |= mask & BITMAP_LAST_WORD_MASK(end);
}

/**
 * bitmap_clear() - Clear bit range in bitmap
 * @bitmap: bitmap to modify
 * @start: start of bits to modify
 * @bits: number of bits to modify
 *
 * Clears @bits number of bits in @bitmap starting at @start.
 */
static __inline__ void bitmap_clear(unsigned long *bitmap, size_t start,
				    size_t bits)
{
	size_t i;
	size_t end = start + bits;
	size_t l = end / BITS_PER_LONG;
	unsigned long mask = BITMAP_FIRST_WORD_MASK(start);
	size_t mask_bits = BITS_PER_LONG - (start % BITS_PER_LONG);

	for (i = start / BITS_PER_LONG; i < l; i++) {
		bitmap[i] &= ~mask;
		bits -= mask_bits;

		mask = ~0UL;
		mask_bits = BITS_PER_LONG;
	}

	if (bits)
		bitmap[l] &= ~(mask & BITMAP_LAST_WORD_MASK(end));
}

/**
 * find_next_bit() - Find next set bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 * @start: start of bits to check
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of next set bit, @bits when no set bit was found
 */
static __inline__ size_t find_next_bit(const unsigned long *bitmap, size_t bits,
				       size_t start)
{
	size_t i;
	size_t pos;
	unsigned long t;
	size_t l = BITS_TO_LONGS(bits);
	size_t first_long = start / BITS_PER_LONG;
	size_t long_lower = start - (start % BITS_PER_LONG);

	if (start >= bits)
		return bits;

	t = bitmap[first_long] & BITMAP_FIRST_WORD_MASK(start);
	for (i = first_long + 1; !t && i < l; i++) {
		/* search until valid t is found */
		long_lower += BITS_PER_LONG;
		t = bitmap[i];
	}

	if (!t)
		return bits;

	pos = long_lower + bitops_ffs(t) - 1;
	if (pos >= bits)
		return bits;

	return pos;
}

/**
 * find_first_bit - Find first set bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of fist set bit, @bits when no set bit was found
 */
#define find_first_bit(bitmap, bits) find_next_bit(bitmap, bits, 0)

/**
 * for_each_set_bit - iterate over set bits in bitmap
 * @bit: current bit
 * @bitmap: bitmap to iterate over
 * @bits: number of bits in @bitmap
 *
 * WARNING expressions @bitmap and @bits must be side-effect free
 */
#define for_each_set_bit(bit, bitmap, bits) \
	for (bit = find_first_bit(bitmap, bits); \
	     bit < (bits); \
	     bit = find_next_bit(bitmap, bits, bit + 1))

/**
 * find_next_zero_bit() - Find next clear bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 * @start: start of bits to check
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of next clear bit, @bits when no clear bit was found
 */
static __inline__ size_t find_next_zero_bit(const unsigned long *bitmap,
					    size_t bits, size_t start)
{
	size_t i;
	size_t pos;
	unsigned long t;
	size_t l = BITS_TO_LONGS(bits);
	size_t first_long = start / BITS_PER_LONG;
	size_t long_lower = start - (start % BITS_PER_LONG);

	if (start >= bits)
		return bits;

	t = bitmap[first_long] | ~BITMAP_FIRST_WORD_MASK(start);
	t ^= ~0UL;

	for (i = first_long + 1; !t && i < l; i++) {
		/* search until valid t is found */
		long_lower += BITS_PER_LONG;
		t = bitmap[i];
		t ^= ~0UL;
	}

	if (!t)
		return bits;

	pos = long_lower + bitops_ffs(t) - 1;
	if (pos >= bits)
		return bits;

	return pos;
}

/**
 * find_first_zero_bit - Find first clear bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of fist clear bit, @bits when no clear bit was found
 */
#define find_first_zero_bit(bitmap, bits) find_next_zero_bit(bitmap, bits, 0)

/**
 * for_each_clear_bit - iterate over clear bits in bitmap
 * @bit: current bit
 * @bitmap: bitmap to iterate over
 * @bits: number of bits in @bitmap
 *
 * WARNING expressions @bitmap and @bits must be side-effect free
 */
#define for_each_clear_bit(bit, bitmap, bits) \
	for (bit = find_first_zero_bit(bitmap, bits); \
	     bit < (bits); \
	     bit = find_next_zero_bit(bitmap, bits, bit + 1))

/**
 * bitmap_weight() - Calculate number of set bits in bitmap
 * @bitmap: bitmap to sum up
 * @bits: number of bits
 *
 * Sums the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not summed up
 *
 * Return: number of set bits
 */
static __inline__ size_t bitmap_weight(const unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;
	size_t sum = 0;

	for (i = 0; i < l - 1; i++)
		sum += hweight_long(bitmap[i]);

	return sum + hweight_long(bitmap[l - 1] & BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_equal() - Compare usable bits of two bitmaps
 * @bitmap1: bitmap to compare
 * @bitmap2: bitmap to compare
 * @bits: number of bits
 *
 * Compares the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be compared
 *
 * Return: true when usable bits were equal and false otherwise
 */
static __inline__ bool bitmap_equal(const unsigned long *bitmap1,
				    const unsigned long *bitmap2, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);

	if (l > 1 &&
	    memcmp(bitmap1, bitmap2, (l - 1) * sizeof(unsigned long)) != 0)
		return false;

	return !((bitmap1[l - 1] ^ bitmap2[l - 1]) &
		 BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_intersects() - Check for common set bits in two bitmaps
 * @bitmap1: bitmap to compare
 * @bitmap2: bitmap to compare
 * @bits: number of bits
 *
 * Compares the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be compared
 *
 * Return: true when at least one bit is set in both bitmaps and false otherwise
 */
static __inline__ bool bitmap_intersects(const unsigned long *bitmap1,
					 const unsigned long *bitmap2,
					 size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++) {
		if (bitmap1[i] & bitmap2[i])
			return true;
	}

	return !!(bitmap1[l - 1] & bitmap2[l - 1] &
		  BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_subset() - Check bitmaps for subset/superset relationship
 * @subset: potential subset bitmap
 * @superset: potential superset bitmap
 * @bits: number of bits
 *
 * Compares the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be compared
 *
 * Return: true when all set bits in @subset are also in @superset and false
 *  otherwise
 */
static __inline__ bool bitmap_subset(const unsigned long *subset,
				     const unsigned long *superset,
				     size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++) {
		if (subset[i] & ~superset[i])
			return false;
	}

	return !(subset[l - 1] & ~superset[l - 1] &
		 BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_empty() - Check if no bit is set in bitmap
 * @bitmap: bitmap to test
 * @bits: number of bits
 *
 * Check the modifiable bits in the bitmap for zero. The overhead bits in the
 * last unsigned long will not be checked
 *
 * Return: true when usable bits were all zero and false otherwise
 */
static __inline__ bool bitmap_empty(const unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++) {
		if (bitmap[i])
			return false;
	}

	return !(bitmap[l - 1] & BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_full() - Check if all bits are set in bitmap
 * @bitmap: bitmap to test
 * @bits: number of bits
 *
 * Check the modifiable bits in the bitmap for one. The overhead bits in the
 * last unsigned long will not be checked
 *
 * Return: true when usable bits were all one and false otherwise
 */
static __inline__ bool bitmap_full(const unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++) {
		if (~bitmap[i])
			return false;
	}

	return !(~bitmap[l - 1] & BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_copy() - Copy bits from one bitmap to another
 * @bitmap: bitmap to modify
 * @src: source bitmap
 * @bits: number of bits
 */
static __inline__ void bitmap_copy(unsigned long *bitmap,
				   const unsigned long *src, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);

	memcpy(bitmap, src, l * sizeof(unsigned long));
}

/**
 * bitmap_or() - Combines bits of two bitmaps using bitwise "or"
 * @bitmap: bitmap to modify
 * @src1: source bitmap 1
 * @src2: source bitmap 2
 * @bits: number of bits
 */
static __inline__ void bitmap_or(unsigned long *bitmap,
				 const unsigned long *src1,
				 const unsigned long *src2, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l; i++)
		bitmap[i] = src1[i] | src2[i];
}

/**
 * bitmap_and() - Combines bits of two bitmaps using bitwise "and"
 * @bitmap: bitmap to modify
 * @src1: source bitmap 1
 * @src2: source bitmap 2
 * @bits: number of bits
 */
static __inline__ void bitmap_and(unsigned long *bitmap,
				  const unsigned long *src1,
				  const unsigned long *src2, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l; i++)
		bitmap[i] = src1[i] & src2[i];
}

/**
 * bitmap_andnot() - Combines bits of two bitmaps using bitwise "andnot"
 * @bitmap: bitmap to modify
 * @src1: source bitmap 1
 * @src2: source bitmap 2
 * @bits: number of bits
 */
static __inline__ void bitmap_andnot(unsigned long *bitmap,
				     const unsigned long *src1,
				     const unsigned long *src2, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++)
		bitmap[i] = src1[i] & ~src2[i];

	bitmap[i] = (src1[i] & ~src2[i]) & BITMAP_LAST_WORD_MASK(bits);
}

/**
 * bitmap_xor() - Combines bits of two bitmaps using bitwise "xor"
 * @bitmap: bitmap to modify
 * @src1: source bitmap 1
 * @src2: source bitmap 2
 * @bits: number of bits
 */
static __inline__ void bitmap_xor(unsigned long *bitmap,
				  const unsigned long *src1,
				  const unsigned long *src2, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l; i++)
		bitmap[i] = src1[i] ^ src2[i];
}

/**
 * bitmap_complement() - Return complement bitmap using bitwise "not"
 * @bitmap: bitmap to modify
 * @src: source bitmap
 * @bits: number of bits
 */
static __inline__ void bitmap_complement(unsigned long *bitmap,
					 const unsigned long *src, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++)
		bitmap[i] = ~src[i];

	bitmap[i] = ~src[l - 1] & BITMAP_LAST_WORD_MASK(bits);
}

/**
 * bitmap_shift_right() - Shift bits of bitmap from msb towards lsb
 * @bitmap: bitmap to modify
 * @src: source bitmap
 * @n: number of bits to shift
 * @bits: number of bits
 *
 * Only the modifiable bits in the bitmap will be shifted. The overhead bits in
 * the last unsigned long will not be used. @n bits from msb onwards will
 * be set to 0.
 */
static __inline__ void bitmap_shift_right(unsigned long *bitmap,
					  const unsigned long *src, size_t n,
					  size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t n_bytes = n / BITS_PER_LONG;
	size_t n_bits = n % BITS_PER_LONG;
	size_t i;
	size_t src_i;
	unsigned long high;
	unsigned long low;

	if (n > bits) {
		bitmap_zero(bitmap, bits);
		return;
	}

	if (!n_bits) {
		for (i = 0, src_i = n_bytes; i + n_bytes < l - 1; i++, src_i++)
			bitmap[i] = src[src_i];

		i = l - 1 - n_bytes;
		src_i = l - 1;
		bitmap[i] = src[src_i] & BITMAP_LAST_WORD_MASK(bits);
	} else {
		for (i = 0, src_i = n_bytes; src_i < l - 1; i++, src_i++) {
			low = src[src_i];
			high = src[src_i + 1];
			if (src_i + 1 == l - 1)
				high &= BITMAP_LAST_WORD_MASK(bits);

			high <<= BITS_PER_LONG - n_bits;
			low >>= n_bits;

			bitmap[i] = high | low;
		}

		low = src[l - 1] & BITMAP_LAST_WORD_MASK(bits);
		bitmap[l - n_bytes - 1] = low >> n_bits;
	}

	if (!n_bytes)
		return;

	memset(&bitmap[l - n_bytes], 0, n_bytes * sizeof(unsigned long));
}

/**
 * bitmap_shift_left() - Shift bits of bitmap from lsb towards msb
 * @bitmap: bitmap to modify
 * @src: source bitmap
 * @n: number of bits to shift
 * @bits: number of bits
 *
 * Only the modifiable bits in the bitmap will be shifted. The overhead bits in
 * the last unsigned long will not be used. @n bits from lsb onwards will
 * be set to 0.
 */
static __inline__ void bitmap_shift_left(unsigned long *bitmap,
					 const unsigned long *src, size_t n,
					 size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t n_bytes = n / BITS_PER_LONG;
	size_t n_bits = n % BITS_PER_LONG;
	size_t i;
	unsigned long high;
	unsigned long low;

	if (n >= bits) {
		bitmap_zero(bitmap, bits);
		return;
	}

	if (!n_bits) {
		for (i = l - n_bytes - 1; i > 0; i--) {
			high = src[i];
			if (i == l - 1)
				high &= BITMAP_LAST_WORD_MASK(bits);

			bitmap[i + n_bytes] = high;
		}

		/* least significant long */
		high = src[0];
		if (l - 1 == 0)
			high &= BITMAP_LAST_WORD_MASK(bits);

		bitmap[n_bytes] = high;
	} else {
		for (i = l - n_bytes - 1; i > 0; i--) {
			low = src[i - 1];
			high = src[i];
			if (i == l - 1)
				high &= BITMAP_LAST_WORD_MASK(bits);

			high <<= n_bits;
			low >>= BITS_PER_LONG - n_bits;

			bitmap[i + n_bytes] = high | low;
		}

		/* least significant long */
		high = src[0];
		if (l - 1 == 0)
			high &= BITMAP_LAST_WORD_MASK(bits);

		bitmap[n_bytes] = high << n_bits;
	}

	if (!n_bytes)
		return;

	memset(bitmap, 0, n_bytes * sizeof(unsigned long));
}


#endif /* __LINUX_LIKE_BITOPS_H__ */
