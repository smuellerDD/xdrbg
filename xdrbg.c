/*
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static inline size_t min_size(size_t a, size_t b)
{
	return a < b ? a : b;
}

static inline uint64_t rol(uint64_t x, int n)
{
	return ((x << (n & (64 - 1))) | (x >> ((64 - n) & (64 - 1))));
}

static inline void memset_secure(void *s, int c, size_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}

/*********************************** Keccak ***********************************/
/* state[x + y*5] */
#define A(x, y) (x + 5 * y)
#define RHO_ROL(t) (((t + 1) * (t + 2) / 2) % 64)

static inline void keccakp_theta_rho_pi(uint64_t s[25])
{
	uint64_t C[5], D[5], t;

	/* Steps 1 + 2 */
	C[0] = s[A(0, 0)] ^ s[A(0, 1)] ^ s[A(0, 2)] ^ s[A(0, 3)] ^ s[A(0, 4)];
	C[1] = s[A(1, 0)] ^ s[A(1, 1)] ^ s[A(1, 2)] ^ s[A(1, 3)] ^ s[A(1, 4)];
	C[2] = s[A(2, 0)] ^ s[A(2, 1)] ^ s[A(2, 2)] ^ s[A(2, 3)] ^ s[A(2, 4)];
	C[3] = s[A(3, 0)] ^ s[A(3, 1)] ^ s[A(3, 2)] ^ s[A(3, 3)] ^ s[A(3, 4)];
	C[4] = s[A(4, 0)] ^ s[A(4, 1)] ^ s[A(4, 2)] ^ s[A(4, 3)] ^ s[A(4, 4)];

	D[0] = C[4] ^ rol(C[1], 1);
	D[1] = C[0] ^ rol(C[2], 1);
	D[2] = C[1] ^ rol(C[3], 1);
	D[3] = C[2] ^ rol(C[4], 1);
	D[4] = C[3] ^ rol(C[0], 1);

	/* Step 3 theta and rho and pi */
	s[A(0, 0)] ^= D[0];
	t = rol(s[A(4, 4)] ^ D[4], RHO_ROL(11));
	s[A(4, 4)] = rol(s[A(1, 4)] ^ D[1], RHO_ROL(10));
	s[A(1, 4)] = rol(s[A(3, 1)] ^ D[3], RHO_ROL(9));
	s[A(3, 1)] = rol(s[A(1, 3)] ^ D[1], RHO_ROL(8));
	s[A(1, 3)] = rol(s[A(0, 1)] ^ D[0], RHO_ROL(7));
	s[A(0, 1)] = rol(s[A(3, 0)] ^ D[3], RHO_ROL(6));
	s[A(3, 0)] = rol(s[A(3, 3)] ^ D[3], RHO_ROL(5));
	s[A(3, 3)] = rol(s[A(2, 3)] ^ D[2], RHO_ROL(4));
	s[A(2, 3)] = rol(s[A(1, 2)] ^ D[1], RHO_ROL(3));
	s[A(1, 2)] = rol(s[A(2, 1)] ^ D[2], RHO_ROL(2));
	s[A(2, 1)] = rol(s[A(0, 2)] ^ D[0], RHO_ROL(1));
	s[A(0, 2)] = rol(s[A(1, 0)] ^ D[1], RHO_ROL(0));
	s[A(1, 0)] = rol(s[A(1, 1)] ^ D[1], RHO_ROL(23));
	s[A(1, 1)] = rol(s[A(4, 1)] ^ D[4], RHO_ROL(22));
	s[A(4, 1)] = rol(s[A(2, 4)] ^ D[2], RHO_ROL(21));
	s[A(2, 4)] = rol(s[A(4, 2)] ^ D[4], RHO_ROL(20));
	s[A(4, 2)] = rol(s[A(0, 4)] ^ D[0], RHO_ROL(19));
	s[A(0, 4)] = rol(s[A(2, 0)] ^ D[2], RHO_ROL(18));
	s[A(2, 0)] = rol(s[A(2, 2)] ^ D[2], RHO_ROL(17));
	s[A(2, 2)] = rol(s[A(3, 2)] ^ D[3], RHO_ROL(16));
	s[A(3, 2)] = rol(s[A(4, 3)] ^ D[4], RHO_ROL(15));
	s[A(4, 3)] = rol(s[A(3, 4)] ^ D[3], RHO_ROL(14));
	s[A(3, 4)] = rol(s[A(0, 3)] ^ D[0], RHO_ROL(13));
	s[A(0, 3)] = rol(s[A(4, 0)] ^ D[4], RHO_ROL(12));
	s[A(4, 0)] = t;
}

static const uint64_t keccakp_iota_vals[] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline void keccakp_chi_iota(uint64_t s[25], unsigned int round)
{
	uint64_t t0[5], t1[5];

	t0[0] = s[A(0, 0)];
	t0[1] = s[A(0, 1)];
	t0[2] = s[A(0, 2)];
	t0[3] = s[A(0, 3)];
	t0[4] = s[A(0, 4)];

	t1[0] = s[A(1, 0)];
	t1[1] = s[A(1, 1)];
	t1[2] = s[A(1, 2)];
	t1[3] = s[A(1, 3)];
	t1[4] = s[A(1, 4)];

	s[A(0, 0)] ^= ~s[A(1, 0)] & s[A(2, 0)];
	s[A(0, 0)] ^= keccakp_iota_vals[round];
	s[A(0, 1)] ^= ~s[A(1, 1)] & s[A(2, 1)];
	s[A(0, 2)] ^= ~s[A(1, 2)] & s[A(2, 2)];
	s[A(0, 3)] ^= ~s[A(1, 3)] & s[A(2, 3)];
	s[A(0, 4)] ^= ~s[A(1, 4)] & s[A(2, 4)];

	s[A(1, 0)] ^= ~s[A(2, 0)] & s[A(3, 0)];
	s[A(1, 1)] ^= ~s[A(2, 1)] & s[A(3, 1)];
	s[A(1, 2)] ^= ~s[A(2, 2)] & s[A(3, 2)];
	s[A(1, 3)] ^= ~s[A(2, 3)] & s[A(3, 3)];
	s[A(1, 4)] ^= ~s[A(2, 4)] & s[A(3, 4)];

	s[A(2, 0)] ^= ~s[A(3, 0)] & s[A(4, 0)];
	s[A(2, 1)] ^= ~s[A(3, 1)] & s[A(4, 1)];
	s[A(2, 2)] ^= ~s[A(3, 2)] & s[A(4, 2)];
	s[A(2, 3)] ^= ~s[A(3, 3)] & s[A(4, 3)];
	s[A(2, 4)] ^= ~s[A(3, 4)] & s[A(4, 4)];

	s[A(3, 0)] ^= ~s[A(4, 0)] & t0[0];
	s[A(3, 1)] ^= ~s[A(4, 1)] & t0[1];
	s[A(3, 2)] ^= ~s[A(4, 2)] & t0[2];
	s[A(3, 3)] ^= ~s[A(4, 3)] & t0[3];
	s[A(3, 4)] ^= ~s[A(4, 4)] & t0[4];

	s[A(4, 0)] ^= ~t0[0] & t1[0];
	s[A(4, 1)] ^= ~t0[1] & t1[1];
	s[A(4, 2)] ^= ~t0[2] & t1[2];
	s[A(4, 3)] ^= ~t0[3] & t1[3];
	s[A(4, 4)] ^= ~t0[4] & t1[4];
}

static inline void keccakp_1600(uint64_t s[25])
{
	unsigned int round;

	for (round = 0; round < 24; round++) {
		keccakp_theta_rho_pi(s);
		keccakp_chi_iota(s, round);
	}
}

/******************************** SHA / SHAKE *********************************/

#define LC_SHA3_SIZE_BLOCK(bits) ((1600 - 2 * bits) >> 3)
#define LC_SHA3_STATE_WORDS 25

#define LC_SHA3_256_SIZE_DIGEST_BITS 256
#define LC_SHA3_256_SIZE_DIGEST (LC_SHA3_256_SIZE_DIGEST_BITS >> 3)
#define LC_SHA3_256_SIZE_BLOCK LC_SHA3_SIZE_BLOCK(LC_SHA3_256_SIZE_DIGEST_BITS)

struct lc_sha3_256_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	size_t offset;
	unsigned int r;
	unsigned int rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;

	/* Variable size */
	uint8_t partial[LC_SHA3_256_SIZE_BLOCK];
};

static inline void sha3_ctx_init(void *_state)
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_256_state *ctx = _state;
	unsigned int i;

	/*
	 * Zeroize the actual state which is required by some implementations
	 * like ARM-CE.
	 */
	for (i = 0; i < LC_SHA3_STATE_WORDS; i++)
		ctx->state[i] = 0;

	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
	ctx->offset = 0;
}

static inline void sha3_state_init(uint64_t state[LC_SHA3_STATE_WORDS])
{
	unsigned int i;

	for (i = 0; i < LC_SHA3_STATE_WORDS; i++)
		state[i] = 0;
}

static void shake_256_init_common(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x1f;
}

static void shake_256_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	shake_256_init_common(_state);
	sha3_state_init(ctx->state);
}

#define LC_SHAKE_256_SIZE_DIGEST_BITS 256
#define LC_SHAKE_256_SIZE_BLOCK                                                \
	LC_SHA3_SIZE_BLOCK(LC_SHAKE_256_SIZE_DIGEST_BITS)

#define _lc_swap64(x) (uint64_t) __builtin_bswap64((uint64_t)(x))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define le_bswap64(x) _lc_swap64(x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define le_bswap64(x) ((uint64_t)(x))
#else
#error "Endianess not defined"
#endif

static inline uint32_t ptr_to_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static inline uint64_t ptr_to_le64(const uint8_t *p)
{
	return (uint64_t)ptr_to_le32(p) | (uint64_t)ptr_to_le32(p + 4) << 32;
}

static inline void le32_to_ptr(uint8_t *p, const uint32_t value)
{
	p[0] = (uint8_t)(value);
	p[1] = (uint8_t)(value >> 8);
	p[2] = (uint8_t)(value >> 16);
	p[3] = (uint8_t)(value >> 24);
}

static inline void le64_to_ptr(uint8_t *p, const uint64_t value)
{
	le32_to_ptr(p + 4, (uint32_t)(value >> 32));
	le32_to_ptr(p, (uint32_t)(value));
}

static void shake_set_digestsize(struct lc_sha3_256_state *ctx,
				 size_t digestsize)
{
	ctx->digestsize = digestsize;
}

/*
 * All lc_sha3_*_state are equal except for the last entry, thus we use
 * the largest state.
 */
static inline void sha3_fill_state(struct lc_sha3_256_state *ctx,
				   const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= ptr_to_le64(in);
		in += 8;
	}
}

static inline int sha3_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void sha3_fill_state_aligned(struct lc_sha3_256_state *ctx,
					   const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= le_bswap64(*in);
		in++;
	}
}

static void keccak_absorb(struct lc_sha3_256_state *ctx, const uint8_t *in,
			  size_t inlen)
{
	size_t partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % ctx->r;
	ctx->squeeze_more = 0;
	ctx->msg_len += inlen;

	/* Sponge absorbing phase */

	/* Check if we have a partial block stored */
	if (partial) {
		size_t todo = ctx->r - partial;

		/*
		 * If the provided data is small enough to fit in the partial
		 * buffer, copy it and leave it unprocessed.
		 */
		if (inlen < todo) {
			memcpy(ctx->partial + partial, in, inlen);
			return;
		}

		/*
		 * The input data is large enough to fill the entire partial
		 * block buffer. Thus, we fill it and transform it.
		 */
		memcpy(ctx->partial + partial, in, todo);
		inlen -= todo;
		in += todo;

		sha3_fill_state(ctx, ctx->partial);
		keccakp_1600(ctx->state);
	}

	/* Perform a transformation of full block-size messages */
	if (sha3_aligned(in, sizeof(uint64_t) - 1)) {
		for (; inlen >= ctx->r; inlen -= ctx->r, in += ctx->r) {
			/*
			 * We can ignore the alignment warning as we checked
			 * for proper alignment.
			 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			sha3_fill_state_aligned(ctx, (uint64_t *)in);
#pragma GCC diagnostic pop
			keccakp_1600(ctx->state);
		}
	} else {
		for (; inlen >= ctx->r; inlen -= ctx->r, in += ctx->r) {
			sha3_fill_state(ctx, in);
			keccakp_1600(ctx->state);
		}
	}

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static void keccak_squeeze(struct lc_sha3_256_state *ctx, uint8_t *digest)
{
	size_t i, digest_len;
	uint32_t part;
	volatile uint32_t *part_p;

	if (!ctx || !digest)
		return;

	digest_len = ctx->digestsize;

	if (!ctx->squeeze_more) {
		size_t partial = ctx->msg_len % ctx->r;

		/* Final round in sponge absorbing phase */

		/* Fill the unused part of the partial buffer with zeros */
		memset(ctx->partial + partial, 0, ctx->r - partial);

		/* Add the padding bits and the 01 bits for the suffix. */
		ctx->partial[partial] = ctx->padding;
		ctx->partial[ctx->r - 1] |= 0x80;

		ctx->squeeze_more = 1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		sha3_fill_state_aligned(ctx, (uint64_t *)ctx->partial);
#pragma GCC diagnostic pop
	}

	while (digest_len) {
		size_t todo_64, todo_32;

		/* How much data can we squeeze considering current state? */
		size_t todo = ctx->r - ctx->offset;

		/* Limit the data to be squeezed by the requested amount. */
		todo = (digest_len > todo) ? todo : digest_len;

		digest_len -= todo;

		if (ctx->offset) {
			/*
			 * Access requests when squeezing more data that
			 * happens to be not aligned with the block size of
			 * the used SHAKE algorithm are processed byte-wise.
			 */
			size_t word, byte;

			for (i = ctx->offset; i < todo + ctx->offset;
			     i++, digest++) {
				word = i / sizeof(ctx->state[0]);
				byte = (i % sizeof(ctx->state[0])) << 3;

				*digest = (uint8_t)(ctx->state[word] >> byte);
			}

			/* Advance the offset */
			ctx->offset += todo;
			/* Wrap the offset at block size */
			ctx->offset %= ctx->r;
			continue;
		}

		/*
		 * Access to obtain blocks without offset are implemented
		 * with streamlined memory access.
		 */

		/* Generate new keccak block */
		keccakp_1600(ctx->state);

		/* Advance the offset */
		ctx->offset += todo;
		/* Wrap the offset at block size */
		ctx->offset %= ctx->r;

		/* How much 64-bit aligned data can we obtain? */
		todo_64 = todo >> 3;

		/* How much 32-bit aligned data can we obtain? */
		todo_32 = (todo - (todo_64 << 3)) >> 2;

		/* How much non-aligned do we have to obtain? */
		todo -= ((todo_64 << 3) + (todo_32 << 2));

		/* Sponge squeeze phase */

		/* 64-bit aligned request */
		for (i = 0; i < todo_64; i++, digest += 8)
			le64_to_ptr(digest, ctx->state[i]);

		if (todo_32) {
			/* 32-bit aligned request */
			le32_to_ptr(digest, (uint32_t)(ctx->state[i]));
			digest += 4;
			part = (uint32_t)(ctx->state[i] >> 32);
		} else {
			/* non-aligned request */
			part = (uint32_t)(ctx->state[i]);
		}

		for (i = 0; i < todo << 3; i += 8, digest++)
			*digest = (uint8_t)(part >> i);
	}

	/* Zeroization */
	part_p = &part;
	*part_p = 0;
}

/****************************** XDRBG Definitions *****************************/

#define LC_XDRBG256_DRNG_KEYSIZE 64

struct lc_xdrbg256_drng_state {
	uint8_t initially_seeded;
	uint8_t v[LC_XDRBG256_DRNG_KEYSIZE];
};

/* maxout as defined in XDRBG specification */
#define LC_XDRBG256_DRNG_MAX_CHUNK (LC_SHAKE_256_SIZE_BLOCK * 2)

/******************************** XDRBG Helper ********************************/

static inline void lc_xdrbg256_shake_final(struct lc_sha3_256_state *shake_ctx,
					   uint8_t *digest, size_t digest_len)
{
	shake_set_digestsize(shake_ctx, digest_len);
	keccak_squeeze(shake_ctx, digest);
}

/* Maximum size of the input data to calculate the encode value */
#define LC_XDRBG256_DRNG_ENCODE_LENGTH 84

/*
 * The encoding is based on the XDRBG paper appendix B.2 with the following
 * properties:
 *
 *   * length of the hash is set to be equal to |V|
 */
static void lc_xdrbg256_encode(struct lc_sha3_256_state *shake_ctx,
			       const uint8_t n,
			       const uint8_t *alpha, size_t alphalen)
{
	uint8_t encode;

	/*
	 * Only consider up to 84 left-most bytes of alpha. According to
	 * the XDRBG specification appendix B:
	 *
	 * """
	 * This encoding is efficient and flexible, but does require that the
	 * additional input string is no longer than 84 bytes–a constraint that
	 * seems very easy to manage in practice.
	 *
	 * For example, IPV6 addresses and GUIDs are 16 bytes long, Ethernet
	 * addresses are 12 bytes long, and the most demanding requirement for
	 * unique randomly-generated device identifiers can be met with a
	 * 32-byte random value. This is the encoding we recommend for XDRBG.
	 * """
	 */
	if (alphalen > 84)
		alphalen = 84;

	/* Encode the length. */
	encode = (uint8_t)((n * 85) + alphalen);

	/* Insert alpha and encode into the hash context. */
	keccak_absorb(shake_ctx, alpha, alphalen);
	keccak_absorb(shake_ctx, &encode, 1);

	/*
	 * Zeroization of encode is not considered to be necessary as alpha is
	 * considered to be known string.
	 */
}

/*
 * Fast-key-erasure initialization of the SHAKE context. The caller must
 * securely dispose of the initialized SHAKE context. Additional data
 * can be squeezed from the state using lc_hash_final.
 *
 * This function initializes the SHAKE context that can later be used to squeeze
 * random bits out of the SHAKE context. The initialization happens from the key
 * found in the state. Before any random bits can be created, the first 512
 * output bits that are generated is used to overwrite the key. This implies
 * an automatic backtracking resistance as the next round to generate random
 * numbers uses the already updated key.
 *
 * When this function completes, initialized SHAKE context can now be used
 * to generate random bits.
 */
static void lc_xdrbg256_drng_fke_init_ctx(struct lc_xdrbg256_drng_state *state,
					  struct lc_sha3_256_state *shake_ctx,
					  const uint8_t *alpha, size_t alphalen)
{
	shake_256_init(shake_ctx);

	/* Insert V' into the SHAKE */
	keccak_absorb(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

	/* Insert alpha into the SHAKE state together with its encoding. */
	lc_xdrbg256_encode(shake_ctx, 2, alpha, alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	lc_xdrbg256_shake_final(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);
}

/********************************** XDRB256 ***********************************/

/*
 * Generating random bits is performed by initializing a transient SHAKE state
 * with the key found in state. The initialization implies that the key in
 * the state variable is already updated before random bits are generated.
 *
 * The random bits are generated by performing a SHAKE final operation. The
 * generation operation is chunked to ensure that the fast-key-erasure updates
 * the key when large quantities of random bits are generated.
 *
 * This function implements the following functions from Algorithm 2  of the
 * XDRBG specification:
 *
 *   * GENERATE
 */
static int lc_xdrbg256_drng_generate(struct lc_xdrbg256_drng_state *state,
				     const uint8_t *alpha,
				     size_t alphalen, uint8_t *out,
				     size_t outlen)
{
	struct lc_sha3_256_state shake_ctx = { 0 };

	if (!state)
		return -EINVAL;

	while (outlen) {
		size_t todo = min_size(outlen, LC_XDRBG256_DRNG_MAX_CHUNK);

		/*
		 * Instantiate SHAKE with V', and alpha with its encoding,
		 * and generate V.
		 */
		lc_xdrbg256_drng_fke_init_ctx(state, &shake_ctx, alpha,
					      alphalen);

		/* Generate the requested amount of output bits */
		lc_xdrbg256_shake_final(&shake_ctx, out, todo);

		out += todo;
		outlen -= todo;
	}

	/* V is already in place. */

	/* Clear the SHAKE state which is not needed any more. */
	memset_secure(&shake_ctx, 0, sizeof(shake_ctx));

	return 0;
}

/*
 * The DRNG is seeded by initializing a fast-key-erasure SHAKE context and add
 * the key into the SHAKE state. The SHAKE final operation replaces the key in
 * state.
 *
 * This function implements the following functions from Algorithm 2 of the
 * XDRBG specification:
 *
 *  * INSTANTIATE: The state is empty (either freshly allocated or zeroized with
 *                 lc_xdrbg256_drng_zero). In particular state->initially_seeded
 *                 is 0.
 *
 *  * RESEED: The state contains a working XDRBG state that was seeded before.
 *            In this case, state->initially_seeded is 1.
 */
static int lc_xdrbg256_drng_seed(struct lc_xdrbg256_drng_state *state,
				 const uint8_t *seed,
				 size_t seedlen, const uint8_t *alpha,
				 size_t alphalen)
{
	uint8_t intially_seeded = state->initially_seeded;
	struct lc_sha3_256_state shake_ctx = { 0 };

	if (!state)
		return -EINVAL;

	shake_256_init(&shake_ctx);

	/*
	 * During reseeding, insert V' into the SHAKE state. During initial
	 * seeding, V' does not yet exist and thus is not considered.
	 */
	if (intially_seeded)
		keccak_absorb(&shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);
	else
		state->initially_seeded = 1;

	/* Insert the seed data into the SHAKE state. */
	keccak_absorb(&shake_ctx, seed, seedlen);

	/* Insert alpha into the SHAKE state together with its encoding. */
	lc_xdrbg256_encode(&shake_ctx, intially_seeded, alpha, alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	lc_xdrbg256_shake_final(&shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

	/* Clear the SHAKE state which is not needed any more. */
	memset_secure(&shake_ctx, 0, sizeof(shake_ctx));

	return 0;
}

/********************************* Test Code **********************************/

static int lc_compare(const uint8_t *act, const uint8_t *exp,
		      const size_t len, const char *info)
{
	if (memcmp(act, exp, len)) {
		unsigned int i;

		printf("Expected %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(exp + i));

		printf("\n");

		printf("Actual %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(act + i));

		printf("\n");

		return 1;
	}

	return 0;
}

static int xdrbg256_drng_selftest(struct lc_xdrbg256_drng_state *xdrbg256_ctx)
{
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0, 0x79, 0x2c,
		0xc0, 0x69, 0x7d, 0x56, 0x6a, 0x65, 0xb8, 0x36, 0xbe, 0x7d,
		0x09, 0x12, 0x7c, 0x65, 0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24,
		0x39, 0x52, 0x29, 0xea, 0xce, 0x43, 0xdf, 0x16, 0x2c, 0x4f,
		0x1a, 0xed, 0xbd, 0x3f, 0xf5, 0x8e, 0xe6, 0x4d, 0x93, 0x07,
		0x3d, 0x7f, 0x3d, 0xd2, 0x50, 0x3c, 0xae, 0x04, 0x4a, 0x87,
		0x2c, 0x90, 0x30, 0xd4, 0x8e, 0xef, 0x5d, 0x53, 0x0f, 0xb2,
		0xdb, 0xec, 0x16, 0x39, 0x5a, 0xb5, 0x9a, 0xdc, 0x9d, 0x01,
		0x7e, 0xe2, 0xac, 0x7c, 0xe4, 0x3d, 0xfd, 0x93, 0xa6, 0x6c,
		0xc1, 0x22, 0x26, 0x64, 0xa0, 0x43, 0x52, 0x51, 0xf9, 0xb5,
		0xa4, 0x91, 0x54, 0x08, 0xf8, 0x8f, 0x16, 0x85, 0x54, 0xc0,
		0x9d, 0xce, 0xc9, 0xd5, 0xd7, 0xa9, 0x51, 0xc0, 0x06, 0x0c,
		0x04, 0x95, 0xcf, 0x7d, 0x27, 0x00, 0x7e, 0x48, 0x6d, 0x2e,
		0xbc, 0xf8, 0xa3, 0x71, 0x3d, 0xb0, 0x2b, 0x75, 0x2a, 0x48,
		0x1a, 0xd3, 0xed, 0xc9, 0xa3, 0x80, 0x88, 0x03, 0xc0, 0x27,
		0x75, 0xcc, 0xf5, 0xda, 0x56, 0x8d, 0x83, 0x36, 0xe6, 0x90,
		0x9c, 0xd5, 0x82, 0xfa, 0x70, 0xe9, 0xbf, 0x61, 0xec, 0x97,
		0xcc, 0xdd, 0xdc, 0x4e, 0xe1, 0x64, 0x9f, 0x1e, 0xb3, 0xfa,
		0x97, 0xa7, 0x02, 0x0a, 0x28, 0x01, 0x19, 0xd0, 0x45, 0xe9,
		0x21, 0x74, 0x52, 0x1a, 0xac, 0x5f, 0x58, 0x7c, 0x02, 0x47,
		0x45, 0x06, 0x17, 0x71, 0xc5, 0x2b, 0x0f, 0xa9, 0xed, 0x5c,
		0xd1, 0x46, 0x63, 0x57, 0xb5, 0x6a, 0x5c, 0x95, 0xd1, 0xa4,
		0xdf, 0x61, 0x62, 0x39, 0x41, 0x47, 0xb1, 0x4e, 0x91, 0x7c,
		0x50, 0x1f, 0xc0, 0x48, 0x42, 0xb6, 0xea, 0x16, 0x4c, 0x50,
		0x29, 0x12, 0xd0, 0x1c, 0x39, 0x9f, 0x79,
	};
	static const uint8_t exp83[] = {
		0x39, 0x2b, 0x18, 0x96, 0x45, 0x81, 0x86, 0x84, 0xcf
	};
	static const uint8_t exp84[] = {
		0xf0, 0x85, 0xd6, 0xc8, 0xd1, 0x76, 0xd7, 0x12, 0x39
	};
	uint8_t act1[sizeof(exp1)];
	uint8_t act2[sizeof(exp83)];
	uint8_t compare1[LC_XDRBG256_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	struct lc_sha3_256_state xdrbg256_compare = { 0 };

	/* Check the XDRBG operation */
	lc_xdrbg256_drng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_xdrbg256_drng_generate(xdrbg256_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "XDRBG");
	memset(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	lc_xdrbg256_drng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	/* Prepare the state with native SHAKE operations */
	shake_256_init(&xdrbg256_compare);
	keccak_absorb(&xdrbg256_compare, seed, sizeof(seed));
	encode = 0;
	keccak_absorb(&xdrbg256_compare, &encode, sizeof(encode));
	shake_set_digestsize(&xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	keccak_squeeze(&xdrbg256_compare, compare1);
	ret += lc_compare(compare1, xdrbg256_ctx->v, LC_XDRBG256_DRNG_KEYSIZE,
			  "SHAKE DRNG state generation");

	/* Verify the generate operation */
	shake_256_init(&xdrbg256_compare);
	/* Use the already generated state from above */
	keccak_absorb(&xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	encode = 2 * 85;
	keccak_absorb(&xdrbg256_compare, &encode, sizeof(encode));
	shake_set_digestsize(&xdrbg256_compare, sizeof(compare1));
	keccak_squeeze(&xdrbg256_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG256_DRNG_KEYSIZE, exp1,
			  sizeof(exp1), "SHAKE DRNG verification");

	memset_secure(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));

	/*
	 * Verify the generate operation with additional information of 83
	 * bytes.
	 */
	lc_xdrbg256_drng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_xdrbg256_drng_generate(xdrbg256_ctx, exp1, 83, act2, sizeof(act2));
	ret += lc_compare(act2, exp83, sizeof(act2),
			  "SHAKE DRNG with alpha 83 bytes");
	memset(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));

	/*
	 * Verify the generate operation with additional information of 84
	 * bytes.
	 */
	lc_xdrbg256_drng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_xdrbg256_drng_generate(xdrbg256_ctx, exp1, 84, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 84 bytes");
	memset(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));

	/*
	 * Verify the generate operation with additional information of 85
	 * bytes to be identical to 84 bytes due to the truncation of the
	 * additional data.
	 */
	lc_xdrbg256_drng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_xdrbg256_drng_generate(xdrbg256_ctx, exp1, 85, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 85 bytes");
	memset(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));

	/* Verify the generate operation with additional data */
	shake_256_init(&xdrbg256_compare);

	/* Verify: Seeding operation of the DRBG */
	keccak_absorb(&xdrbg256_compare, seed, sizeof(seed));
	encode = 0;
	keccak_absorb(&xdrbg256_compare, &encode, sizeof(encode));

	/* Verify: Now get the key for the next operation */
	shake_set_digestsize(&xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	keccak_squeeze(&xdrbg256_compare, compare1);

	shake_256_init(&xdrbg256_compare);
	/* Verify: Generate operation of the DRBG: Insert key */
	keccak_absorb(&xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	/* Verify: Generate operation of the DRBG: Insert alpha of 84 bytes */
	keccak_absorb(&xdrbg256_compare, exp1, 84);

	encode = 2 * 85 + 84;
	/* Verify: Generate operation of the DRBG: n */
	keccak_absorb(&xdrbg256_compare, &encode, sizeof(encode));

	/* Verify: Generate operation of the DRBG: generate data */
	shake_set_digestsize(&xdrbg256_compare,
			     LC_XDRBG256_DRNG_KEYSIZE + sizeof(act2));
	keccak_squeeze(&xdrbg256_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG256_DRNG_KEYSIZE, exp84,
			  sizeof(exp84),
			  "SHAKE DRNG with alpha 84 bytes verification");

	memset(xdrbg256_ctx, 0, sizeof(*xdrbg256_ctx));
	memset_secure(&xdrbg256_compare, 0, sizeof(xdrbg256_compare));

	return ret;
}

static int xdrbg256_drng_test(void)
{
	struct lc_xdrbg256_drng_state xdrbg256_ctx = { 0 };

	return xdrbg256_drng_selftest(&xdrbg256_ctx);
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = xdrbg256_drng_test();

	printf("XDRBG testing conducted %s\n", ret ? "with failures" :
						     "successfully");

	return ret;
}
