enum ModeFunction {
	Benchmark, ZeroBytes, Matching, Leading, Range, Mirror, Doubles, LeadingRange, LeadingAny
};

typedef struct {
	enum ModeFunction function;
	uchar data1[20];
	uchar data2[20];
} mode;

#define MATCH_QUEUE_SIZE 65536

typedef struct {
	uchar score;
	uchar padding[3];
	uchar salt[32];
	uchar hash[20];
	uchar padding2[8];
} match_entry;

#ifndef ERADICATE2_INITHASH
#define ERADICATE2_INITHASH 0
#endif

// Numeric values of enum ModeFunction, needed because the preprocessor can't see enums.
#define MODE_BENCHMARK 0
#define MODE_ZEROBYTES 1
#define MODE_MATCHING 2
#define MODE_LEADING 3
#define MODE_RANGE 4
#define MODE_MIRROR 5
#define MODE_DOUBLES 6
#define MODE_LEADINGRANGE 7
#define MODE_LEADINGANY 8

#ifndef ERADICATE2_MODE
#define ERADICATE2_MODE MODE_BENCHMARK
#endif

// The address is kept as three big-endian words (H0 = bytes 0..7, H1 = bytes 8..15,
// H2 = bytes 16..19) so that every scorer works on registers. All byte and nibble
// indices passed to these macros must be compile-time constants.
#define HBYTE(i) ((uint) (((i) < 8) ? (H0 >> (56 - 8 * (i))) : ((i) < 16) ? (H1 >> (56 - 8 * ((i) - 8))) : (ulong) (H2 >> (24 - 8 * ((i) - 16)))) & 0xFF)
#define NIB(j) ((uint) (((j) < 16) ? (H0 >> (60 - 4 * (j))) : ((j) < 32) ? (H1 >> (60 - 4 * ((j) - 16))) : (ulong) (H2 >> (28 - 4 * ((j) - 32)))) & 0xF)

static inline uint __attribute__((always_inline)) bswap32(const uint x) {
	return rotate(x & 0x00FF00FFu, 24u) | rotate(x & 0xFF00FF00u, 8u);
}

static inline uint __attribute__((always_inline)) nibbleMask(__constant const uchar * const flags) {
	uint mask = 0;
	#pragma unroll
	for (int i = 0; i < 16; ++i) {
		mask |= (flags[i] ? 1u : 0u) << i;
	}
	return mask;
}

static inline uint __attribute__((always_inline)) score_leading_pattern(const ulong H0, const ulong H1, const uint H2, const ulong pattern) {
	uint n = (uint) clz(H0 ^ pattern) >> 2;
	if (n < 16) {
		return n;
	}

	n = (uint) clz(H1 ^ pattern) >> 2;
	if (n < 16) {
		return 16 + n;
	}

	return 32 + ((uint) clz(H2 ^ (uint) pattern) >> 2);
}

static inline uint __attribute__((always_inline)) score_doubles(const ulong H0, const ulong H1, const uint H2) {
	uint n = (uint) clz((H0 ^ (H0 >> 4)) & 0x0F0F0F0F0F0F0F0FUL) >> 3;
	if (n < 8) {
		return n;
	}

	n = (uint) clz((H1 ^ (H1 >> 4)) & 0x0F0F0F0F0F0F0F0FUL) >> 3;
	if (n < 8) {
		return 8 + n;
	}

	return 16 + ((uint) clz((H2 ^ (H2 >> 4)) & 0x0F0F0F0Fu) >> 3);
}

static inline uint __attribute__((always_inline)) score_zerobytes(const ulong H0, const ulong H1, const uint H2) {
	uint score = 0;
	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		score += HBYTE(i) == 0;
	}
	return score;
}

static inline uint __attribute__((always_inline)) score_matching(const ulong H0, const ulong H1, const uint H2, __constant mode * restrict const pMode) {
	uint score = 0;
	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		const uchar mask = pMode->data1[i];
		const uchar val = pMode->data2[i];
		score += (mask && ((HBYTE(i) & mask) == val));
	}
	return score;
}

static inline uint __attribute__((always_inline)) score_range(const ulong H0, const ulong H1, const uint H2, const uint mask) {
	uint score = 0;
	#pragma unroll
	for (int j = 0; j < 40; ++j) {
		score += (mask >> NIB(j)) & 1;
	}
	return score;
}

static inline uint __attribute__((always_inline)) score_leadingrange(const ulong H0, const ulong H1, const uint H2, const uint mask) {
	uint score = 0;
	#pragma unroll
	for (int j = 0; j < 40; ++j) {
		if (!((mask >> NIB(j)) & 1)) {
			break;
		}
		++score;
	}
	return score;
}

static inline uint __attribute__((always_inline)) score_mirror(const ulong H0, const ulong H1, const uint H2) {
	uint score = 0;
	#pragma unroll
	for (int k = 0; k < 20; ++k) {
		if (NIB(19 - k) != NIB(20 + k)) {
			break;
		}
		++score;
	}
	return score;
}

static void eradicate2_report(const uint score, const ulong H0, const ulong H1, const uint H2, const uint deviceIndex, const uint round, const uchar thresholdScore, __global volatile uint * restrict const pBest, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches) {
	// Without a threshold only strict improvements over the device-wide best are queued.
	if (thresholdScore == 0) {
		if (score <= *pBest || atomic_max(pBest, score) >= score) {
			return;
		}
	}

	const uint matchIndex = atomic_inc(pMatchCount);
	if (matchIndex >= MATCH_QUEUE_SIZE) {
		return;
	}

	__global match_entry * const pEntry = pMatches + matchIndex;
	pEntry->score = (uchar) score;

	// Must mirror the salt increment in eradicate2_iterate exactly.
	const ulong init[25] = { ERADICATE2_INITHASH };
	const ulong w2 = init[2];
	const ulong w3 = init[3] + (ulong) deviceIndex + ((ulong) get_global_id(0) << 32);
	const ulong w4 = init[4] + (ulong) round;
	const ulong w5 = init[5];
	const ulong w6 = init[6];

	// Salt occupies bytes 21..52 of the first Keccak input.
	#pragma unroll
	for (int i = 0; i < 32; ++i) {
		const int b = 21 + i;
		const int w = b >> 3;
		const ulong word = (w == 2) ? w2 : (w == 3) ? w3 : (w == 4) ? w4 : (w == 5) ? w5 : w6;
		pEntry->salt[i] = (uchar) (word >> (8 * (b & 7)));
	}

	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		pEntry->hash[i] = (uchar) HBYTE(i);
	}
}

__kernel void eradicate2_iterate(__constant mode * restrict const pMode, const uchar scoreMin, const uint deviceIndex, const uint round, const uint roundsPerKernel, const uchar thresholdScore, __global volatile uint * restrict const pBest, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches) {
	const ulong gid = get_global_id(0);

#if ERADICATE2_MODE == MODE_LEADING
	const ulong pattern = (ulong) (pMode->data1[0] & 0xF) * 0x1111111111111111UL;
#elif ERADICATE2_MODE == MODE_RANGE || ERADICATE2_MODE == MODE_LEADINGRANGE
	const uint mask = nibbleMask(pMode->data2 + 1);
#endif

	for (uint iter = 0; iter < roundsPerKernel; ++iter) {
		const uint currentRound = round + iter;

		// keccak(0xff ++ deployer ++ salt ++ keccak(initcode)); padding is already in the init hash.
		ulong s[25] = { ERADICATE2_INITHASH };
		s[3] += (ulong) deviceIndex + (gid << 32);
		s[4] += (ulong) currentRound;
		keccakf(s);

		// keccak(rlp([address, 1])) = keccak(0xd6 0x94 ++ address ++ 0x01), with 0x01 Keccak padding.
		const ulong a1 = s[1];
		const ulong a2 = s[2];
		const ulong a3 = s[3];
		s[0] = 0x94D6UL | ((a1 >> 32) << 16) | (a2 << 48);
		s[1] = (a2 >> 16) | (a3 << 48);
		s[2] = (a3 >> 16) | 0x0101000000000000UL;
		#pragma unroll
		for (int i = 3; i < 25; ++i) {
			s[i] = 0;
		}
		s[16] = 0x8000000000000000UL;
		keccakf(s);

		const ulong H0 = ((ulong) bswap32((uint) (s[1] >> 32)) << 32) | bswap32((uint) s[2]);
		const ulong H1 = ((ulong) bswap32((uint) (s[2] >> 32)) << 32) | bswap32((uint) s[3]);
		const uint H2 = bswap32((uint) (s[3] >> 32));

#if ERADICATE2_MODE == MODE_LEADING
		const uint score = score_leading_pattern(H0, H1, H2, pattern);
#elif ERADICATE2_MODE == MODE_LEADINGANY
		const uint score = score_leading_pattern(H0, H1, H2, (H0 >> 60) * 0x1111111111111111UL);
#elif ERADICATE2_MODE == MODE_DOUBLES
		const uint score = score_doubles(H0, H1, H2);
#elif ERADICATE2_MODE == MODE_ZEROBYTES
		const uint score = score_zerobytes(H0, H1, H2);
#elif ERADICATE2_MODE == MODE_MATCHING
		const uint score = score_matching(H0, H1, H2, pMode);
#elif ERADICATE2_MODE == MODE_RANGE
		const uint score = score_range(H0, H1, H2, mask);
#elif ERADICATE2_MODE == MODE_LEADINGRANGE
		const uint score = score_leadingrange(H0, H1, H2, mask);
#elif ERADICATE2_MODE == MODE_MIRROR
		const uint score = score_mirror(H0, H1, H2);
#else
		const uint score = 0;
#endif

		if (score > scoreMin) {
			eradicate2_report(score, H0, H1, H2, deviceIndex, currentRound, thresholdScore, pBest, pMatchCount, pMatches);
		}
	}
}
