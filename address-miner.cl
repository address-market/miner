enum ModeFunction {
	Benchmark, ZeroBytes, Matching, Leading, Range, Mirror, Doubles, LeadingRange, LeadingAny
};

typedef struct {
	enum ModeFunction function;
	uchar data1[20];
	uchar data2[20];
} mode;

typedef struct __attribute__((packed)) {
	uchar salt[32];
	uchar hash[20];
	uint found;
} result;

#define MATCH_QUEUE_SIZE 65536

typedef struct {
	uchar score;
	uchar padding[3];
	uchar salt[32];
	uchar hash[20];
	uchar padding2[8];
} match_entry;

#ifndef ERADICATE2_INITHASH
#define ERADICATE2_INITHASH 0x000
typedef union {
	uchar b[200];
	ulong q[25];
	uint d[50];
} ethhash;
void sha3_keccakf(ethhash * const h)
{
}
#endif

inline bool thresholdStillReachable(const int currentScore, const int remainingNibbles, const uchar thresholdScore) {
	if (thresholdScore == 0) {
		return true;
	}

	return currentScore + remainingNibbles >= thresholdScore;
}

__kernel void eradicate2_iterate(__global result * restrict const pResult, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uint roundsPerKernel, const uchar thresholdScore, __global volatile ulong * restrict const pProgress);
void eradicate2_result_update(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uchar score, const uchar scoreMax, const uint deviceIndex, const uint round);
static inline void __attribute__((always_inline)) eradicate2_score_leading(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_benchmark(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_zerobytes(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_matching(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_range(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_leadingrange(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_leadingany(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_mirror(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
static inline void __attribute__((always_inline)) eradicate2_score_doubles(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);

__kernel void eradicate2_iterate(__global result * restrict const pResult, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uint roundsPerKernel, const uchar thresholdScore, __global volatile ulong * restrict const pProgress) {
	for (uint iter = 0; iter < roundsPerKernel; ++iter) {
		const uint currentRound = round + iter;
		
		// Track progress: write current round for the first thread only
		if (get_global_id(0) == 0) {
			*pProgress = currentRound;
		}

		ethhash h = { .q = { ERADICATE2_INITHASH } };

		// Optimized salt update for 64-bit architecture (M1)
		// Instead of 3x 32-bit adds (h.d[6], h.d[7], h.d[8]), use 64-bit ops on h.q[3], h.q[4]
		// h.d[6] is low 32 bits of h.q[3], h.d[7] is high 32 bits of q[3]
		h.q[3] += (ulong)deviceIndex + ((ulong)get_global_id(0) << 32);
		h.q[4] += (ulong)currentRound;

		// Hash
		sha3_keccakf(&h);

		h.b[0] = 0xd6;
		h.b[1] = 0x94;

		// Optimized State Update for 2nd Hash (M1/Universal)
		// Move address (20 bytes) from offset 12 to offset 2.
		// Use manual unroll for small moves, and ulong zeroing for the tail.
		#pragma unroll
		for (int i = 0; i < 20; ++i) {
			h.b[i + 2] = h.b[i + 12];
		}
		
		h.b[22] = 0x01;
		h.b[23] = 0x01; // padding start

		// Fast zeroing using 64-bit stores (replaces 176 byte writes)
		#pragma unroll
		for (int i = 3; i < 25; ++i) {
			h.q[i] = 0;
		}
		
		sha3_keccakf(&h);

		switch (pMode->function) {
		case Benchmark:
			eradicate2_score_benchmark(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case ZeroBytes:
			eradicate2_score_zerobytes(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case Matching:
			eradicate2_score_matching(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case Leading:
			eradicate2_score_leading(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case Range:
			eradicate2_score_range(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case Mirror:
			eradicate2_score_mirror(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case Doubles:
			eradicate2_score_doubles(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case LeadingRange:
			eradicate2_score_leadingrange(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;

		case LeadingAny:
			eradicate2_score_leadingany(h.b + 12, pResult, pHasResult, pMatchCount, pMatches, pMode, scoreMax, deviceIndex, currentRound, thresholdScore);
			break;
		}
	}
}

void eradicate2_result_update(const uchar * const H, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uchar score, const uchar scoreMax, const uint deviceIndex, const uint round) {
	if (score && score >= scoreMax) {
		const uint matchIndex = atomic_inc(pMatchCount);
		if (matchIndex < MATCH_QUEUE_SIZE) {
			pMatches[matchIndex].score = score;
			
			// Reconstruct state with hash and extract salt
			ethhash h = { .q = { ERADICATE2_INITHASH } };
			h.d[6] += deviceIndex;
			h.d[7] += get_global_id(0);
			h.d[8] += round;

			#pragma unroll
			for (int i = 0; i < 32; ++i) {
				pMatches[matchIndex].salt[i] = h.b[i + 21];
			}

			#pragma unroll
			for (int i = 0; i < 20; ++i) {
				pMatches[matchIndex].hash[i] = H[i];
			}
			
			atomic_or(pHasResult, 1u);
			
			// Legacy support for non-queue modes (Result Best Score Only)
			atomic_inc(&pResult[score].found); 
		}
	}
}

static inline void __attribute__((always_inline)) eradicate2_score_leading(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	int i = 0;

	// Optimization: Check 4 bytes (8 nibbles) at a time using 32-bit ops.
	// Hash is aligned to 4 bytes (offset 12 in ethhash).
	const uint * const pHash32 = (const uint *)hash;
	const uchar t = pMode->data1[0];
	uint target32 = (t << 4) | t;
	target32 |= target32 << 8;
	target32 |= target32 << 16;

	// Check first 4 bytes (nibbles 0-7)
	if (i < 20 && pHash32[0] == target32) {
		score += 8;
		i += 4;
		// Check next 4 bytes (nibbles 8-15)
		if (i < 20 && pHash32[1] == target32) {
			score += 8;
			i += 4;
            // Check next 4 bytes (nibbles 16-23)
            if (i < 20 && pHash32[2] == target32) {
                score += 8;
                i += 4;
            }
		}
	}

	for (; i < 20; ++i) {
		int remaining = (20 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		if ((hash[i] & 0xF0) >> 4 == pMode->data1[0]) {
			++score;
		} else {
			break;
		}

		--remaining;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		if ((hash[i] & 0x0F) == pMode->data1[0]) {
			++score;
		} else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_benchmark(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	(void) thresholdScore;

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_zerobytes(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	(void) thresholdScore;

	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		score += !hash[i];
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_matching(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	(void) thresholdScore;

	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		const uchar mask = pMode->data1[i];
		const uchar val  = pMode->data2[i];
		score += (mask && ((hash[i] & mask) == val));
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_range(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		int remaining = (20 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		const uchar first = (hash[i] & 0xF0) >> 4;
		const uchar second = (hash[i] & 0x0F);

		score += pMode->data2[first + 1];

		--remaining;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		score += pMode->data2[second + 1];
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_leadingrange(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		int remaining = (20 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		const uchar first = (hash[i] & 0xF0) >> 4;
		const uchar second = (hash[i] & 0x0F);

		if (pMode->data2[first + 1]) {
			++score;
		}
		else {
			break;
		}

		--remaining;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		if (pMode->data2[second + 1]) {
			++score;
		}
		else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_leadingany(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore){
	int score = 0;
	uchar firstSymbol = (hash[0] & 0xF0) >> 4;

	for (int i = 0; i < 20; ++i) {
		int remaining = (20 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		uchar highNibble = (hash[i] & 0xF0) >> 4;
		uchar lowNibble = hash[i] & 0x0F;
		if (highNibble == firstSymbol) {
			score += 1;
		} else {
			break;
		}
		if (lowNibble == firstSymbol) {
			score += 1;
		} else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_mirror(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;

	for (int i = 0; i < 10; ++i) {
		int remaining = (10 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		const uchar leftLeft = (hash[9 - i] & 0xF0) >> 4;
		const uchar leftRight = (hash[9 - i] & 0x0F);

		const uchar rightLeft = (hash[10 + i] & 0xF0) >> 4;
		const uchar rightRight = (hash[10 + i] & 0x0F);

		if (leftRight != rightLeft) {
			break;
		}

		++score;

		if (leftLeft != rightRight) {
			break;
		}

		++score;
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

static inline void __attribute__((always_inline)) eradicate2_score_doubles(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __constant mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		int remaining = (20 - i) * 2;
		if (!thresholdStillReachable(score, remaining, thresholdScore)) {
			break;
		}

		const uchar hi = (hash[i] & 0xF0) >> 4;
		const uchar lo = hash[i] & 0x0F;
		if (hi == lo) {
			++score;
		}
		else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}
