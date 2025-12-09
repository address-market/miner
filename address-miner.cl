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

#define MATCH_QUEUE_SIZE 64

typedef struct {
	uchar score;
	uchar padding[3];
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

__kernel void eradicate2_iterate(__global result * restrict const pResult, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uint roundsPerKernel, const uchar thresholdScore);
void eradicate2_result_update(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uchar score, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_leading(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_benchmark(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_zerobytes(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_matching(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_range(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_leadingrange(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_leadingany(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_mirror(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);
void eradicate2_score_doubles(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore);

__kernel void eradicate2_iterate(__global result * restrict const pResult, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, const uint roundsPerKernel, const uchar thresholdScore) {
	for (uint iter = 0; iter < roundsPerKernel; ++iter) {
		const uint currentRound = round + iter;
		ethhash h = { .q = { ERADICATE2_INITHASH } };

		// Salt have index h.b[21:52] inclusive, which covers WORDS with index h.d[6:12] inclusive (they represent h.b[24:51] inclusive)
		// We use three out of those six words to generate a unique salt value for each device, thread and round. We ignore any overflows
		// and assume that there'll never be more than 2**32 devices, threads or rounds. Worst case scenario with default settings
		// of 16777216 = 2**24 threads means the assumption fails after a device has tried 2**32 * 2**24 = 2**56 salts, enough to match
		// 14 characters in the address! A GTX 1070 with speed of ~700*10**6 combinations per second would hit this target after ~3 years.
		h.d[6] += deviceIndex; 
		h.d[7] += get_global_id(0);
		h.d[8] += currentRound;

		// Hash
		sha3_keccakf(&h);

		h.b[0] = 0xd6;
		h.b[1] = 0x94;
		#pragma unroll
		for (int i = 12; i < 42; i++) {
			h.b[i - 10] = h.b[i];
		}
		h.b[22] = 0x01;
		h.b[23] = 0x01; // padding
		#pragma unroll
		for (int i = 24; i < 200; i++) {
			h.b[i] = 0;
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
		const uchar hasResult = atomic_inc(&pResult[score].found); // NOTE: If "too many" results are found it'll wrap around to 0 again and overwrite last result. Only relevant if global worksize exceeds MAX(uint).

		// Save only one result for each score, the first.
		if (hasResult == 0) {
			// Reconstruct state with hash and extract salt
			ethhash h = { .q = { ERADICATE2_INITHASH } };
			h.d[6] += deviceIndex;
			h.d[7] += get_global_id(0);
			h.d[8] += round;

			for (int i = 0; i < 32; ++i) {
				pResult[score].salt[i] = h.b[i + 21];
			}

			for (int i = 0; i < 20; ++i) {
				pResult[score].hash[i] = H[i];
			}
			const uint matchIndex = atomic_inc(pMatchCount);
			if (matchIndex < MATCH_QUEUE_SIZE) {
				pMatches[matchIndex].score = score;
			}
			atomic_or(pHasResult, 1u);
		}
	}
}

void eradicate2_score_leading(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;

	for (int i = 0; i < 20; ++i) {
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

void eradicate2_score_benchmark(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	(void) thresholdScore;

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_zerobytes(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
	int score = 0;
	(void) thresholdScore;

	#pragma unroll
	for (int i = 0; i < 20; ++i) {
		score += !hash[i];
	}

	eradicate2_result_update(hash, pResult, pHasResult, pMatchCount, pMatches, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_matching(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
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

void eradicate2_score_range(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
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

void eradicate2_score_leadingrange(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
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

void eradicate2_score_leadingany(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore){
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

void eradicate2_score_mirror(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
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

void eradicate2_score_doubles(const uchar * const hash, __global result * restrict const pResult, __global volatile uint * restrict const pHasResult, __global volatile uint * restrict const pMatchCount, __global match_entry * restrict const pMatches, __global const mode * restrict const pMode, const uchar scoreMax, const uint deviceIndex, const uint round, const uchar thresholdScore) {
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
