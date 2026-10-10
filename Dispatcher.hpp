#ifndef HPP_DISPATCHER
#define HPP_DISPATCHER

#include <stdexcept>
#include <fstream>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>

#if defined(__APPLE__) || defined(__MACOSX)
#include <OpenCL/cl.h>
#define clCreateCommandQueueWithProperties clCreateCommandQueue
#else
#include <CL/cl.h>
#endif

#include "CLMemory.hpp"
#include "Speed.hpp"
#include "types.hpp"

#define ERADICATE2_MAX_SCORE 40

struct MatchEntry {
	cl_uchar score;
	cl_uchar padding[3];
	cl_uchar salt[32];
	cl_uchar hash[20];
	cl_uchar padding2[8];
};

static const size_t MATCH_QUEUE_SIZE = 65536;

class Dispatcher {
	private:
		class OpenCLException : public std::runtime_error {
			public:
				OpenCLException(const std::string s, const cl_int res);

				static void throwIfError(const std::string s, const cl_int res);

				const cl_int m_res;
		};

		struct Device {
			static cl_command_queue createQueue(cl_context & clContext, cl_device_id & clDeviceId, const bool enableProfiling);
			static cl_kernel createKernel(cl_program & clProgram, const std::string s);

			Device(Dispatcher & parent, cl_context & clContext, cl_program & clProgram, cl_device_id clDeviceId, const size_t worksizeLocal, const size_t size, const size_t index);
			~Device();

			Dispatcher & m_parent;
			const size_t m_index;

			cl_device_id m_clDeviceId;
			size_t m_worksizeLocal;
			cl_uchar m_clScoreMax;
			cl_command_queue m_clQueue;

			cl_kernel m_kernelIterate;

			CLMemory<mode> m_memMode;
			CLMemory<cl_uint> m_memBest;
			CLMemory<cl_uint> m_memMatchCount;
			CLMemory<MatchEntry> m_memMatches;

			// Tuning State
			bool m_isAutoTuning;
			cl_uint m_bestRounds;
			double m_bestSpeed;
			std::chrono::time_point<std::chrono::steady_clock> m_tuningStartTime;
			double m_tuningAccumulatedHashes;

			cl_uint m_round;
			cl_uint m_roundsPerKernel;
			cl_ulong m_totalKernelNs;
			cl_ulong m_totalReadNs;
			size_t m_kernelProfileCount;
			size_t m_readProfileCount;
		};

		struct Batch {
			cl_event kernelEvent;
			cl_event countEvent;
			cl_uint matchCount;
			cl_uint rounds;
		};

	public:
		Dispatcher(cl_context & clContext, cl_program & clProgram, const size_t worksizeMax, const size_t size, const bool profile = false, const size_t roundsPerKernel = 1);
		~Dispatcher();

		void addDevice(cl_device_id clDeviceId, const size_t worksizeLocal, const size_t index);
		void run(const mode & mode);
		void enableLeadingThresholdMode(const cl_uchar threshold);

	private:
		void deviceLoop(Device & d);
		void launchBatch(Device & d, Batch & b);
		void finishBatch(Device & d, Batch & b);
		void handleMatches(Device & d);
		void autoTune(Device & d, const cl_uint rounds);

		cl_event enqueueKernel(cl_command_queue & clQueue, cl_kernel & clKernel, size_t worksizeGlobal, const size_t worksizeLocal);
		cl_event enqueueKernelDevice(Device & d, cl_kernel & clKernel, size_t worksizeGlobal);

		void printProfilingReport() const;

	private: /* Instance variables */
		cl_context & m_clContext;
		cl_program & m_clProgram;
		const size_t m_worksizeMax;
		const size_t m_size;
		cl_uchar m_clScoreMax;
		const cl_uint m_roundsPerKernel;
		std::vector<Device *> m_vDevices;

		// Run information
		std::mutex m_mutex;
		std::chrono::time_point<std::chrono::steady_clock> timeStart;
		Speed m_speed;
		bool m_collectAllLeading;
		cl_uchar m_thresholdScore;
		bool m_profile;
		bool m_profileReported;
};

#endif /* HPP_DISPATCHER */
