#include "Dispatcher.hpp"
#include "sha3.hpp"

// Includes
#include <stdexcept>
#include <iostream>
#include <thread>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include "hexadecimal.hpp"

static std::string toChecksumAddress(const std::string & addressHexLower) {
	char digest[32];
	sha3(addressHexLower.c_str(), addressHexLower.size(), digest, 32);
	
	std::string checksumAddress = addressHexLower;
	
	for (int i = 0; i < 40; ++i) {
		const unsigned char hashByte = digest[i / 2];
		const int nibble = (i % 2 == 0) ? (hashByte >> 4) : (hashByte & 0x0f);
		
		if (nibble >= 8) {
			checksumAddress[i] = std::toupper(checksumAddress[i]);
		}
	}
	return checksumAddress;
}

static void printResult(const MatchEntry & r, const std::chrono::time_point<std::chrono::steady_clock> & timeStart) {
	// Time delta
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count();

	// Format address
	const std::string strSalt = toHex(r.salt, 32);
	const std::string strPublic = toHex(r.hash, 20);
	const std::string strChecksum = toChecksumAddress(strPublic);

	// Print
	const std::string strVT100ClearLine = "\33[2K\r";
	std::cout << strVT100ClearLine << "  Time: " << std::setw(5) << seconds << "s Score: " << std::setw(2) << (int) r.score << " Salt: 0x" << strSalt << " Address: 0x" << strChecksum << std::endl;
}

Dispatcher::OpenCLException::OpenCLException(const std::string s, const cl_int res) :
	std::runtime_error( s + " (res = " + lexical_cast::write(res) + ")"),
	m_res(res)
{

}

void Dispatcher::OpenCLException::OpenCLException::throwIfError(const std::string s, const cl_int res) {
	if (res != CL_SUCCESS) {
		throw OpenCLException(s, res);
	}
}

cl_command_queue Dispatcher::Device::createQueue(cl_context & clContext, cl_device_id & clDeviceId, const bool enableProfiling) {
	// nVidia CUDA Toolkit 10.1 only supports OpenCL 1.2 so we revert back to older functions for compatability
	cl_command_queue_properties p = 0;

#ifdef ERADICATE2_DEBUG
	p = CL_QUEUE_PROFILING_ENABLE;
#else
	if (enableProfiling) {
		p = CL_QUEUE_PROFILING_ENABLE;
	}
#endif

	if (p & CL_QUEUE_PROFILING_ENABLE) {
		// std::cout << "  DEBUG: Queue profiling enabled for device." << std::endl;
	}

#ifdef CL_VERSION_2_0
	const cl_queue_properties props[] = { CL_QUEUE_PROPERTIES, p, 0 };
	const cl_command_queue ret = clCreateCommandQueueWithProperties(clContext, clDeviceId, props, NULL);
#else
	const cl_command_queue ret = clCreateCommandQueue(clContext, clDeviceId, p, NULL);
#endif
	return ret == NULL ? throw std::runtime_error("failed to create command queue") : ret;
}

cl_kernel Dispatcher::Device::createKernel(cl_program & clProgram, const std::string s) {
	cl_kernel ret  = clCreateKernel(clProgram, s.c_str(), NULL);
	return ret == NULL ? throw std::runtime_error("failed to create kernel \"" + s + "\"") : ret;
}

Dispatcher::Device::Device(Dispatcher & parent, cl_context & clContext, cl_program & clProgram, cl_device_id clDeviceId, const size_t worksizeLocal, const size_t size, const size_t index) :
	m_parent(parent),
	m_index(index),
	m_clDeviceId(clDeviceId),
	m_worksizeLocal(worksizeLocal),
	m_clScoreMax(0),
	m_clQueue(createQueue(clContext, clDeviceId, parent.m_profile) ),
	m_kernelIterate(createKernel(clProgram, "eradicate2_iterate")),
	m_memMode(clContext, m_clQueue, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, 1),
	m_memBest(clContext, m_clQueue, CL_MEM_READ_WRITE, 1),
	m_memMatchCount(clContext, m_clQueue, CL_MEM_READ_WRITE, 1),
	m_memMatches(clContext, m_clQueue, CL_MEM_READ_WRITE, MATCH_QUEUE_SIZE),
	m_isAutoTuning(parent.m_roundsPerKernel == 0),
	m_bestRounds(1),
	m_bestSpeed(0.0),
	m_tuningStartTime(std::chrono::steady_clock::now()),
	m_tuningAccumulatedHashes(0.0),
	m_round(0),
	m_roundsPerKernel(parent.m_roundsPerKernel),
	m_totalKernelNs(0),
	m_totalReadNs(0),
	m_kernelProfileCount(0),
	m_readProfileCount(0)
{
	m_roundsPerKernel = m_isAutoTuning ? 1 : parent.m_roundsPerKernel;

	if (m_isAutoTuning) {
		std::cout << "\n  GPU" << m_index << ": Auto-tuning enabled. Starting with 1 round..." << std::endl;
	}
}

Dispatcher::Device::~Device() {

}

Dispatcher::Dispatcher(cl_context & clContext, cl_program & clProgram, const size_t worksizeMax, const size_t size, const bool profile, const size_t roundsPerKernel)
	: m_clContext(clContext),
	  m_clProgram(clProgram),
	  m_worksizeMax(worksizeMax),
	  m_size(size),
	  m_clScoreMax(0),
	  // If roundsPerKernel is 0, we enable auto-tuning.
	  m_roundsPerKernel(roundsPerKernel),
	  m_vDevices(),
	  m_speed(),
	  m_collectAllLeading(false),
	  m_thresholdScore(0),
	  m_profile(profile),
	  m_profileReported(false) {

}

Dispatcher::~Dispatcher() {

}

void Dispatcher::enableLeadingThresholdMode(const cl_uchar threshold) {
	if (threshold > 0) {
		m_collectAllLeading = true;
		m_thresholdScore = threshold;
	}
}

void Dispatcher::addDevice(cl_device_id clDeviceId, const size_t worksizeLocal, const size_t index) {
	Device * pDevice = new Device(*this, m_clContext, m_clProgram, clDeviceId, worksizeLocal, m_size, index);
	m_vDevices.push_back(pDevice);
}

void Dispatcher::run(const mode & mode) {
	timeStart = std::chrono::steady_clock::now();
	m_clScoreMax = 0;

	for (auto it = m_vDevices.begin(); it != m_vDevices.end(); ++it) {
		Device & d = **it;
		d.m_round = 0;
		d.m_clScoreMax = 0;

		*d.m_memMode = mode;
		d.m_memMode.write(true);
		d.m_memBest[0] = 0;
		d.m_memBest.write(true);
		d.m_memMatchCount[0] = 0;
		d.m_memMatchCount.write(true);

		// Kernel arguments - eradicate2_iterate. Score floor, round and rounds per kernel are set per launch.
		d.m_memMode.setKernelArg(d.m_kernelIterate, 0);
		CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 2, d.m_index);
		CLMemory<cl_uchar>::setKernelArg(d.m_kernelIterate, 5, m_thresholdScore);
		d.m_memBest.setKernelArg(d.m_kernelIterate, 6);
		d.m_memMatchCount.setKernelArg(d.m_kernelIterate, 7);
		d.m_memMatches.setKernelArg(d.m_kernelIterate, 8);
	}

	std::cout << "Running..." << std::endl;
	std::cout << std::endl;

	std::vector<std::thread> vThreads;
	for (auto it = m_vDevices.begin(); it != m_vDevices.end(); ++it) {
		Device & d = **it;
		d.m_tuningStartTime = std::chrono::steady_clock::now();
		vThreads.emplace_back([this, &d]() {
			try {
				deviceLoop(d);
			} catch (std::exception & e) {
				std::cout << std::endl << "GPU" << d.m_index << " error: " << e.what() << std::endl;
				std::exit(1);
			}
		});
	}

	for (auto & t : vThreads) {
		t.join();
	}
}

cl_event Dispatcher::enqueueKernel(cl_command_queue & clQueue, cl_kernel & clKernel, size_t worksizeGlobal, const size_t worksizeLocal) {
	const size_t worksizeMax = m_worksizeMax;
	size_t worksizeOffset = 0;
	cl_event event = NULL;
	while (worksizeGlobal) {
		const size_t worksizeRun = std::min(worksizeGlobal, worksizeMax);
		const size_t * const pWorksizeLocal = (worksizeLocal == 0 ? NULL : &worksizeLocal);
		if (event) {
			clReleaseEvent(event);
			event = NULL;
		}
		const auto res = clEnqueueNDRangeKernel(clQueue, clKernel, 1, &worksizeOffset, &worksizeRun, pWorksizeLocal, 0, NULL, &event);
		OpenCLException::throwIfError("kernel queueing failed", res);

		worksizeGlobal -= worksizeRun;
		worksizeOffset += worksizeRun;
	}
	return event;
}

cl_event Dispatcher::enqueueKernelDevice(Device & d, cl_kernel & clKernel, size_t worksizeGlobal) {
	try {
		return enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal);
	} catch ( OpenCLException & e ) {
		// If local work size is invalid, abandon it and let implementation decide
		if ((e.m_res == CL_INVALID_WORK_GROUP_SIZE || e.m_res == CL_INVALID_WORK_ITEM_SIZE) && d.m_worksizeLocal != 0) {
			std::cout << std::endl << "warning: local work size abandoned on GPU" << d.m_index << std::endl;
			d.m_worksizeLocal = 0;
			return enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal);
		}
		throw;
	}
}

void Dispatcher::launchBatch(Device & d, Batch & b) {
	const cl_uchar scoreMin = m_collectAllLeading ? static_cast<cl_uchar>(m_thresholdScore - 1) : d.m_clScoreMax;
	CLMemory<cl_uchar>::setKernelArg(d.m_kernelIterate, 1, scoreMin);
	CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 3, d.m_round);
	CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 4, d.m_roundsPerKernel);

	b.rounds = d.m_roundsPerKernel;
	b.matchCount = 0;
	d.m_round += b.rounds;

	b.kernelEvent = enqueueKernelDevice(d, d.m_kernelIterate, m_size);
	d.m_memMatchCount.readRange(false, 0, 1, &b.matchCount, &b.countEvent);
	clFlush(d.m_clQueue);
}

// Two batches stay in flight so the GPU never idles while the host inspects the previous one.
void Dispatcher::deviceLoop(Device & d) {
	Batch batches[2];
	size_t current = 0;
	launchBatch(d, batches[current]);

	for (;;) {
		launchBatch(d, batches[current ^ 1]);

		Batch & b = batches[current];
		const auto res = clWaitForEvents(1, &b.countEvent);
		OpenCLException::throwIfError("failed waiting for kernel", res);
		finishBatch(d, b);

		if (b.matchCount > 0) {
			handleMatches(d);
			// handleMatches drains the queue after the other batch has completed too.
			batches[current ^ 1].matchCount = 0;
		}

		current ^= 1;
	}
}

void Dispatcher::finishBatch(Device & d, Batch & b) {
	if (m_profile) {
		cl_ulong kStart = 0, kEnd = 0, rStart = 0, rEnd = 0;
		clGetEventProfilingInfo(b.kernelEvent, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &kStart, NULL);
		clGetEventProfilingInfo(b.kernelEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &kEnd, NULL);
		clGetEventProfilingInfo(b.countEvent, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &rStart, NULL);
		clGetEventProfilingInfo(b.countEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &rEnd, NULL);

		std::lock_guard<std::mutex> lock(m_mutex);
		d.m_totalKernelNs += (kEnd - kStart);
		++d.m_kernelProfileCount;
		d.m_totalReadNs += (rEnd - rStart);
		++d.m_readProfileCount;

		if (!m_profileReported) {
			bool ready = true;
			for (auto dev : m_vDevices) {
				if (dev->m_kernelProfileCount == 0) {
					ready = false;
					break;
				}
			}

			if (ready) {
				printProfilingReport();
				m_profileReported = true;
			}
		}
	}

	clReleaseEvent(b.kernelEvent);
	clReleaseEvent(b.countEvent);

	m_speed.update(static_cast<unsigned long long>(m_size) * b.rounds, d.m_index);

	if (d.m_isAutoTuning) {
		autoTune(d, b.rounds);
	}
}

void Dispatcher::handleMatches(Device & d) {
	clFinish(d.m_clQueue);
	d.m_memMatchCount.read(true);
	cl_uint matchCount = d.m_memMatchCount[0];
	if (matchCount == 0) {
		return;
	}

	if (matchCount > MATCH_QUEUE_SIZE) {
		std::cout << "\nWARNING: Match queue overflow! Lost " << (matchCount - MATCH_QUEUE_SIZE) << " results. Increase MATCH_QUEUE_SIZE." << std::endl;
		matchCount = MATCH_QUEUE_SIZE;
	}

	d.m_memMatches.readRange(true, 0, matchCount, d.m_memMatches.data());

	d.m_memMatchCount[0] = 0;
	d.m_memMatchCount.write(true);

	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_collectAllLeading) {
		for (cl_uint i = 0; i < matchCount; ++i) {
			printResult(d.m_memMatches[i], timeStart);
			m_speed.addResult();
		}
		return;
	}

	cl_uint bestIndex = 0;
	for (cl_uint i = 1; i < matchCount; ++i) {
		if (d.m_memMatches[i].score > d.m_memMatches[bestIndex].score) {
			bestIndex = i;
		}
	}

	const MatchEntry & best = d.m_memMatches[bestIndex];
	if (best.score > d.m_clScoreMax) {
		d.m_clScoreMax = best.score;

		if (best.score >= m_clScoreMax) {
			m_clScoreMax = best.score;
			printResult(best, timeStart);
			m_speed.addResult();
		}
	}
}

// Time-based: evaluate every 10 seconds, doubling rounds per kernel while speed improves.
void Dispatcher::autoTune(Device & d, const cl_uint rounds) {
	d.m_tuningAccumulatedHashes += (double) m_size * rounds;

	const auto now = std::chrono::steady_clock::now();
	const std::chrono::duration<double> elapsed = now - d.m_tuningStartTime;
	if (elapsed.count() <= 10.0) {
		return;
	}

	const double avgSpeed = d.m_tuningAccumulatedHashes / elapsed.count();

	std::lock_guard<std::mutex> lock(m_mutex);
	// 1.01 = 1% improvement threshold
	if (avgSpeed > d.m_bestSpeed * 1.01) {
		d.m_bestSpeed = avgSpeed;
		d.m_bestRounds = d.m_roundsPerKernel;
		d.m_roundsPerKernel *= 2;

		// Hard limits: 64 rounds
		if (d.m_roundsPerKernel > 64) {
			d.m_roundsPerKernel = d.m_bestRounds;
			d.m_isAutoTuning = false;
			std::cout << "\33[2K\r Auto-tune: Settled on " << d.m_bestRounds << " rounds (Limit reached)" << std::endl;
		} else {
			std::cout << "\33[2K\r Auto-tune: Upgrading to " << d.m_roundsPerKernel << " rounds (" << std::fixed << std::setprecision(2) << avgSpeed / 1000000.0 << " MH/s)" << std::defaultfloat << std::endl;
		}
	} else {
		d.m_roundsPerKernel = d.m_bestRounds;
		d.m_isAutoTuning = false;
		std::cout << "\33[2K\r Auto-tune: Settled on " << d.m_bestRounds << " rounds (Peak performance)" << std::endl;
	}

	d.m_tuningStartTime = now;
	d.m_tuningAccumulatedHashes = 0;
}

void Dispatcher::printProfilingReport() const {
	if (!m_profile) {
		return;
	}

	std::cout << std::endl;
	std::cout << "OpenCL profiling summary:" << std::endl;
	for (const Device * d : m_vDevices) {
		const double avgKernelMs = d->m_kernelProfileCount ? static_cast<double>(d->m_totalKernelNs) / d->m_kernelProfileCount / 1e6 : 0.0;
		const double avgReadUs = d->m_readProfileCount ? static_cast<double>(d->m_totalReadNs) / d->m_readProfileCount / 1e3 : 0.0;

		std::cout << "  GPU" << d->m_index << ": kernels=" << d->m_kernelProfileCount << " avg=";
		std::cout << std::fixed << std::setprecision(3) << avgKernelMs << " ms";
		std::cout << std::defaultfloat;
		std::cout << ", reads=" << d->m_readProfileCount << " avg=" << std::fixed << std::setprecision(3) << avgReadUs << " µs" << std::defaultfloat << std::endl;
	}
	std::cout << std::endl;
}
