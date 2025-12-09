#include "Dispatcher.hpp"

// Includes
#include <stdexcept>
#include <iostream>
#include <thread>
#include <sstream>
#include <iomanip>
#include <random>
#include <thread>
#include <algorithm>
#include "hexadecimal.hpp"

static void printResult(const result r, const cl_uchar score, const std::chrono::time_point<std::chrono::steady_clock> & timeStart) {
	// Time delta
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count();

	// Format address
	const std::string strSalt = toHex(r.salt, 32);
	const std::string strPublic = toHex(r.hash, 20);

	// Print
	const std::string strVT100ClearLine = "\33[2K\r";
	std::cout << strVT100ClearLine << "  Time: " << std::setw(5) << seconds << "s Score: " << std::setw(2) << (int) score << " Salt: 0x" << strSalt << " Address: 0x" << strPublic << std::endl;
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

#ifdef CL_VERSION_2_0
	const cl_command_queue ret = clCreateCommandQueueWithProperties(clContext, clDeviceId, &p, NULL);
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
	m_memResult(clContext, m_clQueue, CL_MEM_READ_WRITE, ERADICATE2_MAX_SCORE + 1),
	m_memMode(clContext, m_clQueue, CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, 1),
	m_memHasResult(clContext, m_clQueue, CL_MEM_READ_WRITE, 1),
	m_memMatchCount(clContext, m_clQueue, CL_MEM_READ_WRITE, 1),
	m_memMatches(clContext, m_clQueue, CL_MEM_READ_WRITE, MATCH_QUEUE_SIZE),
	m_round(0),
	m_roundsPerKernel(parent.m_roundsPerKernel),
	m_dispatchCount(0),
	m_pollInterval(8),
	m_totalKernelNs(0),
	m_totalReadNs(0),
	m_kernelProfileCount(0),
	m_readProfileCount(0)
{

}

Dispatcher::Device::~Device() {

}

Dispatcher::Dispatcher(cl_context & clContext, cl_program & clProgram, const size_t worksizeMax, const size_t size, const bool profile, const size_t roundsPerKernel)
	: m_clContext(clContext),
	  m_clProgram(clProgram),
	  m_worksizeMax(worksizeMax),
	  m_size(size),
	  m_clScoreMax(0),
	  m_roundsPerKernel(static_cast<cl_uint>(std::max<size_t>(1, roundsPerKernel))),
	  m_vDevices(),
	  m_eventFinished(NULL),
	  m_speed(),
	  m_countPrint(0),
	  m_countRunning(0),
	  m_quit(false),
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
	m_eventFinished = clCreateUserEvent(m_clContext, NULL);
	timeStart = std::chrono::steady_clock::now();
	m_clScoreMax = m_collectAllLeading ? m_thresholdScore : 0;

	for (auto it = m_vDevices.begin(); it != m_vDevices.end(); ++it) {
		Device & d = **it;
		d.m_round = 0;
		d.m_clScoreMax = m_collectAllLeading ? m_thresholdScore : 0;

		for (size_t i = 0; i < ERADICATE2_MAX_SCORE + 1; ++i) {
			d.m_memResult[i].found = 0;
		}

		// Copy data
		*d.m_memMode = mode;
		d.m_memMode.write(true);
		d.m_memResult.write(true);
		d.m_memHasResult[0] = 0;
		d.m_memHasResult.write(true);
		d.m_memMatchCount[0] = 0;
		d.m_memMatchCount.write(true);

		// Kernel arguments - eradicate2_iterate
		d.m_memResult.setKernelArg(d.m_kernelIterate, 0);
		d.m_memMode.setKernelArg(d.m_kernelIterate, 1);
		CLMemory<cl_uchar>::setKernelArg(d.m_kernelIterate, 2, d.m_clScoreMax); // Updated in handleResult()		
		CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 3, d.m_index);
		d.m_memHasResult.setKernelArg(d.m_kernelIterate, 5);
		d.m_memMatchCount.setKernelArg(d.m_kernelIterate, 6);
		d.m_memMatches.setKernelArg(d.m_kernelIterate, 7);
		CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 8, d.m_roundsPerKernel);
		CLMemory<cl_uchar>::setKernelArg(d.m_kernelIterate, 9, m_thresholdScore);
		// Round information updated in deviceDispatch()
	}
	
	m_quit = false;
	m_countRunning = m_vDevices.size();

	std::cout << "Running..." << std::endl;
	std::cout << std::endl;

	// Start asynchronous dispatch loop on all devices
	for (auto it = m_vDevices.begin(); it != m_vDevices.end(); ++it) {
		deviceDispatch(*(*it));
	}

	// Wait for finish event
	clWaitForEvents(1, &m_eventFinished);
	clReleaseEvent(m_eventFinished);
	m_eventFinished = NULL;

	if (m_profile && !m_profileReported) {
		std::lock_guard<std::mutex> lock(m_mutex);
		printProfilingReport();
		m_profileReported = true;
	}
}

void Dispatcher::enqueueKernel(cl_command_queue & clQueue, cl_kernel & clKernel, size_t worksizeGlobal, const size_t worksizeLocal, cl_event * pEvent = NULL) {
	const size_t worksizeMax = m_worksizeMax;
	size_t worksizeOffset = 0;
	while (worksizeGlobal) {
		const size_t worksizeRun = std::min(worksizeGlobal, worksizeMax);
		const size_t * const pWorksizeLocal = (worksizeLocal == 0 ? NULL : &worksizeLocal);
		const auto res = clEnqueueNDRangeKernel(clQueue, clKernel, 1, &worksizeOffset, &worksizeRun, pWorksizeLocal, 0, NULL, pEvent);
		OpenCLException::throwIfError("kernel queueing failed", res);

		worksizeGlobal -= worksizeRun;
		worksizeOffset += worksizeRun;
	}
}

void Dispatcher::enqueueKernelDevice(Device & d, cl_kernel & clKernel, size_t worksizeGlobal, cl_event * pEvent = NULL) {
	cl_event kernelEvent = NULL;

	try {
		enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal, &kernelEvent);
	} catch ( OpenCLException & e ) {
		// If local work size is invalid, abandon it and let implementation decide
		if ((e.m_res == CL_INVALID_WORK_GROUP_SIZE || e.m_res == CL_INVALID_WORK_ITEM_SIZE) && d.m_worksizeLocal != 0) {
			std::cout << std::endl << "warning: local work size abandoned on GPU" << d.m_index << std::endl;
			d.m_worksizeLocal = 0;
			enqueueKernel(d.m_clQueue, clKernel, worksizeGlobal, d.m_worksizeLocal, &kernelEvent);
		}
		else {
			throw;
		}
	}

	if (kernelEvent) {
		if (m_profile) {
			const auto res = clSetEventCallback(kernelEvent, CL_COMPLETE, kernelProfilingCallback, &d);
			OpenCLException::throwIfError("failed to set kernel profiling callback", res);
		}
		else {
			clReleaseEvent(kernelEvent);
		}
	}
}

void Dispatcher::deviceDispatch(Device & d) {
	const bool hasResult = d.m_memHasResult[0] != 0;

	if (hasResult) {
		d.m_memMatchCount.read(true);
		cl_uint matchCount = d.m_memMatchCount[0];
		if (matchCount > MATCH_QUEUE_SIZE) {
			matchCount = MATCH_QUEUE_SIZE;
		}

		if (matchCount > 0) {
			d.m_memMatches.read(true);

			if (m_collectAllLeading) {
				for (cl_uint i = 0; i < matchCount; ++i) {
					const cl_uchar score = d.m_memMatches[i].score;
					if (score >= m_thresholdScore) {
						result r;
						d.m_memResult.readRange(true, score, 1, &r);
						r.found = 0;
						d.m_memResult.writeRange(false, score, 1, &r);

						std::lock_guard<std::mutex> lock(m_mutex);
						printResult(r, score, timeStart);
					}
				}
			} else {
				cl_uchar bestScore = d.m_clScoreMax;
				for (cl_uint i = 0; i < matchCount; ++i) {
					const cl_uchar score = d.m_memMatches[i].score;
					if (score > bestScore) {
						bestScore = score;
					}
				}

				if (bestScore > d.m_clScoreMax) {
					result r;
					d.m_memResult.readRange(true, bestScore, 1, &r);

					std::lock_guard<std::mutex> lock(m_mutex);
					d.m_clScoreMax = bestScore;
					CLMemory<cl_uchar>::setKernelArg(d.m_kernelIterate, 2, d.m_clScoreMax);

					if (bestScore >= m_clScoreMax) {
						m_clScoreMax = bestScore;

							// TODO: Add quit condition

							printResult(r, bestScore, timeStart);
					}
				}
			}
		}

		d.m_memHasResult[0] = 0;
		d.m_memHasResult.write(true);
		d.m_memMatchCount[0] = 0;
		d.m_memMatchCount.write(true);
	}

	d.m_parent.m_speed.update(d.m_parent.m_size, d.m_index);

	if (m_quit) {
		std::lock_guard<std::mutex> lock(m_mutex);
		if (--m_countRunning == 0) {
			clSetUserEventStatus(m_eventFinished, CL_COMPLETE);
		}
	} else {
		cl_event event = NULL;
		const bool doPoll = ((++d.m_dispatchCount) % d.m_pollInterval) == 0;
		if (doPoll) {
			d.m_memHasResult.read(false, &event);
		} else {
#ifdef CL_VERSION_1_2
			const auto res = clEnqueueMarkerWithWaitList(d.m_clQueue, 0, NULL, &event);
			OpenCLException::throwIfError("failed to enqueue marker", res);
#else
			const auto res = clEnqueueMarker(d.m_clQueue, &event);
			OpenCLException::throwIfError("failed to enqueue marker", res);
#endif
		}
		
		const cl_uint roundBase = d.m_round;
		CLMemory<cl_uint>::setKernelArg(d.m_kernelIterate, 4, roundBase); // Round information updated in deviceDispatch()
		d.m_round += d.m_roundsPerKernel;
		enqueueKernelDevice(d, d.m_kernelIterate, m_size);
		clFlush(d.m_clQueue);

		const auto res = clSetEventCallback(event, CL_COMPLETE, staticCallback, &d);
		OpenCLException::throwIfError("failed to set custom callback", res);
	}
}

void CL_CALLBACK Dispatcher::staticCallback(cl_event event, cl_int event_command_exec_status, void * user_data) {
	if (event_command_exec_status != CL_COMPLETE) {
		throw std::runtime_error("Dispatcher::onEvent - Got bad status" + lexical_cast::write(event_command_exec_status));
	}

	Device * const pDevice = static_cast<Device *>(user_data);
	if (pDevice->m_parent.m_profile) {
		cl_ulong start = 0;
		cl_ulong end = 0;

		clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start, NULL);
		clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end, NULL);
		pDevice->m_totalReadNs += (end - start);
		++pDevice->m_readProfileCount;
	}

	pDevice->m_parent.deviceDispatch(*pDevice);

	clReleaseEvent(event);
}

void CL_CALLBACK Dispatcher::kernelProfilingCallback(cl_event event, cl_int event_command_exec_status, void * user_data) {
	if (event_command_exec_status != CL_COMPLETE) {
		throw std::runtime_error("Dispatcher::kernelProfilingCallback - Got bad status" + lexical_cast::write(event_command_exec_status));
	}

	Device * const pDevice = static_cast<Device *>(user_data);
	cl_ulong start = 0;
	cl_ulong end = 0;

	clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start, NULL);
	clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end, NULL);
	pDevice->m_totalKernelNs += (end - start);
	++pDevice->m_kernelProfileCount;
	if (pDevice->m_parent.m_profile && !pDevice->m_parent.m_profileReported) {
		bool ready = true;
		for (auto dev : pDevice->m_parent.m_vDevices) {
			if (dev->m_kernelProfileCount == 0) {
				ready = false;
				break;
			}
		}

		if (ready) {
			std::lock_guard<std::mutex> lock(pDevice->m_parent.m_mutex);
			if (!pDevice->m_parent.m_profileReported) {
				pDevice->m_parent.printProfilingReport();
				pDevice->m_parent.m_profileReported = true;
			}
		}
	}

	clReleaseEvent(event);
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
