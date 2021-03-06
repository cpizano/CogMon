/***
* ==++==
*
* Copyright (c) Microsoft Corporation. All rights reserved. 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* ==--==
* =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
*
* pplxwin.cpp
*
* Windows specific implementation of PPL constructs
*
* For the latest on this and related APIs, please see http://casablanca.codeplex.com.
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1800)
#error This file must not be compiled for Visual Studio 12 or later
#endif

#include "pplx/pplxwin.h"

#ifndef _MS_WINDOWS
#error "ERROR: This file should only be included in Windows Build"
#endif

// Disable false alarm code analyze warning 
#pragma warning (disable : 26165 26110)
namespace pplx 
{ 
namespace details
{
    namespace platform
    {
        _PPLXIMP long __cdecl GetCurrentThreadId()
        {
            return (long)(::GetCurrentThreadId());
        }

        _PPLXIMP void __cdecl YieldExecution()
        {
            YieldProcessor();
        }

        _PPLXIMP size_t __cdecl CaptureCallstack(void **stackData, size_t skipFrames, size_t captureFrames)
        {
            (stackData);
            (skipFrames);
            (captureFrames);

            size_t capturedFrames = 0;
            // RtlCaptureSTackBackTrace is not available in MSDK, so we only call it under Desktop or _DEBUG MSDK.
            //  For MSDK unsupported version, we will return zero frame number.
#if !defined(__cplusplus_winrt)
            capturedFrames = RtlCaptureStackBackTrace(static_cast<DWORD>(skipFrames + 1), static_cast<DWORD>(captureFrames), stackData, nullptr);
#endif
            return capturedFrames;
        }

#if defined(__cplusplus_winrt)
        volatile long s_asyncId = 0;

        _PPLXIMP unsigned int __cdecl GetNextAsyncId()
        {
            return static_cast<unsigned int>(_InterlockedIncrement(&s_asyncId));
        }

#endif // defined(__cplusplus_winrt)
    }

    //
    // Event implementation
    //
    _PPLXIMP event_impl::event_impl()
    {
        static_assert(sizeof(HANDLE) <= sizeof(_M_impl), "HANDLE version mismatch");

        _M_impl = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);

        if( _M_impl != NULL )
        {
            ResetEvent(static_cast<HANDLE>(_M_impl));
        }
    }

    _PPLXIMP event_impl::~event_impl()
    {
        CloseHandle(static_cast<HANDLE>(_M_impl));
    }

    _PPLXIMP void event_impl::set()
    {
        SetEvent(static_cast<HANDLE>(_M_impl));
    }

    _PPLXIMP void event_impl::reset()
    {
        ResetEvent(static_cast<HANDLE>(_M_impl));
    }

    _PPLXIMP unsigned int event_impl::wait(unsigned int timeout)
    {
        DWORD waitTime = (timeout == event_impl::timeout_infinite) ?  INFINITE : (DWORD)timeout;
        DWORD status = WaitForSingleObjectEx(static_cast<HANDLE>(_M_impl), waitTime, 0);
        _ASSERTE((status == WAIT_OBJECT_0) || (waitTime != INFINITE));

        return (status == WAIT_OBJECT_0) ? 0 : event_impl::timeout_infinite;
    }

    //
    // critical_section implementation
    //
    // TFS# 612702 -- this implementation is unnecessariliy recursive. See bug for details.
    _PPLXIMP critical_section_impl::critical_section_impl()
    {
        static_assert(sizeof(CRITICAL_SECTION) <= sizeof(_M_impl), "CRITICAL_SECTION version mismatch");
        InitializeCriticalSectionEx(reinterpret_cast<LPCRITICAL_SECTION>(&_M_impl), 0, 0);
    }

    _PPLXIMP critical_section_impl::~critical_section_impl() 
    {
        DeleteCriticalSection(reinterpret_cast<LPCRITICAL_SECTION>(&_M_impl));
    }

    _PPLXIMP void critical_section_impl::lock()
    {
        EnterCriticalSection(reinterpret_cast<LPCRITICAL_SECTION>(&_M_impl));
    }

    _PPLXIMP void critical_section_impl::unlock()
    {
        LeaveCriticalSection(reinterpret_cast<LPCRITICAL_SECTION>(&_M_impl));
    }

    //
    // reader_writer_lock implementation
    //
    _PPLXIMP reader_writer_lock_impl::reader_writer_lock_impl()
    : m_locked_exclusive(false)
    {
        static_assert(sizeof(SRWLOCK) <= sizeof(_M_impl), "SRWLOCK version mismatch");
        InitializeSRWLock(reinterpret_cast<PSRWLOCK>(&_M_impl));
    }

    _PPLXIMP void reader_writer_lock_impl::lock()
    {
        AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(&_M_impl));
        m_locked_exclusive = true;
    }

    _PPLXIMP void reader_writer_lock_impl::lock_read()
    {
        AcquireSRWLockShared(reinterpret_cast<PSRWLOCK>(&_M_impl));
    }

    _PPLXIMP void reader_writer_lock_impl::unlock()
    {
        if(m_locked_exclusive)
        {
            m_locked_exclusive = false;
            ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(&_M_impl));
        }
        else
        {
            ReleaseSRWLockShared(reinterpret_cast<PSRWLOCK>(&_M_impl));
        }
    }

    //
    // Timer implementation
    //
    class windows_timer : public timer_impl::_Timer_interface
    {
    public:
        windows_timer(TaskProc_t userFunc, _In_ void * context)
            : m_userFunc(userFunc), m_userContext(context)
        {
        }

        virtual ~windows_timer()
        {
        }

        virtual void start(unsigned int ms, bool repeat)
        {
    #if defined(__cplusplus_winrt)
            auto timerHandler = ref new Windows::System::Threading::TimerElapsedHandler([this](Windows::System::Threading::ThreadPoolTimer ^)
            {
                this->m_userFunc(this->m_userContext);
            });

            Windows::Foundation::TimeSpan span;
            span.Duration = ms * 10000;
            if (repeat)
            {
                m_hTimer = Windows::System::Threading::ThreadPoolTimer::CreatePeriodicTimer(timerHandler, span);
            }
            else
            {
                m_hTimer = Windows::System::Threading::ThreadPoolTimer::CreateTimer(timerHandler, span);
            }
    #else
            if (!CreateTimerQueueTimer(&m_hTimer, NULL, _TimerCallback, this, ms, repeat ? ms : 0, WT_EXECUTEDEFAULT))
            {
                throw std::bad_alloc();
            }
    #endif
        }

        virtual void stop(bool waitForCallbacks)
        {
    #if defined(__cplusplus_winrt)

            UNREFERENCED_PARAMETER(waitForCallbacks);

            if (m_hTimer != nullptr)
            {
                m_hTimer->Cancel();
                m_hTimer = nullptr;
            }
    #else
            while (!DeleteTimerQueueTimer(NULL, m_hTimer, waitForCallbacks ? INVALID_HANDLE_VALUE : NULL))
            {
                if (GetLastError() == ERROR_IO_PENDING) 
                    break;
            }
    #endif

            delete this;
        }

    private:

        static void CALLBACK _TimerCallback(PVOID context, BOOLEAN)
        {
            auto timer = static_cast<windows_timer *>(context);
            timer->m_userFunc(timer->m_userContext);
        }

    #if defined(__cplusplus_winrt)
        Windows::System::Threading::ThreadPoolTimer ^ m_hTimer;
    #else
        HANDLE m_hTimer;
    #endif
        TaskProc_t m_userFunc;
        void * m_userContext;
    };

    _PPLXIMP void timer_impl::start(unsigned int ms, bool repeat, TaskProc_t userFunc, _In_ void * context)
    {
        _ASSERTE(m_timerImpl == nullptr);
        m_timerImpl = new windows_timer(userFunc, context);
        m_timerImpl->start(ms, repeat);
    }

    _PPLXIMP void timer_impl::stop(bool waitForCallbacks)
    {
        if (m_timerImpl != nullptr)
        {
            m_timerImpl->stop(waitForCallbacks);
            m_timerImpl = nullptr;
        }
    }

    //
    // scheduler implementation
    //
#if defined(__cplusplus_winrt)

    _PPLXIMP void windows_scheduler::schedule( TaskProc_t proc, _In_ void* param)
    {
        auto workItemHandler = ref new Windows::System::Threading::WorkItemHandler([proc, param](Windows::Foundation::IAsyncAction ^ )
        {
            proc(param);
        });

        Windows::System::Threading::ThreadPool::RunAsync(workItemHandler); 
    }
#else

    struct _Scheduler_Param
    {
        TaskProc_t m_proc;
        void * m_param;

        _Scheduler_Param(TaskProc_t proc, _In_ void * param)
            : m_proc(proc), m_param(param)
        {
        }

        static void CALLBACK DefaultWorkCallback(PTP_CALLBACK_INSTANCE, PVOID pContext, PTP_WORK)
        {
            auto schedulerParam = (_Scheduler_Param *)(pContext);

            schedulerParam->m_proc(schedulerParam->m_param);

            delete schedulerParam;
        }
    };

    _PPLXIMP void windows_scheduler::schedule( TaskProc_t proc, _In_ void* param)
    {
        auto schedulerParam = new _Scheduler_Param(proc, param);
        auto work = CreateThreadpoolWork(_Scheduler_Param::DefaultWorkCallback, schedulerParam, NULL);

        if (work == nullptr)
        {
            delete schedulerParam;
            throw utility::details::create_system_error(GetLastError());
        }

        SubmitThreadpoolWork(work);
        CloseThreadpoolWork(work);
    }

#endif
} // namespace details

} // namespace pplx
