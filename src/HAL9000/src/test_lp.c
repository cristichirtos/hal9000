#include "test_common.h"
#include "test_thread.h"
#include "test_lp.h"
#include "mutex.h"
#include "thread_internal.h"

static volatile DWORD gNumberOfThreads = 0;

STATUS
(__cdecl _ThreadLpTest)(
	IN_OPT		PVOID		 Context
	)
{
	int numberOfChildren = (int*)Context;
	int i; 

	for (i = 0; i < numberOfChildren; i++)
	{
		PTHREAD thread;
		char thName[MAX_PATH];
		snprintf(thName, MAX_PATH, "ThreadLp-%d", _InterlockedIncrement(&gNumberOfThreads));

		STATUS status = ThreadCreate(thName, ThreadPriorityDefault, _ThreadLpTest, numberOfChildren - 1, &thread);

		if (!SUCCEEDED(status))
		{
			LOG_FUNC_ERROR("ThreadCreate", status);
		}
		else
		{
			ThreadWaitForTermination(thread, &status);
			ThreadCloseHandle(thread);
		}
	}
}