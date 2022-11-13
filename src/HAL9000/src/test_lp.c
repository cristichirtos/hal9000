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
	int numberOfChildren = *((int*) Context);
	int i;

	PTHREAD* children = (PTHREAD*) ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(PTHREAD) * numberOfChildren , HEAP_THREAD_TAG, 0);


	for (i = 0; i < numberOfChildren; i++)
	{
		char thName[MAX_PATH];
		unsigned long long nextNumberOfChildren = numberOfChildren - 1;
		snprintf(thName, MAX_PATH, "ThreadLp-%d", _InterlockedIncrement(&gNumberOfThreads));

		STATUS status = ThreadCreate(thName, ThreadPriorityDefault, _ThreadLpTest, (PVOID) &nextNumberOfChildren, &children[i]);

		if (!SUCCEEDED(status))
		{
			LOG_FUNC_ERROR("ThreadCreate", status);
		}
	}

	for (i = 0; i < numberOfChildren; i++)
	{
		STATUS exitStatus;
		ThreadWaitForTermination(children[i], &exitStatus);
		ThreadCloseHandle(children[i]);
	}

	return STATUS_SUCCESS;
}