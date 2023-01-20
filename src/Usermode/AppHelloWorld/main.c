#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

FUNC_ThreadStart _HelloWorldFromThread;

STATUS
__main(
    DWORD       argc,
    char**      argv
    )
{
    STATUS status;
    TID tid;
   // UM_HANDLE umHandle;

    LOG("Hello from the Light Project application!\n");

    LOG("Number of arguments 0x%x\n", argc);
    LOG("Arguments at 0x%X\n", argv);

    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    char name[MAX_PATH];
    char copiedName[50];
    status = SyscallThreadGetName(name, MAX_PATH);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetName", status);
        return status;
    }

    QWORD threadNameLength = strlen_s(name, MAX_PATH);
    for (QWORD ThreadNameMaxLen = 0; ThreadNameMaxLen <= threadNameLength + 1; ++ThreadNameMaxLen)
    {
        status = SyscallThreadGetName(copiedName, ThreadNameMaxLen);
        if (!SUCCEEDED(status))
        {
            LOG(
                "[ID=%d][Name=%s] Thread name copying unsuccessful - name length is %d, while ThreadNameMaxLen is %d",
                tid,
                name,
                threadNameLength,
                ThreadNameMaxLen
            );
        }
        else
        {
            LOG("[ID=%d][Name=%s] Copied name: %s", tid, name, copiedName);
        }
    }

    QWORD threadsNo;
    status = SyscallGetTotalThreadNo(&threadsNo);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetTotalThreadNo", status);
        return status;
    }
    LOG("Current number of ready threads: %d", threadsNo);

    PVOID stackBaseAddress;
    status = SyscallGetThreadUmStackAddress(&stackBaseAddress);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadUmStackAddress", status);
        return status;
    }
    LOG("Main thread base address is located at 0x%X", stackBaseAddress);

    DWORD stackSize;
    status = SyscallGetThreadUmStackSize(&stackSize);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadUmStackSize", status);
        return status;
    }
    LOG("Main thread stack size: %d", stackSize);

    PVOID entryPoint;
    status = SyscallGetThreadUmEntryPoint(&entryPoint);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadUmEntryPoint", status);
        return status;
    }
    LOG("Process entry point: 0x%X", entryPoint);

    return STATUS_SUCCESS;
}

STATUS
(__cdecl _HelloWorldFromThread)(
    IN_OPT      PVOID       Context
    )
{
    STATUS status;
    TID tid;

    ASSERT(Context != NULL);

    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    LOG("Hello from thread with ID 0x%X\n", tid);
    LOG("Context is 0x%X\n", Context);

    return status;
}
