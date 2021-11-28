#include "header/globals.h"
#include "header/process.h"
/**
* 寻找基址函数
*/
//BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
//{
//	BOOL status = FALSE;
//	PROCESS_BASIC_INFORMATION processInformations;
//	HANDLE hProcess = (memory->type == KULL_M_MEMORY_TYPE_PROCESS) ? memory->pHandleProcess->hProcess : GetCurrentProcess();
//	KULL_M_MEMORY_ADDRESS aBuffer = { pPeb, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
//	KULL_M_MEMORY_ADDRESS aProcess = { NULL, memory };
//	PROCESSINFOCLASS info;
//	ULONG szPeb, szBuffer, szInfos;
//	LPVOID buffer;
//
//#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
//	if (isWOW)
//	{
//		info = ProcessWow64Information;
//		szBuffer = sizeof(processInformations.PebBaseAddress);
//		buffer = &processInformations.PebBaseAddress;
//		szPeb = sizeof(PEB_F32);
//	}
//	else
//	{
//#endif
//		info = ProcessBasicInformation;
//		szBuffer = sizeof(processInformations);
//		buffer = &processInformations;
//		szPeb = sizeof(PEB);
//#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
//	}
//#endif
//
//	switch (memory->type)
//	{
//#if !defined(MIMIKATZ_W2000_SUPPORT)
//	case KULL_M_MEMORY_TYPE_OWN:
//		if (!isWOW)
//		{
//			*pPeb = *RtlGetCurrentPeb();
//			status = TRUE;
//			break;
//		}
//#endif
//	case KULL_M_MEMORY_TYPE_PROCESS:
//		if (NT_SUCCESS(NtQueryInformationProcess(hProcess, info, buffer, szBuffer, &szInfos)) && (szInfos == szBuffer) && processInformations.PebBaseAddress)
//		{
//			aProcess.address = processInformations.PebBaseAddress;
//			status = kull_m_memory_copy(&aBuffer, &aProcess, szPeb);
//		}
//		break;
//	}
//	return status;
//}

/**
* 根据进程名获取pid:BOOL kull_m_process_getProcessIdForName(LPCWSTR name, PDWORD processId)
*/
VOID qureyProcessId(std::string name, DWORD* pid) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if ( std::string(entry.szExeFile) == name) {
				/**
				* 这个玩意好像可以直接返回打开的句柄
				*/
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				*pid = GetProcessId(hProcess);
				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
}


NTSTATUS kuhl_m_privilege_simple(ULONG privId)
{
	HMODULE hDll = ::LoadLibrary("ntdll.dll");
	typedef int (*type_RtlAdjustPrivilege)(int, bool, bool, int*);
	type_RtlAdjustPrivilege RtlAdjustPrivilege = (type_RtlAdjustPrivilege)GetProcAddress(hDll, "RtlAdjustPrivilege");
	int nEn = 0;
	NTSTATUS status = RtlAdjustPrivilege(privId, TRUE, FALSE, &nEn);
	if (NT_SUCCESS(status))
		printf_s("Privilege \'%u\' OK\n", privId);
	return status;
}


BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
{
	BOOL status = FALSE;
	PROCESS_BASIC_INFORMATION processInformations;
	HANDLE hProcess = (memory->type == KULL_M_MEMORY_TYPE_PROCESS) ? memory->pHandleProcess->hProcess : GetCurrentProcess();
	KULL_M_MEMORY_ADDRESS aBuffer = { pPeb, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_ADDRESS aProcess = { NULL, memory };
	PROCESSINFOCLASS info;
	ULONG szPeb, szBuffer, szInfos;
	LPVOID buffer;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	if (isWOW)
	{
		info = ProcessWow64Information;
		szBuffer = sizeof(processInformations.PebBaseAddress);
		buffer = &processInformations.PebBaseAddress;
		szPeb = sizeof(PEB_F32);
	}
	else
	{
#endif
		info = ProcessBasicInformation;
		szBuffer = sizeof(processInformations);
		buffer = &processInformations;
		szPeb = sizeof(PEB);
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	}
#endif


	switch (memory->type)
	{
	case KULL_M_MEMORY_TYPE_PROCESS:
		HMODULE hModule = LoadLibraryA("Ntdll.dll");
		PFUN_NtQueryInformationProcess pfun = (PFUN_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
		NTSTATUS a = pfun(hProcess, info, buffer, szBuffer, &szInfos);

		if ((szInfos == szBuffer) && processInformations.PebBaseAddress)
		{
			aProcess.address = processInformations.PebBaseAddress;
			status = kull_m_memory_copy(&aBuffer, &aProcess, szPeb);
		}
		break;
	}
	return status;
}


/**
* 配套回调函数，将结果存储:BOOL CALLBACK kull_m_process_callback_pidForName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
*/

/**
* 获取进程信息。NTSTATUS kull_m_process_getProcessInformation(PKULL_M_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg)
*/
