#include "globals.h"

/***************    memory.h      ******************/

typedef enum _KULL_M_MEMORY_TYPE
{
	KULL_M_MEMORY_TYPE_OWN,
	KULL_M_MEMORY_TYPE_PROCESS,
	KULL_M_MEMORY_TYPE_PROCESS_DMP,
	KULL_M_MEMORY_TYPE_KERNEL,
	KULL_M_MEMORY_TYPE_KERNEL_DMP,
	KULL_M_MEMORY_TYPE_HYBERFILE,
	KULL_M_MEMORY_TYPE_FILE,
} KULL_M_MEMORY_TYPE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS
{
	HANDLE hProcess;
} KULL_M_MEMORY_HANDLE_PROCESS, * PKULL_M_MEMORY_HANDLE_PROCESS;

typedef struct _KULL_M_MEMORY_HANDLE_FILE
{
	HANDLE hFile;
} KULL_M_MEMORY_HANDLE_FILE, * PKULL_M_MEMORY_HANDLE_FILE;

typedef struct _KULL_M_MINIDUMP_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
} KULL_M_MINIDUMP_HANDLE, * PKULL_M_MINIDUMP_HANDLE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS_DMP
{
	PKULL_M_MINIDUMP_HANDLE hMinidump;
} KULL_M_MEMORY_HANDLE_PROCESS_DMP, * PKULL_M_MEMORY_HANDLE_PROCESS_DMP;

typedef struct _KULL_M_MEMORY_HANDLE_KERNEL
{
	HANDLE hDriver;
} KULL_M_MEMORY_HANDLE_KERNEL, * PKULL_M_MEMORY_HANDLE_KERNEL;

typedef struct _KULL_M_MEMORY_HANDLE {
	KULL_M_MEMORY_TYPE type;
	union {
		PKULL_M_MEMORY_HANDLE_PROCESS pHandleProcess;
		PKULL_M_MEMORY_HANDLE_FILE pHandleFile;
		PKULL_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
		PKULL_M_MEMORY_HANDLE_KERNEL pHandleDriver;
	};
} KULL_M_MEMORY_HANDLE, * PKULL_M_MEMORY_HANDLE;

typedef struct _KULL_M_MEMORY_ADDRESS {
	LPVOID address;
	PKULL_M_MEMORY_HANDLE hMemory;
} KULL_M_MEMORY_ADDRESS, * PKULL_M_MEMORY_ADDRESS;



typedef struct _KULL_M_MEMORY_RANGE {
	KULL_M_MEMORY_ADDRESS kull_m_memoryAdress;
	SIZE_T size;
} KULL_M_MEMORY_RANGE, * PKULL_M_MEMORY_RANGE;
typedef struct _KULL_M_MEMORY_SEARCH {
	KULL_M_MEMORY_RANGE kull_m_memoryRange;
	LPVOID result;
} KULL_M_MEMORY_SEARCH, * PKULL_M_MEMORY_SEARCH;


/***************    memory.h     end ******************/
/***************	process.h     end ******************/

typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
	KULL_M_MEMORY_ADDRESS DllBase;
	ULONG SizeOfImage;
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, * PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
typedef struct _LSA_UNICODE_STRING_F32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD  Buffer;
} LSA_UNICODE_STRING_F32, * PLSA_UNICODE_STRING_F32;

typedef LSA_UNICODE_STRING_F32 UNICODE_STRING_F32, * PUNICODE_STRING_F32;

typedef struct _LDR_DATA_TABLE_ENTRY_F32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	DWORD DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING_F32 FullDllName;
	UNICODE_STRING_F32 BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY_F32, * PLDR_DATA_TABLE_ENTRY_F32;

typedef struct _PEB_LDR_DATA_F32 {
	ULONG Length;
	BOOLEAN Initialized;
	DWORD SsHandle;
	LIST_ENTRY32 InLoadOrderModulevector;
	LIST_ENTRY32 InMemoryOrderModulevector;
	LIST_ENTRY32 InInitializationOrderModulevector;
} PEB_LDR_DATA_F32, * PPEB_LDR_DATA_F32;

typedef struct _PEB_F32 {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField_F32 {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	DWORD Mutant;
	DWORD ImageBaseAddress;
	DWORD Ldr;
	/// ...
} PEB_F32, * PPEB_F32;
#endif

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModulevector;
	LIST_ENTRY InMemoryOrderModulevector;
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	/// ...
} PEB, * PPEB;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,		  // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass			 // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef LONG KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
/***************    process.h     end ******************/
/***************    process.h     end ******************/
typedef struct _KUHL_M_SEKURLSA_OS_CONTEXT {
	DWORD MajorVersion;
	DWORD MinorVersion;
	DWORD BuildNumber;
} KUHL_M_SEKURLSA_OS_CONTEXT, * PKUHL_M_SEKURLSA_OS_CONTEXT;

typedef struct _KUHL_M_SEKURLSA_CONTEXT {
	PKULL_M_MEMORY_HANDLE hLsassMem;
	KUHL_M_SEKURLSA_OS_CONTEXT osContext;
} KUHL_M_SEKURLSA_CONTEXT, * PKUHL_M_SEKURLSA_CONTEXT;
typedef NTSTATUS(*PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS) (PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
typedef NTSTATUS(*PKUHL_M_SEKURLSA_INIT) ();

typedef struct _KUHL_M_SEKURLSA_LOCAL_HELPER {
	PKUHL_M_SEKURLSA_INIT initLocalLib;
	PKUHL_M_SEKURLSA_INIT cleanLocalLib;
	PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS AcquireKeys;
	const PLSA_PROTECT_MEMORY* pLsaProtectMemory;
	const PLSA_PROTECT_MEMORY* pLsaUnprotectMemory;
} KUHL_M_SEKURLSA_LOCAL_HELPER, * PKUHL_M_SEKURLSA_LOCAL_HELPER;
typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
	PKUHL_M_SEKURLSA_CONTEXT	cLsass;
	const KUHL_M_SEKURLSA_LOCAL_HELPER* lsassLocalHelper;
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, * PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;
typedef void (CALLBACK* PKUHL_M_SEKURLSA_ENUM_LOGONDATA) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KUHL_M_SEKURLSA_LIB {
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION Informations;
	BOOL isPresent;
	BOOL isInit;
} KUHL_M_SEKURLSA_LIB, * PKUHL_M_SEKURLSA_LIB;

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const wchar_t* Name;
	PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;  //回调函数，用于存储得到的数据信息
	BOOL isValid;
	const wchar_t* ModuleName;
	KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, * PKUHL_M_SEKURLSA_PACKAGE;


/***************    process.h     end ******************/


typedef NTSTATUS(WINAPI* PFUN_NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

/***************    patch.h     start ******************/
typedef struct _KULL_M_PATCH_PATTERN {
	DWORD Length;
	BYTE* Pattern;
} KULL_M_PATCH_PATTERN, * PKULL_M_PATCH_PATTERN;


typedef struct _KULL_M_PATCH_OFFSETS {
	LONG off0;
#if defined(_M_ARM64)
	LONG armOff0;
#endif
	LONG off1;
#if defined(_M_ARM64)
	LONG armOff1;
#endif
	LONG off2;
#if defined(_M_ARM64)
	LONG armOff2;
#endif
	LONG off3;
#if defined(_M_ARM64)
	LONG armOff3;
#endif
	LONG off4;
#if defined(_M_ARM64)
	LONG armOff4;
#endif
	LONG off5;
#if defined(_M_ARM64)
	LONG armOff5;
#endif
	LONG off6;
#if defined(_M_ARM64)
	LONG armOff6;
#endif
	LONG off7;
#if defined(_M_ARM64)
	LONG armOff7;
#endif
	LONG off8;
#if defined(_M_ARM64)
	LONG armOff8;
#endif
	LONG off9;
#if defined(_M_ARM64)
	LONG armOff9;
#endif
} KULL_M_PATCH_OFFSETS, * PKULL_M_PATCH_OFFSETS;

typedef struct _KULL_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	KULL_M_PATCH_OFFSETS Offsets;
} KULL_M_PATCH_GENERIC, * PKULL_M_PATCH_GENERIC;


/*************  nt6 *************/
typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, * PKIWI_BCRYPT_GEN_KEY;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;
typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, * PKIWI_BCRYPT_KEY;
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, * PKIWI_BCRYPT_KEY8;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;
/*************  nt6 *************/

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, * PKUHL_M_SEKURLSA_ENUM_HELPER;


typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS* next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, * PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS* next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, * PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63* Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63* Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;