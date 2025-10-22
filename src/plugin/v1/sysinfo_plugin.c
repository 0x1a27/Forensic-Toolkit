#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <iphlpapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== ϵͳ��Ϣ���� ===\n\n");
    
    // ����ϵͳ��Ϣ
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    if (GetVersionExA((OSVERSIONINFOA*)&osvi)) {
        printf("����ϵͳ: Windows %lu.%lu\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
        printf("�����汾: %lu\n", osvi.dwBuildNumber);
        printf("�����: %s\n", osvi.szCSDVersion);
    }
    
    // ���������
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        printf("�������: %s\n", computerName);
    }
    
    // �û���
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    if (GetUserNameA(userName, &userNameSize)) {
        printf("��ǰ�û�: %s\n", userName);
    }
    
    // ϵͳĿ¼
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, sizeof(systemDir));
    printf("ϵͳĿ¼: %s\n", systemDir);
    
    // �ڴ���Ϣ
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        printf("\n=== �ڴ���Ϣ ===\n");
        printf("�����ڴ�����: %.2f GB\n", (double)memStatus.ullTotalPhys / (1024*1024*1024));
        printf("���������ڴ�: %.2f GB\n", (double)memStatus.ullAvailPhys / (1024*1024*1024));
        printf("�ڴ�ʹ����: %lu%%\n", memStatus.dwMemoryLoad);
        printf("�����ڴ�����: %.2f GB\n", (double)memStatus.ullTotalVirtual / (1024*1024*1024));
        printf("���������ڴ�: %.2f GB\n", (double)memStatus.ullAvailVirtual / (1024*1024*1024));
    }
    
    // CPU��Ϣ
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("\n=== CPU��Ϣ ===\n");
    printf("�������ܹ�: ");
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            printf("x64\n"); break;
        case PROCESSOR_ARCHITECTURE_ARM:
            printf("ARM\n"); break;
        case PROCESSOR_ARCHITECTURE_IA64:
            printf("Itanium\n"); break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            printf("x86\n"); break;
        default:
            printf("δ֪\n");
    }
    printf("����������: %lu\n", sysInfo.dwNumberOfProcessors);
    printf("ҳ���С: %lu KB\n", sysInfo.dwPageSize / 1024);
    
    // ������Ϣ
    printf("\n=== ������Ϣ ===\n");
    DWORD drives = GetLogicalDrives();
    char drive[] = "A:\\";
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            drive[0] = 'A' + i;
            UINT type = GetDriveTypeA(drive);
            
            const char* typeStr;
            switch (type) {
                case DRIVE_FIXED: typeStr = "���ش���"; break;
                case DRIVE_REMOVABLE: typeStr = "���ƶ�����"; break;
                case DRIVE_CDROM: typeStr = "����������"; break;
                case DRIVE_REMOTE: typeStr = "����������"; break;
                case DRIVE_RAMDISK: typeStr = "RAM����"; break;
                default: typeStr = "δ֪����";
            }
            
            ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceExA(drive, &freeBytes, &totalBytes, &totalFreeBytes)) {
                printf("������ %s [%s] ����: %.2f GB, ����: %.2f GB\n", 
                       drive, typeStr,
                       (double)totalBytes.QuadPart / (1024*1024*1024),
                       (double)freeBytes.QuadPart / (1024*1024*1024));
            } else {
                printf("������ %s [%s] (�޷���ȡ�ռ���Ϣ)\n", drive, typeStr);
            }
        }
    }
    
    // ϵͳ����ʱ��
    DWORD uptime = GetTickCount() / 1000;
    printf("\nϵͳ����ʱ��: %lu�� %luСʱ %lu����\n", 
           uptime / 86400, (uptime % 86400) / 3600, (uptime % 3600) / 60);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("ϵͳ��Ϣ�������:\n");
    printf("  ����: ��ʾ��ϸ��ϵͳӲ���������Ϣ\n");
    printf("  �÷�: sysinfo\n");
    printf("  ���: ����ϵͳ��Ϣ���ڴ桢CPU�����̡������\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "sysinfo|ϵͳ��Ϣ�������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}