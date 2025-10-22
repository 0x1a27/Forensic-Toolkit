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
    printf("\n=== 系统信息分析 ===\n\n");
    
    // 操作系统信息
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    if (GetVersionExA((OSVERSIONINFOA*)&osvi)) {
        printf("操作系统: Windows %lu.%lu\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
        printf("构建版本: %lu\n", osvi.dwBuildNumber);
        printf("服务包: %s\n", osvi.szCSDVersion);
    }
    
    // 计算机名称
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        printf("计算机名: %s\n", computerName);
    }
    
    // 用户名
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    if (GetUserNameA(userName, &userNameSize)) {
        printf("当前用户: %s\n", userName);
    }
    
    // 系统目录
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, sizeof(systemDir));
    printf("系统目录: %s\n", systemDir);
    
    // 内存信息
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        printf("\n=== 内存信息 ===\n");
        printf("物理内存总量: %.2f GB\n", (double)memStatus.ullTotalPhys / (1024*1024*1024));
        printf("可用物理内存: %.2f GB\n", (double)memStatus.ullAvailPhys / (1024*1024*1024));
        printf("内存使用率: %lu%%\n", memStatus.dwMemoryLoad);
        printf("虚拟内存总量: %.2f GB\n", (double)memStatus.ullTotalVirtual / (1024*1024*1024));
        printf("可用虚拟内存: %.2f GB\n", (double)memStatus.ullAvailVirtual / (1024*1024*1024));
    }
    
    // CPU信息
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("\n=== CPU信息 ===\n");
    printf("处理器架构: ");
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
            printf("未知\n");
    }
    printf("处理器数量: %lu\n", sysInfo.dwNumberOfProcessors);
    printf("页面大小: %lu KB\n", sysInfo.dwPageSize / 1024);
    
    // 磁盘信息
    printf("\n=== 磁盘信息 ===\n");
    DWORD drives = GetLogicalDrives();
    char drive[] = "A:\\";
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            drive[0] = 'A' + i;
            UINT type = GetDriveTypeA(drive);
            
            const char* typeStr;
            switch (type) {
                case DRIVE_FIXED: typeStr = "本地磁盘"; break;
                case DRIVE_REMOVABLE: typeStr = "可移动磁盘"; break;
                case DRIVE_CDROM: typeStr = "光盘驱动器"; break;
                case DRIVE_REMOTE: typeStr = "网络驱动器"; break;
                case DRIVE_RAMDISK: typeStr = "RAM磁盘"; break;
                default: typeStr = "未知类型";
            }
            
            ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceExA(drive, &freeBytes, &totalBytes, &totalFreeBytes)) {
                printf("驱动器 %s [%s] 总量: %.2f GB, 可用: %.2f GB\n", 
                       drive, typeStr,
                       (double)totalBytes.QuadPart / (1024*1024*1024),
                       (double)freeBytes.QuadPart / (1024*1024*1024));
            } else {
                printf("驱动器 %s [%s] (无法获取空间信息)\n", drive, typeStr);
            }
        }
    }
    
    // 系统运行时间
    DWORD uptime = GetTickCount() / 1000;
    printf("\n系统运行时间: %lu天 %lu小时 %lu分钟\n", 
           uptime / 86400, (uptime % 86400) / 3600, (uptime % 3600) / 60);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("系统信息插件帮助:\n");
    printf("  功能: 显示详细的系统硬件和软件信息\n");
    printf("  用法: sysinfo\n");
    printf("  输出: 操作系统信息、内存、CPU、磁盘、网络等\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "sysinfo|系统信息分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}