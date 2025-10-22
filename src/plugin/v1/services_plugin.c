#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "advapi32.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== Windows服务分析 ===\n\n");
    
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        printf("[ERROR] 无法打开服务控制管理器 (错误: %lu)\n", GetLastError());
        return -1;
    }
    
    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;
    
    // 第一次调用获取所需缓冲区大小
    EnumServicesStatusExA(
        scManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        NULL,
        0,
        &bytesNeeded,
        &serviceCount,
        &resumeHandle,
        NULL
    );
    
    if (GetLastError() != ERROR_MORE_DATA) {
        printf("[ERROR] 枚举服务失败\n");
        CloseServiceHandle(scManager);
        return -1;
    }
    
    // 分配缓冲区
    BYTE* buffer = (BYTE*)malloc(bytesNeeded);
    if (!buffer) {
        printf("[ERROR] 内存分配失败\n");
        CloseServiceHandle(scManager);
        return -1;
    }
    
    ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;
    
    // 第二次调用获取服务信息
    if (EnumServicesStatusExA(
        scManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        buffer,
        bytesNeeded,
        &bytesNeeded,
        &serviceCount,
        &resumeHandle,
        NULL)) {
        
        printf("%-40s %-15s %-10s %s\n", "服务名称", "显示名称", "状态", "类型");
        printf("----------------------------------------------------------------------------------------\n");
        
        for (DWORD i = 0; i < serviceCount && i < 50; i++) { // 限制显示数量
            const char* state;
            switch (services[i].ServiceStatusProcess.dwCurrentState) {
                case SERVICE_STOPPED: state = "已停止"; break;
                case SERVICE_START_PENDING: state = "启动中"; break;
                case SERVICE_STOP_PENDING: state = "停止中"; break;
                case SERVICE_RUNNING: state = "运行中"; break;
                case SERVICE_CONTINUE_PENDING: state = "继续中"; break;
                case SERVICE_PAUSE_PENDING: state = "暂停中"; break;
                case SERVICE_PAUSED: state = "已暂停"; break;
                default: state = "未知";
            }
            
            const char* type;
            switch (services[i].ServiceStatusProcess.dwServiceType) {
                case SERVICE_FILE_SYSTEM_DRIVER: type = "文件系统驱动"; break;
                case SERVICE_KERNEL_DRIVER: type = "内核驱动"; break;
                case SERVICE_WIN32_OWN_PROCESS: type = "独立进程"; break;
                case SERVICE_WIN32_SHARE_PROCESS: type = "共享进程"; break;
                default: type = "其他";
            }
            
            printf("%-40s %-15s %-10s %s\n", 
                   services[i].lpServiceName,
                   services[i].lpDisplayName,
                   state,
                   type);
        }
        
        printf("\n总共发现 %lu 个服务 (显示前50个)\n", serviceCount);
    }
    
    free(buffer);
    CloseServiceHandle(scManager);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("服务管理插件帮助:\n");
    printf("  功能: 枚举和分析Windows服务\n");
    printf("  用法: services\n");
    printf("  输出: 所有服务的名称、状态、类型等信息\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "services|Windows服务分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}