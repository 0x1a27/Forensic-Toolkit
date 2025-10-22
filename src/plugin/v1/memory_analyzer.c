#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")  // 添加这行

// 插件接口函数
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[MEMORY] 内存分析插件初始化\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "memory|内存使用分析插件 - 分析进程内存使用情况";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("内存分析插件命令:\n");
    printf("  memory                  - 显示内存使用排行\n");
    printf("  memory -p <PID>         - 显示指定进程内存详情\n");
    printf("  memory -t               - 显示内存总量统计\n");
    printf("  memory -w               - 监控内存变化\n");
}

__declspec(dllexport) int ftk_plugin_execute(const char* args) {
    if (args == NULL || strlen(args) == 0) {
        return show_memory_usage();
    }
    
    if (strcmp(args, "-t") == 0) {
        return show_total_memory();
    }
    else if (strcmp(args, "-w") == 0) {
        return monitor_memory_changes();
    }
    else if (strncmp(args, "-p ", 3) == 0) {
        DWORD pid = atoi(args + 3);
        if (pid > 0) {
            return show_process_memory_details(pid);
        }
    }
    
    printf("[MEMORY] 未知参数: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// 显示内存使用排行
int show_memory_usage() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n=== 进程内存使用排行 ===\n\n");
    printf("%-8s %-40s %-12s %s\n", "PID", "进程名", "内存使用", "工作集");
    printf("------------------------------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess != NULL) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    printf("%-8lu %-40s %-12.2fMB %-12.2fMB\n", 
                           pe.th32ProcessID,
                           pe.szExeFile,
                           (double)pmc.PagefileUsage / (1024 * 1024),
                           (double)pmc.WorkingSetSize / (1024 * 1024));
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

// 显示内存总量统计
int show_total_memory() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    
    if (GlobalMemoryStatusEx(&statex)) {
        printf("\n=== 系统内存统计 ===\n\n");
        printf("物理内存总量: %.2f GB\n", (double)statex.ullTotalPhys / (1024 * 1024 * 1024));
        printf("可用物理内存: %.2f GB\n", (double)statex.ullAvailPhys / (1024 * 1024 * 1024));
        printf("内存使用率: %ld%%\n", statex.dwMemoryLoad);
        printf("虚拟内存总量: %.2f GB\n", (double)statex.ullTotalPageFile / (1024 * 1024 * 1024));
        printf("可用虚拟内存: %.2f GB\n", (double)statex.ullAvailPageFile / (1024 * 1024 * 1024));
    }
    
    return 0;
}

// 监控内存变化
int monitor_memory_changes() {
    printf("\n=== 内存变化监控 ===\n");
    printf("按ESC键退出监控...\n\n");
    
    int count = 0;
    while (1) {
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            break;
        }
        
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        
        if (GlobalMemoryStatusEx(&statex)) {
            printf("[%d] 内存使用率: %ld%% | 可用物理内存: %.2f GB\r", 
                   ++count,
                   statex.dwMemoryLoad,
                   (double)statex.ullAvailPhys / (1024 * 1024 * 1024));
        }
        
        Sleep(2000);
    }
    
    printf("\n[INFO] 退出内存监控\n");
    return 0;
}

// 显示进程内存详情
int show_process_memory_details(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] 无法打开进程 PID=%lu\n", pid);
        return 1;
    }
    
    // 获取进程名
    char process_name[MAX_PATH] = "未知";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    strcpy_s(process_name, sizeof(process_name), pe.szExeFile);
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        printf("\n=== 进程 %lu 内存详情 ===\n\n", pid);
        printf("进程名: %s\n", process_name);
        printf("页面文件使用: %.2f MB\n", (double)pmc.PagefileUsage / (1024 * 1024));
        printf("峰值页面文件: %.2f MB\n", (double)pmc.PeakPagefileUsage / (1024 * 1024));
        printf("工作集大小: %.2f MB\n", (double)pmc.WorkingSetSize / (1024 * 1024));
        printf("峰值工作集: %.2f MB\n", (double)pmc.PeakWorkingSetSize / (1024 * 1024));
        printf("分页池使用: %.2f MB\n", (double)pmc.QuotaPagedPoolUsage / (1024 * 1024));
        printf("非分页池使用: %.2f MB\n", (double)pmc.QuotaNonPagedPoolUsage / (1024 * 1024));
    }
    
    CloseHandle(hProcess);
    return 0;
}