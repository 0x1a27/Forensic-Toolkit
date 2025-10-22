#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// 插件接口函数
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[NETWORK] 网络分析插件初始化\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "network|网络连接分析插件 - 显示进程网络连接信息";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("网络分析插件命令:\n");
    printf("  network                 - 显示所有网络连接\n");
    printf("  network -p <PID>        - 显示指定进程的网络连接\n");
    printf("  network -s              - 显示监听端口的进程\n");
    printf("  network -a              - 显示所有连接详细信息\n");
}

__declspec(dllexport) int ftk_plugin_execute(const char* args) {
    if (args == NULL || strlen(args) == 0) {
        return show_all_connections();
    }
    
    if (strcmp(args, "-s") == 0) {
        return show_listening_ports();
    }
    else if (strcmp(args, "-a") == 0) {
        return show_detailed_connections();
    }
    else if (strncmp(args, "-p ", 3) == 0) {
        DWORD pid = atoi(args + 3);
        if (pid > 0) {
            return show_process_connections(pid);
        }
    }
    
    printf("[NETWORK] 未知参数: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// 显示所有网络连接
int show_all_connections() {
    printf("\n=== TCP 网络连接 ===\n\n");
    printf("%-8s %-20s %-20s %-10s %s\n", 
           "PID", "本地地址", "远程地址", "状态", "进程名");
    printf("------------------------------------------------------------------------\n");
    
    // 使用系统命令获取网络连接信息（简化实现）
    system("netstat -ano | findstr TCP");
    
    printf("\n[INFO] 使用 'netstat -ano' 获取完整网络连接信息\n");
    return 0;
}

// 显示监听端口的进程
int show_listening_ports() {
    printf("\n=== 监听端口进程 ===\n\n");
    printf("%-8s %-20s %-10s %s\n", "PID", "本地地址", "状态", "进程名");
    printf("------------------------------------------------------------\n");
    
    // 使用系统命令获取监听端口信息
    system("netstat -ano | findstr LISTENING");
    
    printf("\n[INFO] 使用 'netstat -ano' 获取完整监听端口信息\n");
    return 0;
}

// 显示详细连接信息
int show_detailed_connections() {
    printf("\n=== 详细网络连接信息 ===\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n正在运行的网络相关进程:\n");
    printf("%-8s %-40s\n", "PID", "进程名");
    printf("----------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            // 检查是否为常见的网络相关进程
            const char* network_processes[] = {
                "svchost.exe", "lsass.exe", "services.exe", 
                "spoolsv.exe", "winlogon.exe", "explorer.exe"
            };
            
            for (int i = 0; i < 6; i++) {
                if (_stricmp(pe.szExeFile, network_processes[i]) == 0) {
                    printf("%-8lu %-40s\n", pe.th32ProcessID, pe.szExeFile);
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    
    printf("\n[INFO] 详细网络分析功能需要管理员权限\n");
    return 0;
}

// 显示指定进程的网络连接
int show_process_connections(DWORD pid) {
    printf("\n=== 进程 %lu 的网络连接信息 ===\n\n", pid);
    
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
    
    printf("进程名: %s\n", process_name);
    printf("PID: %lu\n", pid);
    
    // 使用系统命令检查该进程的网络连接
    char command[256];
    sprintf_s(command, sizeof(command), "netstat -ano | findstr %lu", pid);
    printf("\n网络连接:\n");
    system(command);
    
    return 0;
}