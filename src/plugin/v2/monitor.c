#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <time.h>
#include <conio.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// 监控数据结构
typedef struct {
    DWORD pid;
    char name[MAX_PATH];
    FILETIME create_time;
    SIZE_T memory_usage;
    DWORD thread_count;
    int is_new;
    int is_terminated;
} MonitorProcess;

static MonitorProcess g_previous_processes[1024];
static int g_previous_count = 0;
static volatile int g_monitoring = 0;

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[MONITOR] 进程监控插件初始化\n");
    return 0;
}

// 获取当前进程列表
int get_current_processes(MonitorProcess* processes, int max_count) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照 (错误: %lu)\n", GetLastError());
        return 0;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    int count = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (count < max_count) {
                processes[count].pid = pe.th32ProcessID;
                strncpy_s(processes[count].name, MAX_PATH, pe.szExeFile, _TRUNCATE);
                processes[count].thread_count = pe.cntThreads;
                processes[count].is_new = 0;
                processes[count].is_terminated = 0;
                
                // 获取内存信息
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        processes[count].memory_usage = pmc.WorkingSetSize;
                    }
                    
                    // 获取创建时间
                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        processes[count].create_time = createTime;
                    }
                    
                    CloseHandle(hProcess);
                } else {
                    processes[count].memory_usage = 0;
                }
                count++;
            }
        } while (Process32Next(hSnapshot, &pe) && count < max_count);
    }
    
    CloseHandle(hSnapshot);
    return count;
}

// 比较进程变化
void compare_process_changes(MonitorProcess* current, int current_count, 
                           MonitorProcess* previous, int previous_count) {
    int new_count = 0;
    int terminated_count = 0;
    
    // 检查新进程
    for (int i = 0; i < current_count; i++) {
        int found = 0;
        for (int j = 0; j < previous_count; j++) {
            if (current[i].pid == previous[j].pid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            current[i].is_new = 1;
            new_count++;
        }
    }
    
    // 检查终止的进程
    for (int i = 0; i < previous_count; i++) {
        int found = 0;
        for (int j = 0; j < current_count; j++) {
            if (previous[i].pid == current[j].pid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            previous[i].is_terminated = 1;
            terminated_count++;
        }
    }
    
    // 显示变化
    if (new_count > 0) {
        printf("\n[新进程] 发现 %d 个新进程:\n", new_count);
        for (int i = 0; i < current_count; i++) {
            if (current[i].is_new) {
                printf("  [+] PID: %-6lu | 进程: %s | 内存: %.2f MB\n", 
                       current[i].pid, current[i].name,
                       (double)current[i].memory_usage / (1024 * 1024));
            }
        }
    }
    
    if (terminated_count > 0) {
        printf("\n[终止进程] 发现 %d 个进程终止:\n", terminated_count);
        for (int i = 0; i < previous_count; i++) {
            if (previous[i].is_terminated) {
                printf("  [-] PID: %-6lu | 进程: %s\n", 
                       previous[i].pid, previous[i].name);
            }
        }
    }
    
    if (new_count == 0 && terminated_count == 0) {
        printf(".");
    } else {
        printf("\n");
    }
}

// 显示当前进程统计
void show_process_stats(MonitorProcess* processes, int count) {
    time_t now;
    time(&now);
    struct tm local_time;
    localtime_s(&local_time, &now);
    
    printf("\n[%02d:%02d:%02d] 当前进程数: %d", 
           local_time.tm_hour, local_time.tm_min, local_time.tm_sec, count);
    
    // 计算总内存使用
    SIZE_T total_memory = 0;
    for (int i = 0; i < count; i++) {
        total_memory += processes[i].memory_usage;
    }
    
    printf(" | 总内存: %.2f MB", (double)total_memory / (1024 * 1024));
}

// 检查键盘输入（非阻塞）
int check_keyboard() {
    return _kbhit();
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    int interval = 3; // 默认3秒
    
    if (args && strlen(args) > 0) {
        interval = atoi(args);
        if (interval <= 0) interval = 3;
        if (interval > 60) interval = 60; // 最大60秒
    }
    
    printf("[MONITOR] 启动实时进程监控\n");
    printf("监控间隔: %d秒\n", interval);
    printf("按 'q' 键停止监控\n");
    printf("按 's' 键显示当前进程统计\n");
    printf("===============================================\n");
    
    // 获取初始进程列表
    g_previous_count = get_current_processes(g_previous_processes, 1024);
    printf("初始进程数: %d\n", g_previous_count);
    
    g_monitoring = 1;
    int cycle = 0;
    
    while (g_monitoring) {
        MonitorProcess current_processes[1024];
        int current_count = get_current_processes(current_processes, 1024);
        
        if (current_count > 0) {
            if (cycle > 0) {
                compare_process_changes(current_processes, current_count, 
                                      g_previous_processes, g_previous_count);
            }
            
            // 保存当前状态
            memcpy(g_previous_processes, current_processes, sizeof(MonitorProcess) * current_count);
            g_previous_count = current_count;
        }
        
        cycle++;
        
        // 检查键盘输入
        int wait_count = interval * 10; // 将秒转换为100ms间隔
        for (int i = 0; i < wait_count && g_monitoring; i++) {
            Sleep(100); // 每100ms检查一次
            
            if (check_keyboard()) {
                int ch = _getch();
                if (ch == 'q' || ch == 'Q') {
                    g_monitoring = 0;
                    printf("\n[INFO] 用户请求停止监控\n");
                    break;
                } else if (ch == 's' || ch == 'S') {
                    show_process_stats(current_processes, current_count);
                }
            }
        }
    }
    
    printf("\n[MONITOR] 监控结束，共运行 %d 个周期\n", cycle);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("进程监控插件帮助:\n");
    printf("  功能: 实时监控进程创建和终止\n");
    printf("  用法: monitor [间隔秒数]\n");
    printf("  参数: 间隔秒数 - 监控间隔，默认3秒，最大60秒\n");
    printf("  示例: monitor 5    - 每5秒监控一次\n");
    printf("         monitor     - 使用默认3秒间隔\n");
    printf("  控制: q - 停止监控\n");
    printf("         s - 显示当前统计\n");
    printf("  输出: 显示新创建的进程和终止的进程\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "monitor|实时进程监控插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}