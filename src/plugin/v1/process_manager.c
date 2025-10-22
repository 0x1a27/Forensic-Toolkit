#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")

// 插件接口函数
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[PROCESS] 进程管理插件初始化\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "process|进程管理插件 - 终止、挂起、恢复和创建进程";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("进程管理插件命令:\n");
    printf("  process                 - 显示进程管理帮助\n");
    printf("  process list            - 列出所有进程\n");
    printf("  process kill <PID>      - 终止指定PID的进程\n");
    printf("  process killname <名称> - 通过进程名终止进程\n");
    printf("  process suspend <PID>   - 挂起指定PID的进程\n");
    printf("  process resume <PID>    - 恢复指定PID的进程\n");
    printf("  process create <路径>   - 创建新进程\n");
    printf("  process find <名称>     - 查找进程\n");
    printf("  process priority <PID> <级别> - 设置进程优先级\n");
    printf("\n优先级级别: idle(低), normal(普通), high(高), realtime(实时)\n");
}

__declspec(dllexport) int ftk_plugin_execute(const char* args) {
    if (args == NULL || strlen(args) == 0) {
        // 直接显示帮助内容，而不是交互式菜单
        ftk_plugin_help();
        return 0;
    }
    
    if (strcmp(args, "list") == 0) {
        return list_all_processes();
    }
    else if (strncmp(args, "kill ", 5) == 0) {
        DWORD pid = atoi(args + 5);
        if (pid > 0) {
            return kill_process(pid);
        } else {
            printf("[ERROR] 无效的进程ID\n");
            return 1;
        }
    }
    else if (strncmp(args, "killname ", 9) == 0) {
        return kill_process_by_name(args + 9);
    }
    else if (strncmp(args, "suspend ", 8) == 0) {
        DWORD pid = atoi(args + 8);
        if (pid > 0) {
            return suspend_process(pid);
        } else {
            printf("[ERROR] 无效的进程ID\n");
            return 1;
        }
    }
    else if (strncmp(args, "resume ", 7) == 0) {
        DWORD pid = atoi(args + 7);
        if (pid > 0) {
            return resume_process(pid);
        } else {
            printf("[ERROR] 无效的进程ID\n");
            return 1;
        }
    }
    else if (strncmp(args, "create ", 7) == 0) {
        return create_process(args + 7);
    }
    else if (strncmp(args, "find ", 5) == 0) {
        return find_process(args + 5);
    }
    else if (strncmp(args, "priority ", 9) == 0) {
        DWORD pid = atoi(args + 9);
        char* rest = strchr(args + 9, ' ');
        if (rest != NULL && pid > 0) {
            return set_process_priority(pid, rest + 1);
        } else {
            printf("[ERROR] 无效的参数格式\n");
            return 1;
        }
    }
    
    printf("[ERROR] 未知参数: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// 显示进程管理菜单（现在直接显示帮助）
int show_process_menu() {
    ftk_plugin_help();
    return 0;
}

// 列出所有进程
int list_all_processes() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n%-8s %-6s %-40s %-12s\n", "PID", "父PID", "进程名", "线程数");
    printf("------------------------------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            printf("%-8lu %-6lu %-40s %-12lu\n", 
                   pe.th32ProcessID,
                   pe.th32ParentProcessID,
                   pe.szExeFile,
                   pe.cntThreads);
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    printf("\n[INFO] 使用 'process kill <PID>' 终止进程\n");
    return 0;
}

// 终止进程
int kill_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] 不能终止自身进程\n");
        return 1;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] 无法打开进程 PID=%lu (错误: %lu)\n", pid, GetLastError());
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
    
    printf("[WARNING] 即将终止进程: %s (PID: %lu)\n", process_name, pid);
    printf("确认终止? (y/N): ");
    
    char confirm[10];
    if (fgets(confirm, sizeof(confirm), stdin) != NULL && 
        (confirm[0] == 'y' || confirm[0] == 'Y')) {
        
        if (TerminateProcess(hProcess, 0)) {
            printf("[SUCCESS] 成功终止进程: %s (PID: %lu)\n", process_name, pid);
            CloseHandle(hProcess);
            return 0;
        } else {
            printf("[ERROR] 终止进程失败 (错误: %lu)\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }
    } else {
        printf("[INFO] 操作已取消\n");
        CloseHandle(hProcess);
        return 0;
    }
}

// 通过进程名终止进程
int kill_process_by_name(const char* process_name) {
    DWORD pid = find_pid_by_name(process_name);
    if (pid != 0) {
        return kill_process(pid);
    } else {
        printf("[ERROR] 未找到进程: %s\n", process_name);
        return 1;
    }
}

// 挂起进程
int suspend_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] 不能挂起自身进程\n");
        return 1;
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建线程快照\n");
        return 1;
    }
    
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    
    int suspended_count = 0;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread != NULL) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                    suspended_count++;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    if (suspended_count > 0) {
        printf("[SUCCESS] 成功挂起进程 PID=%lu 的 %d 个线程\n", pid, suspended_count);
        return 0;
    } else {
        printf("[ERROR] 无法挂起进程 PID=%lu\n", pid);
        return 1;
    }
}

// 恢复进程
int resume_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] 不能恢复自身进程\n");
        return 1;
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建线程快照\n");
        return 1;
    }
    
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    
    int resumed_count = 0;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread != NULL) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    resumed_count++;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    if (resumed_count > 0) {
        printf("[SUCCESS] 成功恢复进程 PID=%lu 的 %d 个线程\n", pid, resumed_count);
        return 0;
    } else {
        printf("[ERROR] 无法恢复进程 PID=%lu\n", pid);
        return 1;
    }
}

// 创建新进程
int create_process(const char* process_path) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd_line[MAX_PATH];
    strcpy_s(cmd_line, sizeof(cmd_line), process_path);
    
    printf("[INFO] 正在创建进程: %s\n", process_path);
    
    if (CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[SUCCESS] 进程创建成功: PID=%lu\n", pi.dwProcessId);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    } else {
        printf("[ERROR] 进程创建失败: %s (错误: %lu)\n", process_path, GetLastError());
        return 1;
    }
}

// 查找进程
int find_process(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n查找进程: %s\n", process_name);
    printf("%-8s %-6s %-40s\n", "PID", "父PID", "进程名");
    printf("----------------------------------------\n");
    
    int found = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strstr(pe.szExeFile, process_name) != NULL) {
                printf("%-8lu %-6lu %-40s\n", 
                       pe.th32ProcessID,
                       pe.th32ParentProcessID,
                       pe.szExeFile);
                found++;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    
    if (found > 0) {
        printf("\n[INFO] 找到 %d 个匹配的进程\n", found);
        return 0;
    } else {
        printf("[INFO] 未找到匹配的进程\n");
        return 1;
    }
}

// 设置进程优先级
int set_process_priority(DWORD pid, const char* priority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] 无法打开进程 PID=%lu (错误: %lu)\n", pid, GetLastError());
        return 1;
    }
    
    DWORD priority_class;
    if (strcmp(priority, "idle") == 0 || strcmp(priority, "low") == 0) {
        priority_class = IDLE_PRIORITY_CLASS;
        printf("[INFO] 设置进程为低优先级\n");
    }
    else if (strcmp(priority, "normal") == 0) {
        priority_class = NORMAL_PRIORITY_CLASS;
        printf("[INFO] 设置进程为普通优先级\n");
    }
    else if (strcmp(priority, "high") == 0) {
        priority_class = HIGH_PRIORITY_CLASS;
        printf("[INFO] 设置进程为高优先级\n");
    }
    else if (strcmp(priority, "realtime") == 0) {
        priority_class = REALTIME_PRIORITY_CLASS;
        printf("[INFO] 设置进程为实时优先级\n");
    }
    else {
        printf("[ERROR] 无效的优先级级别: %s\n", priority);
        printf("可用级别: idle, normal, high, realtime\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    if (SetPriorityClass(hProcess, priority_class)) {
        printf("[SUCCESS] 成功设置进程 PID=%lu 的优先级\n", pid);
        CloseHandle(hProcess);
        return 0;
    } else {
        printf("[ERROR] 设置优先级失败 (错误: %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
}

// 通过进程名查找PID
DWORD find_pid_by_name(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}