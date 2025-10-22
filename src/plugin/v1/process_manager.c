#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")

// ����ӿں���
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[PROCESS] ���̹�������ʼ��\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "process|���̹����� - ��ֹ�����𡢻ָ��ʹ�������";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("���̹���������:\n");
    printf("  process                 - ��ʾ���̹������\n");
    printf("  process list            - �г����н���\n");
    printf("  process kill <PID>      - ��ָֹ��PID�Ľ���\n");
    printf("  process killname <����> - ͨ����������ֹ����\n");
    printf("  process suspend <PID>   - ����ָ��PID�Ľ���\n");
    printf("  process resume <PID>    - �ָ�ָ��PID�Ľ���\n");
    printf("  process create <·��>   - �����½���\n");
    printf("  process find <����>     - ���ҽ���\n");
    printf("  process priority <PID> <����> - ���ý������ȼ�\n");
    printf("\n���ȼ�����: idle(��), normal(��ͨ), high(��), realtime(ʵʱ)\n");
}

__declspec(dllexport) int ftk_plugin_execute(const char* args) {
    if (args == NULL || strlen(args) == 0) {
        // ֱ����ʾ�������ݣ������ǽ���ʽ�˵�
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
            printf("[ERROR] ��Ч�Ľ���ID\n");
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
            printf("[ERROR] ��Ч�Ľ���ID\n");
            return 1;
        }
    }
    else if (strncmp(args, "resume ", 7) == 0) {
        DWORD pid = atoi(args + 7);
        if (pid > 0) {
            return resume_process(pid);
        } else {
            printf("[ERROR] ��Ч�Ľ���ID\n");
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
            printf("[ERROR] ��Ч�Ĳ�����ʽ\n");
            return 1;
        }
    }
    
    printf("[ERROR] δ֪����: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// ��ʾ���̹���˵�������ֱ����ʾ������
int show_process_menu() {
    ftk_plugin_help();
    return 0;
}

// �г����н���
int list_all_processes() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿���\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n%-8s %-6s %-40s %-12s\n", "PID", "��PID", "������", "�߳���");
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
    printf("\n[INFO] ʹ�� 'process kill <PID>' ��ֹ����\n");
    return 0;
}

// ��ֹ����
int kill_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] ������ֹ�������\n");
        return 1;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] �޷��򿪽��� PID=%lu (����: %lu)\n", pid, GetLastError());
        return 1;
    }
    
    // ��ȡ������
    char process_name[MAX_PATH] = "δ֪";
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
    
    printf("[WARNING] ������ֹ����: %s (PID: %lu)\n", process_name, pid);
    printf("ȷ����ֹ? (y/N): ");
    
    char confirm[10];
    if (fgets(confirm, sizeof(confirm), stdin) != NULL && 
        (confirm[0] == 'y' || confirm[0] == 'Y')) {
        
        if (TerminateProcess(hProcess, 0)) {
            printf("[SUCCESS] �ɹ���ֹ����: %s (PID: %lu)\n", process_name, pid);
            CloseHandle(hProcess);
            return 0;
        } else {
            printf("[ERROR] ��ֹ����ʧ�� (����: %lu)\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }
    } else {
        printf("[INFO] ������ȡ��\n");
        CloseHandle(hProcess);
        return 0;
    }
}

// ͨ����������ֹ����
int kill_process_by_name(const char* process_name) {
    DWORD pid = find_pid_by_name(process_name);
    if (pid != 0) {
        return kill_process(pid);
    } else {
        printf("[ERROR] δ�ҵ�����: %s\n", process_name);
        return 1;
    }
}

// �������
int suspend_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] ���ܹ����������\n");
        return 1;
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷������߳̿���\n");
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
        printf("[SUCCESS] �ɹ�������� PID=%lu �� %d ���߳�\n", pid, suspended_count);
        return 0;
    } else {
        printf("[ERROR] �޷�������� PID=%lu\n", pid);
        return 1;
    }
}

// �ָ�����
int resume_process(DWORD pid) {
    if (pid == GetCurrentProcessId()) {
        printf("[ERROR] ���ָܻ��������\n");
        return 1;
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷������߳̿���\n");
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
        printf("[SUCCESS] �ɹ��ָ����� PID=%lu �� %d ���߳�\n", pid, resumed_count);
        return 0;
    } else {
        printf("[ERROR] �޷��ָ����� PID=%lu\n", pid);
        return 1;
    }
}

// �����½���
int create_process(const char* process_path) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd_line[MAX_PATH];
    strcpy_s(cmd_line, sizeof(cmd_line), process_path);
    
    printf("[INFO] ���ڴ�������: %s\n", process_path);
    
    if (CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[SUCCESS] ���̴����ɹ�: PID=%lu\n", pi.dwProcessId);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    } else {
        printf("[ERROR] ���̴���ʧ��: %s (����: %lu)\n", process_path, GetLastError());
        return 1;
    }
}

// ���ҽ���
int find_process(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿���\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n���ҽ���: %s\n", process_name);
    printf("%-8s %-6s %-40s\n", "PID", "��PID", "������");
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
        printf("\n[INFO] �ҵ� %d ��ƥ��Ľ���\n", found);
        return 0;
    } else {
        printf("[INFO] δ�ҵ�ƥ��Ľ���\n");
        return 1;
    }
}

// ���ý������ȼ�
int set_process_priority(DWORD pid, const char* priority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] �޷��򿪽��� PID=%lu (����: %lu)\n", pid, GetLastError());
        return 1;
    }
    
    DWORD priority_class;
    if (strcmp(priority, "idle") == 0 || strcmp(priority, "low") == 0) {
        priority_class = IDLE_PRIORITY_CLASS;
        printf("[INFO] ���ý���Ϊ�����ȼ�\n");
    }
    else if (strcmp(priority, "normal") == 0) {
        priority_class = NORMAL_PRIORITY_CLASS;
        printf("[INFO] ���ý���Ϊ��ͨ���ȼ�\n");
    }
    else if (strcmp(priority, "high") == 0) {
        priority_class = HIGH_PRIORITY_CLASS;
        printf("[INFO] ���ý���Ϊ�����ȼ�\n");
    }
    else if (strcmp(priority, "realtime") == 0) {
        priority_class = REALTIME_PRIORITY_CLASS;
        printf("[INFO] ���ý���Ϊʵʱ���ȼ�\n");
    }
    else {
        printf("[ERROR] ��Ч�����ȼ�����: %s\n", priority);
        printf("���ü���: idle, normal, high, realtime\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    if (SetPriorityClass(hProcess, priority_class)) {
        printf("[SUCCESS] �ɹ����ý��� PID=%lu �����ȼ�\n", pid);
        CloseHandle(hProcess);
        return 0;
    } else {
        printf("[ERROR] �������ȼ�ʧ�� (����: %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
}

// ͨ������������PID
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