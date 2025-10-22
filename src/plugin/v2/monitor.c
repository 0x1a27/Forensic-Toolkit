#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <time.h>
#include <conio.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// ������ݽṹ
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
    printf("[MONITOR] ���̼�ز����ʼ��\n");
    return 0;
}

// ��ȡ��ǰ�����б�
int get_current_processes(MonitorProcess* processes, int max_count) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿��� (����: %lu)\n", GetLastError());
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
                
                // ��ȡ�ڴ���Ϣ
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        processes[count].memory_usage = pmc.WorkingSetSize;
                    }
                    
                    // ��ȡ����ʱ��
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

// �ȽϽ��̱仯
void compare_process_changes(MonitorProcess* current, int current_count, 
                           MonitorProcess* previous, int previous_count) {
    int new_count = 0;
    int terminated_count = 0;
    
    // ����½���
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
    
    // �����ֹ�Ľ���
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
    
    // ��ʾ�仯
    if (new_count > 0) {
        printf("\n[�½���] ���� %d ���½���:\n", new_count);
        for (int i = 0; i < current_count; i++) {
            if (current[i].is_new) {
                printf("  [+] PID: %-6lu | ����: %s | �ڴ�: %.2f MB\n", 
                       current[i].pid, current[i].name,
                       (double)current[i].memory_usage / (1024 * 1024));
            }
        }
    }
    
    if (terminated_count > 0) {
        printf("\n[��ֹ����] ���� %d ��������ֹ:\n", terminated_count);
        for (int i = 0; i < previous_count; i++) {
            if (previous[i].is_terminated) {
                printf("  [-] PID: %-6lu | ����: %s\n", 
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

// ��ʾ��ǰ����ͳ��
void show_process_stats(MonitorProcess* processes, int count) {
    time_t now;
    time(&now);
    struct tm local_time;
    localtime_s(&local_time, &now);
    
    printf("\n[%02d:%02d:%02d] ��ǰ������: %d", 
           local_time.tm_hour, local_time.tm_min, local_time.tm_sec, count);
    
    // �������ڴ�ʹ��
    SIZE_T total_memory = 0;
    for (int i = 0; i < count; i++) {
        total_memory += processes[i].memory_usage;
    }
    
    printf(" | ���ڴ�: %.2f MB", (double)total_memory / (1024 * 1024));
}

// ���������루��������
int check_keyboard() {
    return _kbhit();
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    int interval = 3; // Ĭ��3��
    
    if (args && strlen(args) > 0) {
        interval = atoi(args);
        if (interval <= 0) interval = 3;
        if (interval > 60) interval = 60; // ���60��
    }
    
    printf("[MONITOR] ����ʵʱ���̼��\n");
    printf("��ؼ��: %d��\n", interval);
    printf("�� 'q' ��ֹͣ���\n");
    printf("�� 's' ����ʾ��ǰ����ͳ��\n");
    printf("===============================================\n");
    
    // ��ȡ��ʼ�����б�
    g_previous_count = get_current_processes(g_previous_processes, 1024);
    printf("��ʼ������: %d\n", g_previous_count);
    
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
            
            // ���浱ǰ״̬
            memcpy(g_previous_processes, current_processes, sizeof(MonitorProcess) * current_count);
            g_previous_count = current_count;
        }
        
        cycle++;
        
        // ����������
        int wait_count = interval * 10; // ����ת��Ϊ100ms���
        for (int i = 0; i < wait_count && g_monitoring; i++) {
            Sleep(100); // ÿ100ms���һ��
            
            if (check_keyboard()) {
                int ch = _getch();
                if (ch == 'q' || ch == 'Q') {
                    g_monitoring = 0;
                    printf("\n[INFO] �û�����ֹͣ���\n");
                    break;
                } else if (ch == 's' || ch == 'S') {
                    show_process_stats(current_processes, current_count);
                }
            }
        }
    }
    
    printf("\n[MONITOR] ��ؽ����������� %d ������\n", cycle);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("���̼�ز������:\n");
    printf("  ����: ʵʱ��ؽ��̴�������ֹ\n");
    printf("  �÷�: monitor [�������]\n");
    printf("  ����: ������� - ��ؼ����Ĭ��3�룬���60��\n");
    printf("  ʾ��: monitor 5    - ÿ5����һ��\n");
    printf("         monitor     - ʹ��Ĭ��3����\n");
    printf("  ����: q - ֹͣ���\n");
    printf("         s - ��ʾ��ǰͳ��\n");
    printf("  ���: ��ʾ�´����Ľ��̺���ֹ�Ľ���\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "monitor|ʵʱ���̼�ز��";
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