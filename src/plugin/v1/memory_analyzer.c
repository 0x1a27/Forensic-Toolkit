#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")  // �������

// ����ӿں���
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[MEMORY] �ڴ���������ʼ��\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "memory|�ڴ�ʹ�÷������ - ���������ڴ�ʹ�����";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("�ڴ�����������:\n");
    printf("  memory                  - ��ʾ�ڴ�ʹ������\n");
    printf("  memory -p <PID>         - ��ʾָ�������ڴ�����\n");
    printf("  memory -t               - ��ʾ�ڴ�����ͳ��\n");
    printf("  memory -w               - ����ڴ�仯\n");
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
    
    printf("[MEMORY] δ֪����: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// ��ʾ�ڴ�ʹ������
int show_memory_usage() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿���\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n=== �����ڴ�ʹ������ ===\n\n");
    printf("%-8s %-40s %-12s %s\n", "PID", "������", "�ڴ�ʹ��", "������");
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

// ��ʾ�ڴ�����ͳ��
int show_total_memory() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    
    if (GlobalMemoryStatusEx(&statex)) {
        printf("\n=== ϵͳ�ڴ�ͳ�� ===\n\n");
        printf("�����ڴ�����: %.2f GB\n", (double)statex.ullTotalPhys / (1024 * 1024 * 1024));
        printf("���������ڴ�: %.2f GB\n", (double)statex.ullAvailPhys / (1024 * 1024 * 1024));
        printf("�ڴ�ʹ����: %ld%%\n", statex.dwMemoryLoad);
        printf("�����ڴ�����: %.2f GB\n", (double)statex.ullTotalPageFile / (1024 * 1024 * 1024));
        printf("���������ڴ�: %.2f GB\n", (double)statex.ullAvailPageFile / (1024 * 1024 * 1024));
    }
    
    return 0;
}

// ����ڴ�仯
int monitor_memory_changes() {
    printf("\n=== �ڴ�仯��� ===\n");
    printf("��ESC���˳����...\n\n");
    
    int count = 0;
    while (1) {
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            break;
        }
        
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        
        if (GlobalMemoryStatusEx(&statex)) {
            printf("[%d] �ڴ�ʹ����: %ld%% | ���������ڴ�: %.2f GB\r", 
                   ++count,
                   statex.dwMemoryLoad,
                   (double)statex.ullAvailPhys / (1024 * 1024 * 1024));
        }
        
        Sleep(2000);
    }
    
    printf("\n[INFO] �˳��ڴ���\n");
    return 0;
}

// ��ʾ�����ڴ�����
int show_process_memory_details(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] �޷��򿪽��� PID=%lu\n", pid);
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
    
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        printf("\n=== ���� %lu �ڴ����� ===\n\n", pid);
        printf("������: %s\n", process_name);
        printf("ҳ���ļ�ʹ��: %.2f MB\n", (double)pmc.PagefileUsage / (1024 * 1024));
        printf("��ֵҳ���ļ�: %.2f MB\n", (double)pmc.PeakPagefileUsage / (1024 * 1024));
        printf("��������С: %.2f MB\n", (double)pmc.WorkingSetSize / (1024 * 1024));
        printf("��ֵ������: %.2f MB\n", (double)pmc.PeakWorkingSetSize / (1024 * 1024));
        printf("��ҳ��ʹ��: %.2f MB\n", (double)pmc.QuotaPagedPoolUsage / (1024 * 1024));
        printf("�Ƿ�ҳ��ʹ��: %.2f MB\n", (double)pmc.QuotaNonPagedPoolUsage / (1024 * 1024));
    }
    
    CloseHandle(hProcess);
    return 0;
}