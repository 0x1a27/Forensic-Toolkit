#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// ����ӿں���
__declspec(dllexport) int ftk_plugin_init(void) {
    printf("[NETWORK] ������������ʼ��\n");
    return 0;
}

__declspec(dllexport) const char* ftk_plugin_info(void) {
    return "network|�������ӷ������ - ��ʾ��������������Ϣ";
}

__declspec(dllexport) void ftk_plugin_help(void) {
    printf("��������������:\n");
    printf("  network                 - ��ʾ������������\n");
    printf("  network -p <PID>        - ��ʾָ�����̵���������\n");
    printf("  network -s              - ��ʾ�����˿ڵĽ���\n");
    printf("  network -a              - ��ʾ����������ϸ��Ϣ\n");
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
    
    printf("[NETWORK] δ֪����: %s\n", args);
    ftk_plugin_help();
    return 1;
}

// ��ʾ������������
int show_all_connections() {
    printf("\n=== TCP �������� ===\n\n");
    printf("%-8s %-20s %-20s %-10s %s\n", 
           "PID", "���ص�ַ", "Զ�̵�ַ", "״̬", "������");
    printf("------------------------------------------------------------------------\n");
    
    // ʹ��ϵͳ�����ȡ����������Ϣ����ʵ�֣�
    system("netstat -ano | findstr TCP");
    
    printf("\n[INFO] ʹ�� 'netstat -ano' ��ȡ��������������Ϣ\n");
    return 0;
}

// ��ʾ�����˿ڵĽ���
int show_listening_ports() {
    printf("\n=== �����˿ڽ��� ===\n\n");
    printf("%-8s %-20s %-10s %s\n", "PID", "���ص�ַ", "״̬", "������");
    printf("------------------------------------------------------------\n");
    
    // ʹ��ϵͳ�����ȡ�����˿���Ϣ
    system("netstat -ano | findstr LISTENING");
    
    printf("\n[INFO] ʹ�� 'netstat -ano' ��ȡ���������˿���Ϣ\n");
    return 0;
}

// ��ʾ��ϸ������Ϣ
int show_detailed_connections() {
    printf("\n=== ��ϸ����������Ϣ ===\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿���\n");
        return 1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("\n�������е�������ؽ���:\n");
    printf("%-8s %-40s\n", "PID", "������");
    printf("----------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            // ����Ƿ�Ϊ������������ؽ���
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
    
    printf("\n[INFO] ��ϸ�������������Ҫ����ԱȨ��\n");
    return 0;
}

// ��ʾָ�����̵���������
int show_process_connections(DWORD pid) {
    printf("\n=== ���� %lu ������������Ϣ ===\n\n", pid);
    
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
    
    printf("������: %s\n", process_name);
    printf("PID: %lu\n", pid);
    
    // ʹ��ϵͳ������ý��̵���������
    char command[256];
    sprintf_s(command, sizeof(command), "netstat -ano | findstr %lu", pid);
    printf("\n��������:\n");
    system(command);
    
    return 0;
}