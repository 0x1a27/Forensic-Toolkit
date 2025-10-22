#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <time.h>

#define FTK_PLUGIN_API __declspec(dllexport)

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[REPORT] �������ɲ����ʼ��\n");
    return 0;
}

// ����HTML����
void generate_html_report(const char* filename) {
    FILE* fp;
    if (fopen_s(&fp, filename, "w") != 0) {
        printf("[ERROR] �޷����������ļ�: %s\n", filename);
        return;
    }
    
    time_t now = time(NULL);
    struct tm local_time;
    localtime_s(&local_time, &now);
    
    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html>\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "    <title>FTK ȡ֤����</title>\n");
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        body { font-family: Arial, sans-serif; margin: 20px; }\n");
    fprintf(fp, "        h1 { color: #2c3e50; }\n");
    fprintf(fp, "        table { border-collapse: collapse; width: 100%%; margin: 20px 0; }\n");
    fprintf(fp, "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    fprintf(fp, "        th { background-color: #f2f2f2; }\n");
    fprintf(fp, "        .new { background-color: #d4edda; }\n");
    fprintf(fp, "        .suspicious { background-color: #f8d7da; }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "    <h1>Forensic Toolkit ȡ֤����</h1>\n");
    fprintf(fp, "    <p>����ʱ��: %04d-%02d-%02d %02d:%02d:%02d</p>\n",
           local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday,
           local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
    
    // ϵͳ��Ϣ����
    fprintf(fp, "    <h2>ϵͳ��Ϣ</h2>\n");
    fprintf(fp, "    <table>\n");
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    
    fprintf(fp, "        <tr><td>�������ܹ�</td><td>%lu</td></tr>\n", sysInfo.dwProcessorType);
    fprintf(fp, "        <tr><td>����������</td><td>%lu</td></tr>\n", sysInfo.dwNumberOfProcessors);
    fprintf(fp, "        <tr><td>���ڴ�</td><td>%.2f GB</td></tr>\n", 
           (double)memoryStatus.ullTotalPhys / (1024*1024*1024));
    fprintf(fp, "        <tr><td>�����ڴ�</td><td>%.2f GB</td></tr>\n", 
           (double)memoryStatus.ullAvailPhys / (1024*1024*1024));
    
    fprintf(fp, "    </table>\n");
    
    // �����б���
    fprintf(fp, "    <h2>�����б�</h2>\n");
    fprintf(fp, "    <table>\n");
    fprintf(fp, "        <tr><th>PID</th><th>������</th><th>�߳���</th><th>�ڴ�ʹ��</th></tr>\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                SIZE_T memory_usage = 0;
                
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        memory_usage = pmc.WorkingSetSize;
                    }
                    CloseHandle(hProcess);
                }
                
                fprintf(fp, "        <tr><td>%lu</td><td>%s</td><td>%lu</td><td>%.2f MB</td></tr>\n",
                       pe.th32ProcessID, pe.szExeFile, pe.cntThreads, 
                       (double)memory_usage / (1024*1024));
                
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    fprintf(fp, "    </table>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");
    
    fclose(fp);
    printf("[SUCCESS] HTML����������: %s\n", filename);
}

// �����ı�����
void generate_text_report(const char* filename) {
    FILE* fp;
    if (fopen_s(&fp, filename, "w") != 0) {
        printf("[ERROR] �޷����������ļ�: %s\n", filename);
        return;
    }
    
    time_t now = time(NULL);
    struct tm local_time;
    localtime_s(&local_time, &now);
    
    fprintf(fp, "===============================================\n");
    fprintf(fp, "        Forensic Toolkit ȡ֤����\n");
    fprintf(fp, "===============================================\n");
    fprintf(fp, "����ʱ��: %04d-%02d-%02d %02d:%02d:%02d\n\n",
           local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday,
           local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
    
    // ϵͳ��Ϣ
    fprintf(fp, "ϵͳ��Ϣ:\n");
    fprintf(fp, "--------\n");
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    
    fprintf(fp, "�������ܹ�: %lu\n", sysInfo.dwProcessorType);
    fprintf(fp, "����������: %lu\n", sysInfo.dwNumberOfProcessors);
    fprintf(fp, "���ڴ�: %.2f GB\n", (double)memoryStatus.ullTotalPhys / (1024*1024*1024));
    fprintf(fp, "�����ڴ�: %.2f GB\n\n", (double)memoryStatus.ullAvailPhys / (1024*1024*1024));
    
    // �����б�
    fprintf(fp, "�����б�:\n");
    fprintf(fp, "--------\n");
    fprintf(fp, "%-8s %-40s %-12s %-12s\n", "PID", "������", "�߳���", "�ڴ�ʹ��");
    fprintf(fp, "------------------------------------------------------------\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                SIZE_T memory_usage = 0;
                
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        memory_usage = pmc.WorkingSetSize;
                    }
                    CloseHandle(hProcess);
                }
                
                fprintf(fp, "%-8lu %-40s %-12lu %-10.2fMB\n",
                       pe.th32ProcessID, pe.szExeFile, pe.cntThreads, 
                       (double)memory_usage / (1024*1024));
                
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    fclose(fp);
    printf("[SUCCESS] �ı�����������: %s\n", filename);
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    char filename[MAX_PATH] = "ftk_report";
    char format[10] = "html";
    
    if (args && strlen(args) > 0) {
        char format_arg[10];
        if (sscanf_s(args, "%9s", format_arg, (unsigned)sizeof(format_arg)) == 1) {
            if (strcmp(format_arg, "html") == 0 || strcmp(format_arg, "txt") == 0) {
                strcpy_s(format, sizeof(format), format_arg);
            }
        }
    }
    
    // ���ɴ�ʱ������ļ���
    time_t now = time(NULL);
    struct tm local_time;
    localtime_s(&local_time, &now);
    
    char timestamp[20];
    sprintf_s(timestamp, sizeof(timestamp), "%04d%02d%02d_%02d%02d%02d",
             local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday,
             local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
    
    char full_filename[MAX_PATH];
    sprintf_s(full_filename, sizeof(full_filename), "%s_%s.%s", filename, timestamp, format);
    
    if (strcmp(format, "html") == 0) {
        generate_html_report(full_filename);
    } else {
        generate_text_report(full_filename);
    }
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("�������ɲ������:\n");
    printf("  ����: ����ϵͳȡ֤����\n");
    printf("  �÷�: report [��ʽ]\n");
    printf("  ��ʽ: html - ����HTML���棨Ĭ�ϣ�\n");
    printf("         txt  - �����ı�����\n");
    printf("  ʾ��: report html\n");
    printf("         report txt\n");
    printf("  ���: ����ϵͳ��Ϣ�ͽ����б����ϸ����\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "report|ϵͳȡ֤�������ɲ��";
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