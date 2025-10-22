#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[TIMELINE] ʱ���߷��������ʼ��\n");
    return 0;
}

// ת��FILETIMEΪ�ɶ�ʱ��
void filetime_to_string(FILETIME ft, char* buffer, int buffer_size) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    sprintf_s(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[TIMELINE] ���ɽ���ʱ����...\n\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷��������̿���\n");
        return -1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("%-8s %-30s %-20s %-12s\n", "PID", "������", "����ʱ��", "����ʱ��");
    printf("----------------------------------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                    char createTimeStr[64];
                    filetime_to_string(createTime, createTimeStr, sizeof(createTimeStr));
                    
                    // ��������ʱ��
                    FILETIME currentTime;
                    GetSystemTimeAsFileTime(&currentTime);
                    
                    ULARGE_INTEGER create, current;
                    create.LowPart = createTime.dwLowDateTime;
                    create.HighPart = createTime.dwHighDateTime;
                    current.LowPart = currentTime.dwLowDateTime;
                    current.HighPart = currentTime.dwHighDateTime;
                    
                    ULONGLONG diff = current.QuadPart - create.QuadPart;
                    ULONGLONG seconds = diff / 10000000; // 100ns��λת��Ϊ��
                    
                    int hours = (int)(seconds / 3600);
                    int minutes = (int)((seconds % 3600) / 60);
                    int secs = (int)(seconds % 60);
                    
                    printf("%-8lu %-30s %-20s %02d:%02d:%02d\n",
                           pe.th32ProcessID, pe.szExeFile, createTimeStr, hours, minutes, secs);
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("ʱ���߷����������:\n");
    printf("  ����: ��ʾ���̴���ʱ���ߺ�����ʱ��\n");
    printf("  �÷�: timeline\n");
    printf("  ���: ����PID�����ơ�����ʱ���������ʱ��\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "timeline|����ʱ���߷������";
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