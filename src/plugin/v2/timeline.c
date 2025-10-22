#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[TIMELINE] 时间线分析插件初始化\n");
    return 0;
}

// 转换FILETIME为可读时间
void filetime_to_string(FILETIME ft, char* buffer, int buffer_size) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    sprintf_s(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[TIMELINE] 生成进程时间线...\n\n");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法创建进程快照\n");
        return -1;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    printf("%-8s %-30s %-20s %-12s\n", "PID", "进程名", "创建时间", "运行时间");
    printf("----------------------------------------------------------------\n");
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                    char createTimeStr[64];
                    filetime_to_string(createTime, createTimeStr, sizeof(createTimeStr));
                    
                    // 计算运行时间
                    FILETIME currentTime;
                    GetSystemTimeAsFileTime(&currentTime);
                    
                    ULARGE_INTEGER create, current;
                    create.LowPart = createTime.dwLowDateTime;
                    create.HighPart = createTime.dwHighDateTime;
                    current.LowPart = currentTime.dwLowDateTime;
                    current.HighPart = currentTime.dwHighDateTime;
                    
                    ULONGLONG diff = current.QuadPart - create.QuadPart;
                    ULONGLONG seconds = diff / 10000000; // 100ns单位转换为秒
                    
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
    printf("时间线分析插件帮助:\n");
    printf("  功能: 显示进程创建时间线和运行时间\n");
    printf("  用法: timeline\n");
    printf("  输出: 进程PID、名称、创建时间和总运行时间\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "timeline|进程时间线分析插件";
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