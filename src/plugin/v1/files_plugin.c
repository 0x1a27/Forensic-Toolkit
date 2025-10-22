#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "psapi.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== 进程文件分析 ===\n\n");
    
    DWORD targetPid = 0;
    if (args && strlen(args) > 0) {
        targetPid = atoi(args);
    }
    
    if (targetPid == 0) {
        // 如果没有指定PID，显示所有进程的模块信息
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            printf("[ERROR] 无法创建进程快照\n");
            return -1;
        }
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        printf("%-8s %-30s %-10s %s\n", "PID", "进程名", "模块数", "路径");
        printf("----------------------------------------------------------------\n");
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    HMODULE hModules[1024];
                    DWORD cbNeeded;
                    
                    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                        char processPath[MAX_PATH] = "未知";
                        
                        if (GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath))) {
                            printf("%-8lu %-30s %-10lu %s\n", 
                                   pe.th32ProcessID, pe.szExeFile, moduleCount, processPath);
                        }
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
    } else {
        // 分析特定进程的模块
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
        if (!hProcess) {
            printf("[ERROR] 无法打开进程 (PID: %lu)\n", targetPid);
            return -1;
        }
        
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        printf("进程 PID: %lu 的加载模块:\n\n", targetPid);
        printf("%-60s %-20s %s\n", "模块路径", "基地址", "大小");
        printf("--------------------------------------------------------------------------------\n");
        
        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);
            
            for (DWORD i = 0; i < moduleCount; i++) {
                char modulePath[MAX_PATH];
                MODULEINFO moduleInfo;
                
                if (GetModuleFileNameExA(hProcess, hModules[i], modulePath, sizeof(modulePath)) &&
                    GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
                    
                    printf("%-60s 0x%p %-10lu\n", 
                           modulePath, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
                }
            }
            
            printf("\n总共 %lu 个模块\n", moduleCount);
        } else {
            printf("[ERROR] 无法枚举进程模块\n");
        }
        
        CloseHandle(hProcess);
    }
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("文件分析插件帮助:\n");
    printf("  功能: 分析进程加载的DLL模块和文件句柄\n");
    printf("  用法: files [PID]\n");
    printf("  参数: PID - 要分析的进程ID (可选，不指定则显示所有进程)\n");
    printf("  输出: 进程加载的DLL模块列表或所有进程的模块统计\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "files|进程文件分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}