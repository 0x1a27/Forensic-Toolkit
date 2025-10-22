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
    printf("\n=== �����ļ����� ===\n\n");
    
    DWORD targetPid = 0;
    if (args && strlen(args) > 0) {
        targetPid = atoi(args);
    }
    
    if (targetPid == 0) {
        // ���û��ָ��PID����ʾ���н��̵�ģ����Ϣ
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            printf("[ERROR] �޷��������̿���\n");
            return -1;
        }
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        printf("%-8s %-30s %-10s %s\n", "PID", "������", "ģ����", "·��");
        printf("----------------------------------------------------------------\n");
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    HMODULE hModules[1024];
                    DWORD cbNeeded;
                    
                    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                        char processPath[MAX_PATH] = "δ֪";
                        
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
        // �����ض����̵�ģ��
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
        if (!hProcess) {
            printf("[ERROR] �޷��򿪽��� (PID: %lu)\n", targetPid);
            return -1;
        }
        
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        printf("���� PID: %lu �ļ���ģ��:\n\n", targetPid);
        printf("%-60s %-20s %s\n", "ģ��·��", "����ַ", "��С");
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
            
            printf("\n�ܹ� %lu ��ģ��\n", moduleCount);
        } else {
            printf("[ERROR] �޷�ö�ٽ���ģ��\n");
        }
        
        CloseHandle(hProcess);
    }
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("�ļ������������:\n");
    printf("  ����: �������̼��ص�DLLģ����ļ����\n");
    printf("  �÷�: files [PID]\n");
    printf("  ����: PID - Ҫ�����Ľ���ID (��ѡ����ָ������ʾ���н���)\n");
    printf("  ���: ���̼��ص�DLLģ���б�����н��̵�ģ��ͳ��\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "files|�����ļ��������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}