#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ctype.h>

#define FTK_PLUGIN_API __declspec(dllexport)

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[STRINGS] �ַ������������ʼ��\n");
    return 0;
}

// ����Ƿ�Ϊ�ɴ�ӡ�ַ�
int is_printable_string(const char* str, int min_len) {
    int len = 0;
    while (str[len] != '\0') {
        if (!isprint((unsigned char)str[len])) {
            return 0;
        }
        len++;
        if (len >= min_len) {
            return 1;
        }
    }
    return (len >= min_len);
}

// �ڽ����ڴ��������ַ���
int search_strings_in_process(DWORD pid, int min_length) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] �޷��򿪽��� PID: %lu (����: %lu)\n", pid, GetLastError());
        return 0;
    }
    
    // ��ȡ������
    char process_name[MAX_PATH] = "Unknown";
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
    
    printf("\n�ڽ��� %s (PID: %lu) �������ַ��� (��С����: %d)...\n", 
           process_name, pid, min_length);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    char* address = (char*)sysInfo.lpMinimumApplicationAddress;
    int string_count = 0;
    const int MAX_STRINGS = 1000; // �����������
    
    while (address < sysInfo.lpMaximumApplicationAddress && string_count < MAX_STRINGS) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        
        // ֻ���ɶ����ύ�ڴ� (�޸� PAGE_READABLE ����)
        if ((mbi.State == MEM_COMMIT) && 
            (mbi.Protect == PAGE_READONLY || 
             mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            char* buffer = (char*)malloc(mbi.RegionSize);
            if (buffer) {
                SIZE_T bytes_read;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytes_read)) {
                    // ���ڴ���������ַ���
                    for (SIZE_T i = 0; i < bytes_read - min_length; i++) {
                        if (is_printable_string(&buffer[i], min_length)) {
                            // �ҵ��ɴ�ӡ�ַ���
                            printf("0x%p: ", (void*)((char*)mbi.BaseAddress + i));
                            
                            // ��ӡ�ַ��������Ƴ��ȣ�
                            int j = 0;
                            while (j < 80 && i + j < bytes_read && isprint((unsigned char)buffer[i + j])) {
                                printf("%c", buffer[i + j]);
                                j++;
                                if (j >= 80) {
                                    printf("...");
                                    break;
                                }
                            }
                            printf("\n");
                            string_count++;
                            
                            i += j; // ��������ַ���
                            
                            if (string_count >= MAX_STRINGS) {
                                printf("[INFO] �Ѵﵽ�����ʾ���� (%d)\n", MAX_STRINGS);
                                break;
                            }
                        }
                    }
                }
                free(buffer);
            }
        }
        
        if (string_count >= MAX_STRINGS) break;
        address = (char*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return string_count;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    DWORD pid = 0;
    int min_length = 4;
    
    if (!args || strlen(args) == 0) {
        printf("[ERROR] ��ָ������ID\n");
        printf("�÷�: strings <����ID> [��С����]\n");
        printf("ʾ��: strings 1234 6\n");
        return -1;
    }
    
    // ��������
    if (sscanf_s(args, "%lu %d", &pid, &min_length) < 1) {
        printf("[ERROR] ��������ʧ��\n");
        return -1;
    }
    
    if (min_length < 2) min_length = 2;
    if (min_length > 100) min_length = 100;
    
    printf("[INFO] ��ʼ�������� %lu �е��ַ���...\n", pid);
    int count = search_strings_in_process(pid, min_length);
    printf("\n�ҵ� %d ���ַ���\n", count);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("�ַ��������������:\n");
    printf("  ����: �ڽ����ڴ��������ɴ�ӡ�ַ���\n");
    printf("  �÷�: strings <����ID> [��С����]\n");
    printf("  ����: ����ID - Ҫ�����Ľ���ID\n");
    printf("        ��С���� - �ַ�����С���� (Ĭ��: 4)\n");
    printf("  ʾ��: strings 1234\n");
    printf("         strings 5678 6\n");
    printf("  ע��: ��Ҫ�ʵ�Ȩ������ȡ�����ڴ�\n");
    printf("        �����ʾ1000���ַ����Ա����������\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "strings|�����ڴ��ַ����������";
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