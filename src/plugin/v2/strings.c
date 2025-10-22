#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ctype.h>

#define FTK_PLUGIN_API __declspec(dllexport)

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[STRINGS] 字符串搜索插件初始化\n");
    return 0;
}

// 检查是否为可打印字符
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

// 在进程内存中搜索字符串
int search_strings_in_process(DWORD pid, int min_length) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        printf("[ERROR] 无法打开进程 PID: %lu (错误: %lu)\n", pid, GetLastError());
        return 0;
    }
    
    // 获取进程名
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
    
    printf("\n在进程 %s (PID: %lu) 中搜索字符串 (最小长度: %d)...\n", 
           process_name, pid, min_length);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    char* address = (char*)sysInfo.lpMinimumApplicationAddress;
    int string_count = 0;
    const int MAX_STRINGS = 1000; // 限制输出数量
    
    while (address < sysInfo.lpMaximumApplicationAddress && string_count < MAX_STRINGS) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        
        // 只检查可读的提交内存 (修复 PAGE_READABLE 问题)
        if ((mbi.State == MEM_COMMIT) && 
            (mbi.Protect == PAGE_READONLY || 
             mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            char* buffer = (char*)malloc(mbi.RegionSize);
            if (buffer) {
                SIZE_T bytes_read;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytes_read)) {
                    // 在内存块中搜索字符串
                    for (SIZE_T i = 0; i < bytes_read - min_length; i++) {
                        if (is_printable_string(&buffer[i], min_length)) {
                            // 找到可打印字符串
                            printf("0x%p: ", (void*)((char*)mbi.BaseAddress + i));
                            
                            // 打印字符串（限制长度）
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
                            
                            i += j; // 跳过这个字符串
                            
                            if (string_count >= MAX_STRINGS) {
                                printf("[INFO] 已达到最大显示数量 (%d)\n", MAX_STRINGS);
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
        printf("[ERROR] 请指定进程ID\n");
        printf("用法: strings <进程ID> [最小长度]\n");
        printf("示例: strings 1234 6\n");
        return -1;
    }
    
    // 解析参数
    if (sscanf_s(args, "%lu %d", &pid, &min_length) < 1) {
        printf("[ERROR] 参数解析失败\n");
        return -1;
    }
    
    if (min_length < 2) min_length = 2;
    if (min_length > 100) min_length = 100;
    
    printf("[INFO] 开始搜索进程 %lu 中的字符串...\n", pid);
    int count = search_strings_in_process(pid, min_length);
    printf("\n找到 %d 个字符串\n", count);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("字符串搜索插件帮助:\n");
    printf("  功能: 在进程内存中搜索可打印字符串\n");
    printf("  用法: strings <进程ID> [最小长度]\n");
    printf("  参数: 进程ID - 要搜索的进程ID\n");
    printf("        最小长度 - 字符串最小长度 (默认: 4)\n");
    printf("  示例: strings 1234\n");
    printf("         strings 5678 6\n");
    printf("  注意: 需要适当权限来读取进程内存\n");
    printf("        最多显示1000个字符串以避免输出过多\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "strings|进程内存字符串搜索插件";
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