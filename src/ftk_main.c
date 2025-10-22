#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <conio.h>

#define MAX_COMMAND_LENGTH 512
#define MAX_PATH_LENGTH 1024
#define MAX_PROCESSES 1024
#define MAX_PLUGINS 32
#define LOG_FILE "ftk_audit.log"
#define MAX_TAB_MATCHES 50

// 编译指示
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ntdll.lib")

// 扩展插件接口 - 允许插件修改主程序
typedef struct {
    char banner_text[256];
    char welcome_message[256];
    int enable_advanced_features;
    int hide_sensitive_info;
} FTK_MAIN_CONFIG;

// 全局配置
FTK_MAIN_CONFIG g_main_config = {
    "Forensic Toolkit (FTK) - 进程取证分析",
    "版本 2.2 | 动态插件架构",
    1,  // enable_advanced_features
    0   // hide_sensitive_info
};

// 插件回调函数类型
typedef void (*FTK_PLUGIN_CONFIG_CALLBACK)(FTK_MAIN_CONFIG* config);

// 数据结构
typedef struct {
    DWORD pid;
    DWORD parent_pid;
    char name[MAX_PATH];
    char user[64];
    FILETIME create_time;
    DWORD thread_count;
    SIZE_T memory_usage;
    DWORD session_id;
} ProcessInfo;

// 扩展插件函数指针类型定义
typedef int (*FTK_PLUGIN_INIT)(void);
typedef int (*FTK_PLUGIN_EXECUTE)(const char* args);
typedef void (*FTK_PLUGIN_HELP)(void);
typedef const char* (*FTK_PLUGIN_INFO)(void);
typedef void (*FTK_PLUGIN_CONFIG)(FTK_MAIN_CONFIG* config);  // 新增配置回调

// 扩展插件结构体
typedef struct {
    char name[64];
    char description[128];
    HMODULE handle;
    FTK_PLUGIN_INIT init_func;
    FTK_PLUGIN_EXECUTE execute_func;
    FTK_PLUGIN_HELP help_func;
    FTK_PLUGIN_INFO info_func;
    FTK_PLUGIN_CONFIG config_func;  // 配置回调函数
} Plugin;

// 全局变量
ProcessInfo g_process_list[MAX_PROCESSES];
int g_process_count = 0;
Plugin g_plugins[MAX_PLUGINS];
int g_plugin_count = 0;

// 输入系统相关变量
char g_command_history[100][MAX_COMMAND_LENGTH];
int g_history_count = 0;
int g_history_index = 0;
char g_current_input[MAX_COMMAND_LENGTH] = "";
int g_cursor_pos = 0;

// 函数声明
void ftk_banner();
void ftk_print_help();
void ftk_load_plugins(int silent);
void ftk_unload_plugins();
void ftk_reload_plugins();
void ftk_list_plugins();
void ftk_plugin_help(const char* plugin_name);
int ftk_execute_plugin(const char* plugin_name, const char* args);
const char* ftk_stristr(const char* str, const char* substr);

// 颜色输出函数
void ftk_print_error(const char* format, ...);
void ftk_print_success(const char* format, ...);
void ftk_print_warning(const char* format, ...);
void ftk_print_info(const char* format, ...);
void ftk_print_debug(const char* format, ...);
void ftk_print_plugin(const char* format, ...);
void ftk_print_system(const char* format, ...);
void ftk_enable_virtual_terminal();
void ftk_set_color(int color);

// 核心功能函数
void ftk_refresh_process_list();
int ftk_list_processes(int detailed);
void ftk_create_process(const char* command);
int ftk_terminate_process(DWORD pid, int force);
void ftk_process_details(DWORD pid);
void ftk_search_process(const char* pattern, int case_sensitive);
void ftk_monitor_processes(int interval);
void ftk_export_process_list(const char* filename);
void ftk_get_process_tree(DWORD root_pid, int depth);
void ftk_analyze_suspicious();
void ftk_detect_hollowing();
DWORD ftk_find_process(const char* name, int exact_match);
void ftk_log_operation(const char* operation, const char* target, int success);
char* ftk_get_username_from_pid(DWORD pid);
char* ftk_format_time(FILETIME* ft);

// 紧急避险功能
void ftk_trigger_bsod();
int ftk_is_system_process(DWORD pid);
void ftk_emergency_shutdown();

// 改进的输入系统函数
void ftk_init_input_system();
char* ftk_tab_complete(const char* current_input, int* match_count, char matches[][MAX_COMMAND_LENGTH]);
void ftk_add_to_history(const char* command);
void ftk_show_command_history();
void ftk_clear_line(int length);
void ftk_print_prompt();
int ftk_readline(char* buffer, int max_len);
void ftk_display_matches(char matches[][MAX_COMMAND_LENGTH], int match_count);
char* ftk_find_common_prefix(char matches[][MAX_COMMAND_LENGTH], int match_count);
void ftk_update_display(char* buffer, int pos, int max_len);
void ftk_handle_arrow_keys(int ext_ch, char* buffer, int* pos, int max_len);
void ftk_handle_backspace(char* buffer, int* pos);
void ftk_handle_delete(char* buffer, int* pos);
void ftk_handle_home_end(int ext_ch, char* buffer, int* pos);

// 命令列表
const char* g_commands[] = {
    "help", "exit", "quit", "list", "list -d", "list detailed",
    "create", "kill", "kill -f", "killbyname", "details", 
    "search", "search -e", "monitor", "export", "tree", 
    "analyze", "detect", "refresh", "test", "debug", "plugins",
    "plugin", "history", "clear", "cls", "reload", "bsod"
};
const int g_command_count = sizeof(g_commands) / sizeof(g_commands[0]);

// BSOD相关函数声明 (需要ntdll.lib)
typedef NTSTATUS (NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS (NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);

// 启用虚拟终端处理
void ftk_enable_virtual_terminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// 设置颜色函数
void ftk_set_color(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// 颜色输出函数实现 - 使用Windows控制台API
void ftk_print_error(const char* format, ...) {
    ftk_set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_success(const char* format, ...) {
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_warning(const char* format, ...) {
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_info(const char* format, ...) {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // 青色
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_debug(const char* format, ...) {
    ftk_set_color(FOREGROUND_INTENSITY); // 灰色
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_plugin(const char* format, ...) {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY); // 紫色
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_system(const char* format, ...) {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

// 自定义不区分大小写的字符串搜索函数
const char* ftk_stristr(const char* str, const char* substr) {
    if (str == NULL || substr == NULL || *substr == '\0') return NULL;
    
    while (*str) {
        const char* s1 = str;
        const char* s2 = substr;
        
        while (*s1 && *s2 && tolower((unsigned char)*s1) == tolower((unsigned char)*s2)) {
            s1++;
            s2++;
        }
        
        if (*s2 == '\0') {
            return str;
        }
        
        str++;
    }
    
    return NULL;
}

// 设置控制台编码为GBK（中文Windows默认编码）
void setup_console_encoding() {
    SetConsoleOutputCP(936);
    SetConsoleCP(936);
}

// 初始化输入系统
void ftk_init_input_system() {
    g_history_count = 0;
    g_history_index = 0;
    g_cursor_pos = 0;
    memset(g_command_history, 0, sizeof(g_command_history));
    memset(g_current_input, 0, sizeof(g_current_input));
}

// 清除当前行
void ftk_clear_line(int length) {
    printf("\r");
    for (int i = 0; i < length + 50; i++) {
        printf(" ");
    }
    printf("\r");
}

// 打印提示符
void ftk_print_prompt() {
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\rForensic_Toolkit> ");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// 显示匹配列表
void ftk_display_matches(char matches[][MAX_COMMAND_LENGTH], int match_count) {
    printf("\n");
    int cols = 3; // 每行显示3个
    int rows = (match_count + cols - 1) / cols;
    
    for (int i = 0; i < rows; i++) {
        printf("  ");
        for (int j = 0; j < cols; j++) {
            int index = i + j * rows;
            if (index < match_count) {
                ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                printf("%-25s", matches[index]);
                ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
        }
        printf("\n");
    }
    printf("\n");
}

// 查找共同前缀
char* ftk_find_common_prefix(char matches[][MAX_COMMAND_LENGTH], int match_count) {
    static char common_prefix[MAX_COMMAND_LENGTH];
    if (match_count == 0) return NULL;
    
    strcpy_s(common_prefix, MAX_COMMAND_LENGTH, matches[0]);
    
    for (int i = 1; i < match_count; i++) {
        int j = 0;
        while (common_prefix[j] && matches[i][j] && 
               tolower(common_prefix[j]) == tolower(matches[i][j])) {
            j++;
        }
        common_prefix[j] = '\0';
        if (j == 0) break; // 没有共同前缀
    }
    
    return common_prefix;
}

// Tab补全函数 - 优化版本
char* ftk_tab_complete(const char* current_input, int* match_count, char matches[][MAX_COMMAND_LENGTH]) {
    *match_count = 0;
    
    // 如果输入为空，显示所有可用命令
    if (strlen(current_input) == 0) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n可用命令 (%d个):", g_command_count + g_plugin_count);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
        
        // 显示内置命令
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("内置命令:");
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
        ftk_display_matches((char(*)[MAX_COMMAND_LENGTH])g_commands, g_command_count);
        
        // 显示插件命令
        if (g_plugin_count > 0) {
            ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("插件命令:");
            ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("\n");
            for (int i = 0; i < g_plugin_count; i++) {
                strcpy_s(matches[*match_count], MAX_COMMAND_LENGTH, g_plugins[i].name);
                (*match_count)++;
            }
            ftk_display_matches(matches, g_plugin_count);
        }
        return NULL;
    }
    
    // 搜索内置命令
    for (int i = 0; i < g_command_count; i++) {
        if (strncmp(g_commands[i], current_input, strlen(current_input)) == 0) {
            strcpy_s(matches[*match_count], MAX_COMMAND_LENGTH, g_commands[i]);
            (*match_count)++;
            if (*match_count >= MAX_TAB_MATCHES) break;
        }
    }
    
    // 搜索插件命令
    for (int i = 0; i < g_plugin_count; i++) {
        if (strncmp(g_plugins[i].name, current_input, strlen(current_input)) == 0) {
            strcpy_s(matches[*match_count], MAX_COMMAND_LENGTH, g_plugins[i].name);
            (*match_count)++;
            if (*match_count >= MAX_TAB_MATCHES) break;
        }
    }
    
    if (*match_count == 0) {
        printf("\a"); // 蜂鸣声提示无匹配
        return NULL;
    }
    else if (*match_count == 1) {
        // 只有一个匹配，直接补全
        return matches[0];
    }
    else {
        // 多个匹配，显示列表并返回共同前缀
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n找到 %d 个匹配:", *match_count);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
        ftk_display_matches(matches, *match_count);
        
        char* common_prefix = ftk_find_common_prefix(matches, *match_count);
        if (strlen(common_prefix) > strlen(current_input)) {
            return common_prefix;
        }
    }
    
    return NULL;
}

// 更新显示
void ftk_update_display(char* buffer, int pos, int max_len) {
    ftk_clear_line((int)strlen(buffer));
    ftk_print_prompt();
    printf("%s", buffer);
    
    // 重新定位光标
    int current_len = (int)strlen(buffer);
    if (pos < current_len) {
        for (int i = current_len; i > pos; i--) {
            printf("\b");
        }
    }
    fflush(stdout);
}

// 处理方向键
void ftk_handle_arrow_keys(int ext_ch, char* buffer, int* pos, int max_len) {
    if (ext_ch == 72) { // 上箭头
        if (g_history_count > 0) {
            if (g_history_index > 0) {
                g_history_index--;
            }
            strcpy_s(buffer, max_len, g_command_history[g_history_index]);
            *pos = (int)strlen(buffer);
            strcpy_s(g_current_input, MAX_COMMAND_LENGTH, buffer);
            ftk_update_display(buffer, *pos, max_len);
        }
    }
    else if (ext_ch == 80) { // 下箭头
        if (g_history_count > 0) {
            if (g_history_index < g_history_count - 1) {
                g_history_index++;
                strcpy_s(buffer, max_len, g_command_history[g_history_index]);
                *pos = (int)strlen(buffer);
                strcpy_s(g_current_input, MAX_COMMAND_LENGTH, buffer);
            } else if (g_history_index == g_history_count - 1) {
                g_history_index++;
                buffer[0] = '\0';
                *pos = 0;
                strcpy_s(g_current_input, MAX_COMMAND_LENGTH, "");
            }
            ftk_update_display(buffer, *pos, max_len);
        }
    }
    else if (ext_ch == 75) { // 左箭头
        if (*pos > 0) {
            (*pos)--;
            printf("\b");
        }
    }
    else if (ext_ch == 77) { // 右箭头
        if (*pos < (int)strlen(buffer)) {
            printf("%c", buffer[*pos]);
            (*pos)++;
        }
    }
}

// 处理Home/End键
void ftk_handle_home_end(int ext_ch, char* buffer, int* pos) {
    if (ext_ch == 71) { // Home
        while (*pos > 0) {
            (*pos)--;
            printf("\b");
        }
    }
    else if (ext_ch == 79) { // End
        while (*pos < (int)strlen(buffer)) {
            printf("%c", buffer[*pos]);
            (*pos)++;
        }
    }
}

// 处理退格键
void ftk_handle_backspace(char* buffer, int* pos) {
    if (*pos > 0) {
        (*pos)--;
        for (int i = *pos; i < (int)strlen(buffer); i++) {
            buffer[i] = buffer[i + 1];
        }
        ftk_update_display(buffer, *pos, MAX_COMMAND_LENGTH);
    }
}

// 处理Delete键
void ftk_handle_delete(char* buffer, int* pos) {
    if (*pos < (int)strlen(buffer)) {
        for (int i = *pos; i < (int)strlen(buffer); i++) {
            buffer[i] = buffer[i + 1];
        }
        ftk_update_display(buffer, *pos, MAX_COMMAND_LENGTH);
    }
}

// 添加到历史记录
void ftk_add_to_history(const char* command) {
    if (strlen(command) == 0) return;
    
    // 避免重复添加相同的命令
    if (g_history_count > 0 && strcmp(g_command_history[g_history_count - 1], command) == 0) {
        return;
    }
    
    if (g_history_count < 100) {
        strcpy_s(g_command_history[g_history_count], MAX_COMMAND_LENGTH, command);
        g_history_count++;
    } else {
        // 历史记录已满，移除最旧的记录
        for (int i = 0; i < 99; i++) {
            strcpy_s(g_command_history[i], MAX_COMMAND_LENGTH, g_command_history[i + 1]);
        }
        strcpy_s(g_command_history[99], MAX_COMMAND_LENGTH, command);
    }
    g_history_index = g_history_count;
}

// 显示命令历史
void ftk_show_command_history() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== 命令历史 (%d条) ===", g_history_count);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n\n");
    for (int i = 0; i < g_history_count; i++) {
        ftk_set_color(FOREGROUND_INTENSITY);
        printf("%3d. ", i + 1);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("%s\n", g_command_history[i]);
    }
}

// 输入函数 - 优化版本
int ftk_readline(char* buffer, int max_len) {
    int pos = 0;
    int ch;
    
    memset(buffer, 0, max_len);
    strcpy_s(g_current_input, MAX_COMMAND_LENGTH, "");
    g_cursor_pos = 0;
    
    while (1) {
        ch = _getch();
        
        if (ch == '\r' || ch == '\n') {
            printf("\n");
            buffer[pos] = '\0';
            if (pos > 0) {
                ftk_add_to_history(buffer);
            }
            strcpy_s(g_current_input, MAX_COMMAND_LENGTH, "");
            g_cursor_pos = 0;
            return pos;
        }
        else if (ch == '\t') {
            buffer[pos] = '\0';
            char matches[MAX_TAB_MATCHES][MAX_COMMAND_LENGTH];
            int match_count = 0;
            char* completed = ftk_tab_complete(buffer, &match_count, matches);
            
            if (completed != NULL) {
                strcpy_s(buffer, max_len, completed);
                pos = (int)strlen(completed);
                strcpy_s(g_current_input, MAX_COMMAND_LENGTH, completed);
                ftk_update_display(buffer, pos, max_len);
            } else if (match_count > 0) {
                ftk_update_display(buffer, pos, max_len);
            }
        }
        else if (ch == 0x00 || ch == 0xE0) {
            int ext_ch = _getch();
            ftk_handle_arrow_keys(ext_ch, buffer, &pos, max_len);
            ftk_handle_home_end(ext_ch, buffer, &pos);
            
            if (ext_ch == 83) { // Delete键
                ftk_handle_delete(buffer, &pos);
            }
        }
        else if (ch == 8 || ch == 127) {
            ftk_handle_backspace(buffer, &pos);
        }
        else if (ch == 3) { // Ctrl+C
            printf("^C\n");
            buffer[0] = '\0';
            strcpy_s(g_current_input, MAX_COMMAND_LENGTH, "");
            return -1;
        }
        else if (ch == 12) { // Ctrl+L
            system("cls");
            ftk_banner();
            ftk_print_prompt();
            printf("%s", buffer);
            // 重新定位光标
            int current_len = (int)strlen(buffer);
            if (pos < current_len) {
                for (int i = current_len; i > pos; i--) {
                    printf("\b");
                }
            }
        }
        else if (pos < max_len - 1 && ch >= 32 && ch <= 126) {
            // 插入字符
            if (pos < (int)strlen(buffer)) {
                for (int i = (int)strlen(buffer); i >= pos; i--) {
                    buffer[i + 1] = buffer[i];
                }
            }
            buffer[pos] = (char)ch;
            pos++;
            
            strcpy_s(g_current_input, MAX_COMMAND_LENGTH, buffer);
            ftk_update_display(buffer, pos, max_len);
        }
        
        g_cursor_pos = pos;
        fflush(stdout);
    }
}

// 触发蓝屏紧急避险
void ftk_trigger_bsod() {
    ftk_print_warning("\n[!!! 紧急警告 !!!]\n");
    ftk_print_warning("您即将触发系统蓝屏紧急避险！\n");
    ftk_print_warning("这将导致系统立即崩溃并重启！\n");
    ftk_print_warning("所有未保存的数据将会丢失！\n\n");
    
    printf("确认执行？(输入 'CONFIRM_BSOD' 继续): ");
    char confirmation[64];
    if (fgets(confirmation, sizeof(confirmation), stdin) != NULL) {
        confirmation[strcspn(confirmation, "\n")] = 0;
        if (strcmp(confirmation, "CONFIRM_BSOD") == 0) {
            ftk_print_error("\n[紧急避险] 触发系统蓝屏...\n");
            ftk_print_error("系统将在3秒后崩溃...\n");
            
            for (int i = 3; i > 0; i--) {
                ftk_print_error("%d...\n", i);
                Sleep(1000);
            }
            
            // 方法1: 使用NTAPI触发蓝屏
            HMODULE hNtdll = LoadLibraryA("ntdll.dll");
            if (hNtdll) {
                pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
                pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");
                
                if (RtlAdjustPrivilege && NtRaiseHardError) {
                    BOOLEAN Enabled;
                    // 启用调试权限
                    RtlAdjustPrivilege(19, TRUE, FALSE, &Enabled);
                    // 触发蓝屏
                    ULONG Response;
                    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
                }
                FreeLibrary(hNtdll);
            }
            
            // 方法2: 如果NTAPI失败，尝试终止关键系统进程
            ftk_print_warning("[警告] 蓝屏触发失败，尝试终止系统进程...\n");
            system("taskkill /f /im csrss.exe >nul 2>&1");
            system("taskkill /f /im winlogon.exe >nul 2>&1");
            
        } else {
            ftk_print_success("[取消] 紧急避险已取消\n");
        }
    }
}

// 检查是否为系统关键进程
int ftk_is_system_process(DWORD pid) {
    if (pid <= 4) return 1; // System, smss.exe等
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                // 检查是否为系统关键进程
                const char* system_processes[] = {
                    "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
                    "smss.exe", "system", "svchost.exe"
                };
                
                for (int i = 0; i < sizeof(system_processes)/sizeof(system_processes[0]); i++) {
                    if (_stricmp(pe.szExeFile, system_processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return 1;
                    }
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

// 紧急关机
void ftk_emergency_shutdown() {
    ftk_print_error("\n[紧急关机] 触发系统关机...\n");
    system("shutdown /s /f /t 0");
}

// 重新加载插件
void ftk_reload_plugins() {
    ftk_print_info("[INFO] 重新加载插件...\n");
    ftk_unload_plugins();
    ftk_load_plugins(0); // 非静默模式，显示加载信息
    ftk_print_success("[SUCCESS] 插件重新加载完成，共 %d 个插件\n", g_plugin_count);
}

// 改进的插件加载函数
void ftk_load_plugins(int silent) {
    if (GetFileAttributesA("plugins") == INVALID_FILE_ATTRIBUTES) {
        if (!silent) ftk_print_info("[INFO] 插件目录不存在，跳过插件加载\n");
        return;
    }
    
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA("plugins\\*.dll", &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        if (!silent) ftk_print_info("[INFO] 未找到插件文件\n");
        return;
    }
    
    int loaded_count = 0;
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char dll_path[MAX_PATH];
            sprintf_s(dll_path, sizeof(dll_path), "plugins\\%s", findFileData.cFileName);
            
            HMODULE hModule = LoadLibraryA(dll_path);
            if (hModule != NULL) {
                FTK_PLUGIN_INIT init_func = (FTK_PLUGIN_INIT)GetProcAddress(hModule, "ftk_plugin_init");
                FTK_PLUGIN_INFO info_func = (FTK_PLUGIN_INFO)GetProcAddress(hModule, "ftk_plugin_info");
                FTK_PLUGIN_CONFIG config_func = (FTK_PLUGIN_CONFIG)GetProcAddress(hModule, "ftk_plugin_config");
                
                if (init_func != NULL && info_func != NULL) {
                    if (g_plugin_count < MAX_PLUGINS) {
                        Plugin* plugin = &g_plugins[g_plugin_count];
                        
                        if (init_func() == 0) {
                            plugin->handle = hModule;
                            plugin->init_func = init_func;
                            plugin->execute_func = (FTK_PLUGIN_EXECUTE)GetProcAddress(hModule, "ftk_plugin_execute");
                            plugin->help_func = (FTK_PLUGIN_HELP)GetProcAddress(hModule, "ftk_plugin_help");
                            plugin->info_func = info_func;
                            plugin->config_func = config_func;
                            
                            // 调用插件配置回调（如果存在）
                            if (config_func != NULL) {
                                config_func(&g_main_config);
                            }
                            
                            const char* info = info_func();
                            if (info != NULL) {
                                char name[64], desc[128];
                                if (sscanf_s(info, "%63[^|]|%127[^\n]", name, (unsigned)sizeof(name), desc, (unsigned)sizeof(desc)) == 2) {
                                    strcpy_s(plugin->name, sizeof(plugin->name), name);
                                    strcpy_s(plugin->description, sizeof(plugin->description), desc);
                                } else {
                                    strcpy_s(plugin->name, sizeof(plugin->name), findFileData.cFileName);
                                    strcpy_s(plugin->description, sizeof(plugin->description), info);
                                }
                            } else {
                                strcpy_s(plugin->name, sizeof(plugin->name), findFileData.cFileName);
                                strcpy_s(plugin->description, sizeof(plugin->description), "无描述信息");
                            }
                            
                            if (!silent) {
                                ftk_print_plugin("[PLUGIN] 加载插件: %s - %s\n", plugin->name, plugin->description);
                            }
                            g_plugin_count++;
                            loaded_count++;
                        } else {
                            if (!silent) ftk_print_warning("[WARNING] 插件初始化失败: %s\n", findFileData.cFileName);
                            FreeLibrary(hModule);
                        }
                    } else {
                        if (!silent) ftk_print_warning("[WARNING] 插件数量已达上限，跳过: %s\n", findFileData.cFileName);
                        FreeLibrary(hModule);
                    }
                } else {
                    if (!silent) ftk_print_warning("[WARNING] 无效的插件格式: %s\n", findFileData.cFileName);
                    FreeLibrary(hModule);
                }
            } else {
                if (!silent) ftk_print_warning("[WARNING] 无法加载插件: %s\n", findFileData.cFileName);
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);
    
    FindClose(hFind);
    if (!silent) ftk_print_info("[INFO] 共加载 %d 个插件\n", loaded_count);
}

// 进程列表刷新函数
void ftk_refresh_process_list() {
    g_process_count = 0;
    memset(g_process_list, 0, sizeof(g_process_list));
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        ftk_print_error("[ERROR] 无法创建进程快照\n");
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe)) {
        ftk_print_error("[ERROR] 无法枚举进程\n");
        CloseHandle(hSnapshot);
        return;
    }
    
    do {
        if (g_process_count < MAX_PROCESSES) {
            ProcessInfo* info = &g_process_list[g_process_count];
            info->pid = pe.th32ProcessID;
            info->parent_pid = pe.th32ParentProcessID;
            strncpy_s(info->name, sizeof(info->name), pe.szExeFile, _TRUNCATE);
            info->thread_count = pe.cntThreads;
            
            // 获取进程用户名
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess != NULL) {
                strcpy_s(info->user, sizeof(info->user), "SYSTEM");
                
                // 获取内存使用情况
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info->memory_usage = pmc.WorkingSetSize;
                }
                
                CloseHandle(hProcess);
            } else {
                strcpy_s(info->user, sizeof(info->user), "ACCESS_DENIED");
                info->memory_usage = 0;
            }
            
            g_process_count++;
        }
    } while (Process32Next(hSnapshot, &pe) && g_process_count < MAX_PROCESSES);
    
    CloseHandle(hSnapshot);
}

// 进程列表显示函数
int ftk_list_processes(int detailed) {
    if (g_process_count == 0) {
        ftk_print_info("[INFO] 没有找到任何进程\n");
        return 0;
    }
    
    if (detailed) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n%-8s %-8s %-30s %-20s %-12s %-12s\n", 
               "PID", "PPID", "进程名", "用户", "线程数", "内存使用");
        ftk_set_color(FOREGROUND_INTENSITY);
        printf("----------------------------------------------------------------------------------------\n");
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        
        for (int i = 0; i < g_process_count; i++) {
            ProcessInfo* info = &g_process_list[i];
            double memory_mb = (double)info->memory_usage / (1024 * 1024);
            
            printf("%-8lu %-8lu %-30s %-20s %-12lu %-10.2fMB\n", 
                   info->pid, 
                   info->parent_pid,
                   info->name, 
                   info->user,
                   info->thread_count,
                   memory_mb);
        }
    } else {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n%-8s %-40s %-12s %-12s\n", "PID", "进程名", "线程数", "内存使用");
        ftk_set_color(FOREGROUND_INTENSITY);
        printf("------------------------------------------------------------\n");
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        
        for (int i = 0; i < g_process_count; i++) {
            ProcessInfo* info = &g_process_list[i];
            double memory_mb = (double)info->memory_usage / (1024 * 1024);
            
            printf("%-8lu %-40s %-12lu %-10.2fMB\n", 
                   info->pid, 
                   info->name, 
                   info->thread_count,
                   memory_mb);
        }
    }
    
    ftk_print_info("\n[INFO] 共显示 %d 个进程\n", g_process_count);
    return g_process_count;
}

// 其他功能函数（简化实现）
void ftk_create_process(const char* command) {
    if (strlen(command) == 0) {
        ftk_print_error("[ERROR] 请指定要启动的程序路径\n");
        return;
    }
    ftk_print_info("[INFO] 尝试创建进程: %s\n", command);
    ftk_print_info("[INFO] 此功能在当前版本中暂不可用\n");
}

int ftk_terminate_process(DWORD pid, int force) {
    ftk_print_info("[INFO] 尝试终止进程: PID=%lu\n", pid);
    ftk_print_info("[INFO] 此功能在当前版本中暂不可用\n");
    return 0;
}

void ftk_process_details(DWORD pid) {
    ftk_print_info("[INFO] 进程详情功能暂不可用\n");
}

void ftk_search_process(const char* pattern, int case_sensitive) {
    ftk_print_info("[INFO] 搜索功能暂不可用\n");
}

void ftk_monitor_processes(int interval) {
    ftk_print_info("[INFO] 启动进程监控...\n");
    
    // 直接调用监控插件
    ftk_execute_plugin("monitor", "");
}

void ftk_export_process_list(const char* filename) {
    ftk_print_info("[INFO] 导出功能暂不可用\n");
}

void ftk_get_process_tree(DWORD root_pid, int depth) {
    ftk_print_info("[INFO] 进程树功能暂不可用\n");
}

void ftk_analyze_suspicious() {
    ftk_print_info("[INFO] 分析功能暂不可用\n");
}

void ftk_detect_hollowing() {
    ftk_print_info("[INFO] 检测功能暂不可用\n");
}

DWORD ftk_find_process(const char* name, int exact_match) {
    ftk_print_info("[INFO] 查找进程功能暂不可用\n");
    return 0;
}

void ftk_log_operation(const char* operation, const char* target, int success) {
    // 简化实现
}

char* ftk_get_username_from_pid(DWORD pid) {
    char* username = (char*)malloc(32);
    if (username != NULL) {
        strcpy_s(username, 32, "SYSTEM");
    }
    return username;
}

char* ftk_format_time(FILETIME* ft) {
    char* buffer = (char*)malloc(64);
    if (buffer != NULL) {
        strcpy_s(buffer, 64, "N/A");
    }
    return buffer;
}

// 插件列表显示
void ftk_list_plugins() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== 已加载插件 (%d) ===", g_plugin_count);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n\n");
    
    if (g_plugin_count == 0) {
        ftk_print_info("没有加载任何插件\n");
        return;
    }
    
    for (int i = 0; i < g_plugin_count; i++) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("%d. %s\n", i + 1, g_plugins[i].name);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("   描述: %s\n", g_plugins[i].description);
        printf("   配置接口: %s\n", g_plugins[i].config_func ? "支持" : "不支持");
        printf("\n");
    }
}

// 插件帮助
void ftk_plugin_help(const char* plugin_name) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (_stricmp(g_plugins[i].name, plugin_name) == 0) {
            ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("\n=== %s 插件帮助 ===", plugin_name);
            ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("\n\n");
            if (g_plugins[i].help_func != NULL) {
                g_plugins[i].help_func();
            } else {
                ftk_print_info("该插件没有提供帮助信息\n");
            }
            
            if (g_plugins[i].config_func != NULL) {
                ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                printf("\n[插件特性] 支持主程序配置修改\n");
                ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            return;
        }
    }
    ftk_print_error("[ERROR] 未找到插件: %s\n", plugin_name);
}

// 执行插件
int ftk_execute_plugin(const char* plugin_name, const char* args) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (_stricmp(g_plugins[i].name, plugin_name) == 0) {
            if (g_plugins[i].execute_func != NULL) {
                ftk_print_plugin("[PLUGIN] 执行插件: %s", plugin_name);
                if (args != NULL && strlen(args) > 0) {
                    printf(" 参数: %s", args);
                }
                printf("\n");
                
                int result = g_plugins[i].execute_func(args);
                ftk_log_operation("PLUGIN_EXECUTE", plugin_name, result == 0);
                return 1;
            } else {
                ftk_print_error("[ERROR] 插件 '%s' 没有执行函数\n", plugin_name);
                return 1;
            }
        }
    }
    return 0;
}

// 卸载插件
void ftk_unload_plugins() {
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].handle != NULL) {
            FreeLibrary(g_plugins[i].handle);
        }
    }
    g_plugin_count = 0;
}

void ftk_banner() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n===============================================\n");
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("    %s\n", g_main_config.banner_text);
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("        %s\n", g_main_config.welcome_message);
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("===============================================\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    ftk_print_info("[INFO] 输入 'help' 查看命令列表\n");
    ftk_print_info("[INFO] 输入 'plugins' 查看已加载插件\n");
    if (g_main_config.enable_advanced_features) {
        ftk_print_warning("[INFO] 高级功能已启用 (紧急避险系统就绪)\n");
    }
}

void ftk_print_help() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== FTK 命令手册 ===\n\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("核心功能:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  list                    - 列出所有进程\n");
    printf("  list -d                 - 详细进程列表\n");
    printf("  plugins                 - 列出所有插件\n");
    printf("  plugin <name> help      - 查看插件帮助\n");
    printf("  reload                  - 重新加载所有插件\n");
    printf("  history                 - 显示命令历史\n");
    printf("  clear/cls               - 清屏\n\n");
    
    ftk_set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("紧急避险系统:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  debug bsod              - 触发系统蓝屏紧急避险\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("  ??  警告: 此命令将导致系统崩溃！\n\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    ftk_set_color(FOREGROUND_INTENSITY);
    printf("调试命令:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  test                    - 功能测试\n");
    printf("  debug                   - 调试信息\n\n");
    
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("系统命令:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  help                    - 显示此帮助\n");
    printf("  exit                    - 退出FTK\n");
}

int main() {
    // 设置控制台编码
    setup_console_encoding();
    
    // 启用虚拟终端处理
    ftk_enable_virtual_terminal();
    
    ftk_print_system("正在初始化 Forensic Toolkit...\n");
    
    char command[MAX_COMMAND_LENGTH];
    
    // 静默加载插件
    ftk_load_plugins(1); // 1 = 静默模式
    
    ftk_banner();
    ftk_init_input_system();
    
    // 初始刷新进程列表
    ftk_print_system("正在加载进程列表...\n");
    __try {
        ftk_refresh_process_list();
        ftk_print_success("初始化完成！找到 %d 个进程\n", g_process_count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ftk_print_error("[ERROR] 进程列表加载失败，程序将继续运行但功能可能受限\n");
        g_process_count = 0;
    }
    
    while (1) {
        ftk_print_prompt();
        fflush(stdout);
        
        int len = ftk_readline(command, sizeof(command));
        if (len == -1) {
            ftk_print_info("[INFO] 用户中断，退出程序\n");
            break;
        }
        if (len == 0) {
            continue;
        }
        
        // 命令解析
        if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
            ftk_print_info("[INFO] Forensic Toolkit 会话结束\n");
            break;
        }
        else if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0) {
            ftk_print_help();
        }
        else if (strcmp(command, "plugins") == 0) {
            ftk_list_plugins();
        }
        else if (strcmp(command, "history") == 0) {
            ftk_show_command_history();
        }
        else if (strcmp(command, "clear") == 0 || strcmp(command, "cls") == 0) {
            system("cls");
            ftk_banner();
        }
        else if (strcmp(command, "reload") == 0) {
            ftk_reload_plugins();
        }
        else if (strcmp(command, "debug bsod") == 0) {
            ftk_trigger_bsod();
        }
        else if (strcmp(command, "test") == 0) {
            ftk_print_debug("[TEST] 程序运行正常\n");
            ftk_print_debug("[TEST] 进程数量: %d\n", g_process_count);
            ftk_print_debug("[TEST] 插件数量: %d\n", g_plugin_count);
            ftk_print_debug("[TEST] 输入测试完成\n");
        }
        else if (strcmp(command, "debug") == 0) {
            ftk_print_debug("[DEBUG] 调试信息:\n");
            ftk_print_debug("  g_process_count: %d\n", g_process_count);
            ftk_print_debug("  g_plugin_count: %d\n", g_plugin_count);
            ftk_print_debug("  主程序配置: %s\n", g_main_config.banner_text);
            if (g_process_count > 0) {
                ftk_print_debug("  第一个进程: %s (PID: %lu)\n", g_process_list[0].name, g_process_list[0].pid);
            }
        }
        else if (strncmp(command, "plugin ", 7) == 0) {
            char plugin_name[64];
            char args[MAX_COMMAND_LENGTH] = "";
            
            if (sscanf_s(command + 7, "%63s %511[^\n]", plugin_name, (unsigned)sizeof(plugin_name), args, (unsigned)sizeof(args)) >= 1) {
                if (strcmp(args, "help") == 0) {
                    ftk_plugin_help(plugin_name);
                } else {
                    ftk_execute_plugin(plugin_name, args);
                }
            } else {
                ftk_print_error("[ERROR] 无效的插件命令格式\n");
            }
        }
        else if (strcmp(command, "list") == 0) {
            __try {
                ftk_refresh_process_list();
                ftk_list_processes(0);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_error("[ERROR] 进程列表操作失败\n");
            }
        }
        else if (strcmp(command, "list -d") == 0 || strcmp(command, "list detailed") == 0) {
            __try {
                ftk_refresh_process_list();
                ftk_list_processes(1);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_error("[ERROR] 进程列表操作失败\n");
            }
        }
        else if (strncmp(command, "create ", 7) == 0) {
            ftk_create_process(command + 7);
            __try {
                ftk_refresh_process_list();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_warning("[WARNING] 进程列表刷新失败\n");
            }
        }
        else if (strncmp(command, "kill ", 5) == 0) {
            DWORD pid = atoi(command + 5);
            if (pid > 0) {
                if (ftk_terminate_process(pid, 0)) {
                    __try {
                        ftk_refresh_process_list();
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        ftk_print_warning("[WARNING] 进程列表刷新失败\n");
                    }
                }
            } else {
                ftk_print_error("[ERROR] 无效的进程ID\n");
            }
        }
        else if (strncmp(command, "kill -f ", 8) == 0) {
            DWORD pid = atoi(command + 8);
            if (pid > 0) {
                if (ftk_terminate_process(pid, 1)) {
                    __try {
                        ftk_refresh_process_list();
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        ftk_print_warning("[WARNING] 进程列表刷新失败\n");
                    }
                }
            } else {
                ftk_print_error("[ERROR] 无效的进程ID\n");
            }
        }
        else if (strncmp(command, "killbyname ", 11) == 0) {
            DWORD pid = ftk_find_process(command + 11, 1);
            if (pid != 0) {
                ftk_print_info("找到进程: %s (PID: %lu)\n", command + 11, pid);
                if (ftk_terminate_process(pid, 0)) {
                    __try {
                        ftk_refresh_process_list();
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        ftk_print_warning("[WARNING] 进程列表刷新失败\n");
                    }
                }
            } else {
                ftk_print_warning("未找到进程: %s\n", command + 11);
            }
        }
        else if (strncmp(command, "details ", 8) == 0) {
            DWORD pid = atoi(command + 8);
            if (pid > 0) {
                ftk_process_details(pid);
            } else {
                ftk_print_error("[ERROR] 无效的进程ID\n");
            }
        }
        else if (strncmp(command, "search ", 7) == 0) {
            ftk_search_process(command + 7, 0);
        }
        else if (strncmp(command, "search -e ", 10) == 0) {
            ftk_search_process(command + 10, 1);
        }
        else if (strcmp(command, "monitor") == 0) {
            ftk_monitor_processes(5);
        }
        else if (strncmp(command, "monitor ", 8) == 0) {
            int interval = atoi(command + 8);
            if (interval > 0) {
                ftk_monitor_processes(interval);
            } else {
                ftk_monitor_processes(5);
            }
        }
        else if (strncmp(command, "export ", 7) == 0) {
            ftk_export_process_list(command + 7);
        }
        else if (strcmp(command, "tree") == 0) {
            ftk_refresh_process_list();
            ftk_get_process_tree(0, 0);
        }
        else if (strncmp(command, "tree ", 5) == 0) {
            DWORD root_pid = atoi(command + 5);
            ftk_refresh_process_list();
            ftk_get_process_tree(root_pid, 0);
        }
        else if (strcmp(command, "analyze") == 0) {
            ftk_refresh_process_list();
            ftk_analyze_suspicious();
        }
        else if (strcmp(command, "detect") == 0) {
            ftk_detect_hollowing();
        }
        else if (strcmp(command, "refresh") == 0) {
            ftk_refresh_process_list();
            ftk_print_info("[INFO] 进程列表已刷新\n");
        }
        else {
            // 尝试作为插件命令执行
            char plugin_cmd[64];
            char plugin_args[MAX_COMMAND_LENGTH] = "";
            
            if (sscanf_s(command, "%63s %511[^\n]", plugin_cmd, (unsigned)sizeof(plugin_cmd), plugin_args, (unsigned)sizeof(plugin_args)) >= 1) {
                if (!ftk_execute_plugin(plugin_cmd, plugin_args)) {
                    ftk_print_error("[ERROR] 未知命令: %s\n输入 'help' 查看可用命令\n", command);
                }
            } else {
                ftk_print_error("[ERROR] 未知命令: %s\n输入 'help' 查看可用命令\n", command);
            }
        }
    }
    
    ftk_unload_plugins();
    return 0;
}
