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

// ����ָʾ
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ntdll.lib")

// ��չ����ӿ� - �������޸�������
typedef struct {
    char banner_text[256];
    char welcome_message[256];
    int enable_advanced_features;
    int hide_sensitive_info;
} FTK_MAIN_CONFIG;

// ȫ������
FTK_MAIN_CONFIG g_main_config = {
    "Forensic Toolkit (FTK) - ����ȡ֤����",
    "�汾 2.2 | ��������ϵͳ | ��̬����ܹ�",
    1,  // enable_advanced_features
    0   // hide_sensitive_info
};

// ����ص���������
typedef void (*FTK_PLUGIN_CONFIG_CALLBACK)(FTK_MAIN_CONFIG* config);

// ���ݽṹ
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

// ��չ�������ָ�����Ͷ���
typedef int (*FTK_PLUGIN_INIT)(void);
typedef int (*FTK_PLUGIN_EXECUTE)(const char* args);
typedef void (*FTK_PLUGIN_HELP)(void);
typedef const char* (*FTK_PLUGIN_INFO)(void);
typedef void (*FTK_PLUGIN_CONFIG)(FTK_MAIN_CONFIG* config);  // �������ûص�

// ��չ����ṹ��
typedef struct {
    char name[64];
    char description[128];
    HMODULE handle;
    FTK_PLUGIN_INIT init_func;
    FTK_PLUGIN_EXECUTE execute_func;
    FTK_PLUGIN_HELP help_func;
    FTK_PLUGIN_INFO info_func;
    FTK_PLUGIN_CONFIG config_func;  // ���ûص�����
} Plugin;

// ȫ�ֱ���
ProcessInfo g_process_list[MAX_PROCESSES];
int g_process_count = 0;
Plugin g_plugins[MAX_PLUGINS];
int g_plugin_count = 0;

// ����ϵͳ��ر���
char g_command_history[100][MAX_COMMAND_LENGTH];
int g_history_count = 0;
int g_history_index = 0;
char g_current_input[MAX_COMMAND_LENGTH] = "";
int g_cursor_pos = 0;

// ��������
void ftk_banner();
void ftk_print_help();
void ftk_load_plugins(int silent);
void ftk_unload_plugins();
void ftk_reload_plugins();
void ftk_list_plugins();
void ftk_plugin_help(const char* plugin_name);
int ftk_execute_plugin(const char* plugin_name, const char* args);
const char* ftk_stristr(const char* str, const char* substr);

// ��ɫ�������
void ftk_print_error(const char* format, ...);
void ftk_print_success(const char* format, ...);
void ftk_print_warning(const char* format, ...);
void ftk_print_info(const char* format, ...);
void ftk_print_debug(const char* format, ...);
void ftk_print_plugin(const char* format, ...);
void ftk_print_system(const char* format, ...);
void ftk_enable_virtual_terminal();
void ftk_set_color(int color);

// ���Ĺ��ܺ���
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

// �������չ���
void ftk_trigger_bsod();
int ftk_is_system_process(DWORD pid);
void ftk_emergency_shutdown();

// �Ľ�������ϵͳ����
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

// �����б�
const char* g_commands[] = {
    "help", "exit", "quit", "list", "list -d", "list detailed",
    "create", "kill", "kill -f", "killbyname", "details", 
    "search", "search -e", "monitor", "export", "tree", 
    "analyze", "detect", "refresh", "test", "debug", "plugins",
    "plugin", "history", "clear", "cls", "reload", "bsod"
};
const int g_command_count = sizeof(g_commands) / sizeof(g_commands[0]);

// BSOD��غ������� (��Ҫntdll.lib)
typedef NTSTATUS (NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS (NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);

// ���������ն˴���
void ftk_enable_virtual_terminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// ������ɫ����
void ftk_set_color(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// ��ɫ�������ʵ�� - ʹ��Windows����̨API
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
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // ��ɫ
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_debug(const char* format, ...) {
    ftk_set_color(FOREGROUND_INTENSITY); // ��ɫ
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
}

void ftk_print_plugin(const char* format, ...) {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY); // ��ɫ
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

// �Զ��岻���ִ�Сд���ַ�����������
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

// ���ÿ���̨����ΪGBK������WindowsĬ�ϱ��룩
void setup_console_encoding() {
    SetConsoleOutputCP(936);
    SetConsoleCP(936);
}

// ��ʼ������ϵͳ
void ftk_init_input_system() {
    g_history_count = 0;
    g_history_index = 0;
    g_cursor_pos = 0;
    memset(g_command_history, 0, sizeof(g_command_history));
    memset(g_current_input, 0, sizeof(g_current_input));
}

// �����ǰ��
void ftk_clear_line(int length) {
    printf("\r");
    for (int i = 0; i < length + 50; i++) {
        printf(" ");
    }
    printf("\r");
}

// ��ӡ��ʾ��
void ftk_print_prompt() {
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\rForensic_Toolkit> ");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ��ʾƥ���б�
void ftk_display_matches(char matches[][MAX_COMMAND_LENGTH], int match_count) {
    printf("\n");
    int cols = 3; // ÿ����ʾ3��
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

// ���ҹ�ͬǰ׺
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
        if (j == 0) break; // û�й�ͬǰ׺
    }
    
    return common_prefix;
}

// Tab��ȫ���� - �Ż��汾
char* ftk_tab_complete(const char* current_input, int* match_count, char matches[][MAX_COMMAND_LENGTH]) {
    *match_count = 0;
    
    // �������Ϊ�գ���ʾ���п�������
    if (strlen(current_input) == 0) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n�������� (%d��):", g_command_count + g_plugin_count);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
        
        // ��ʾ��������
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("��������:");
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
        ftk_display_matches((char(*)[MAX_COMMAND_LENGTH])g_commands, g_command_count);
        
        // ��ʾ�������
        if (g_plugin_count > 0) {
            ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("�������:");
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
    
    // ������������
    for (int i = 0; i < g_command_count; i++) {
        if (strncmp(g_commands[i], current_input, strlen(current_input)) == 0) {
            strcpy_s(matches[*match_count], MAX_COMMAND_LENGTH, g_commands[i]);
            (*match_count)++;
            if (*match_count >= MAX_TAB_MATCHES) break;
        }
    }
    
    // �����������
    for (int i = 0; i < g_plugin_count; i++) {
        if (strncmp(g_plugins[i].name, current_input, strlen(current_input)) == 0) {
            strcpy_s(matches[*match_count], MAX_COMMAND_LENGTH, g_plugins[i].name);
            (*match_count)++;
            if (*match_count >= MAX_TAB_MATCHES) break;
        }
    }
    
    if (*match_count == 0) {
        printf("\a"); // ��������ʾ��ƥ��
        return NULL;
    }
    else if (*match_count == 1) {
        // ֻ��һ��ƥ�䣬ֱ�Ӳ�ȫ
        return matches[0];
    }
    else {
        // ���ƥ�䣬��ʾ�б����ع�ͬǰ׺
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n�ҵ� %d ��ƥ��:", *match_count);
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

// ������ʾ
void ftk_update_display(char* buffer, int pos, int max_len) {
    ftk_clear_line((int)strlen(buffer));
    ftk_print_prompt();
    printf("%s", buffer);
    
    // ���¶�λ���
    int current_len = (int)strlen(buffer);
    if (pos < current_len) {
        for (int i = current_len; i > pos; i--) {
            printf("\b");
        }
    }
    fflush(stdout);
}

// �������
void ftk_handle_arrow_keys(int ext_ch, char* buffer, int* pos, int max_len) {
    if (ext_ch == 72) { // �ϼ�ͷ
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
    else if (ext_ch == 80) { // �¼�ͷ
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
    else if (ext_ch == 75) { // ���ͷ
        if (*pos > 0) {
            (*pos)--;
            printf("\b");
        }
    }
    else if (ext_ch == 77) { // �Ҽ�ͷ
        if (*pos < (int)strlen(buffer)) {
            printf("%c", buffer[*pos]);
            (*pos)++;
        }
    }
}

// ����Home/End��
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

// �����˸��
void ftk_handle_backspace(char* buffer, int* pos) {
    if (*pos > 0) {
        (*pos)--;
        for (int i = *pos; i < (int)strlen(buffer); i++) {
            buffer[i] = buffer[i + 1];
        }
        ftk_update_display(buffer, *pos, MAX_COMMAND_LENGTH);
    }
}

// ����Delete��
void ftk_handle_delete(char* buffer, int* pos) {
    if (*pos < (int)strlen(buffer)) {
        for (int i = *pos; i < (int)strlen(buffer); i++) {
            buffer[i] = buffer[i + 1];
        }
        ftk_update_display(buffer, *pos, MAX_COMMAND_LENGTH);
    }
}

// ��ӵ���ʷ��¼
void ftk_add_to_history(const char* command) {
    if (strlen(command) == 0) return;
    
    // �����ظ������ͬ������
    if (g_history_count > 0 && strcmp(g_command_history[g_history_count - 1], command) == 0) {
        return;
    }
    
    if (g_history_count < 100) {
        strcpy_s(g_command_history[g_history_count], MAX_COMMAND_LENGTH, command);
        g_history_count++;
    } else {
        // ��ʷ��¼�������Ƴ���ɵļ�¼
        for (int i = 0; i < 99; i++) {
            strcpy_s(g_command_history[i], MAX_COMMAND_LENGTH, g_command_history[i + 1]);
        }
        strcpy_s(g_command_history[99], MAX_COMMAND_LENGTH, command);
    }
    g_history_index = g_history_count;
}

// ��ʾ������ʷ
void ftk_show_command_history() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== ������ʷ (%d��) ===", g_history_count);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n\n");
    for (int i = 0; i < g_history_count; i++) {
        ftk_set_color(FOREGROUND_INTENSITY);
        printf("%3d. ", i + 1);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("%s\n", g_command_history[i]);
    }
}

// ���뺯�� - �Ż��汾
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
            
            if (ext_ch == 83) { // Delete��
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
            // ���¶�λ���
            int current_len = (int)strlen(buffer);
            if (pos < current_len) {
                for (int i = current_len; i > pos; i--) {
                    printf("\b");
                }
            }
        }
        else if (pos < max_len - 1 && ch >= 32 && ch <= 126) {
            // �����ַ�
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

// ����������������
void ftk_trigger_bsod() {
    ftk_print_warning("\n[!!! �������� !!!]\n");
    ftk_print_warning("����������ϵͳ�����������գ�\n");
    ftk_print_warning("�⽫����ϵͳ����������������\n");
    ftk_print_warning("����δ��������ݽ��ᶪʧ��\n\n");
    
    printf("ȷ��ִ�У�(���� 'CONFIRM_BSOD' ����): ");
    char confirmation[64];
    if (fgets(confirmation, sizeof(confirmation), stdin) != NULL) {
        confirmation[strcspn(confirmation, "\n")] = 0;
        if (strcmp(confirmation, "CONFIRM_BSOD") == 0) {
            ftk_print_error("\n[��������] ����ϵͳ����...\n");
            ftk_print_error("ϵͳ����3������...\n");
            
            for (int i = 3; i > 0; i--) {
                ftk_print_error("%d...\n", i);
                Sleep(1000);
            }
            
            // ����1: ʹ��NTAPI��������
            HMODULE hNtdll = LoadLibraryA("ntdll.dll");
            if (hNtdll) {
                pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
                pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");
                
                if (RtlAdjustPrivilege && NtRaiseHardError) {
                    BOOLEAN Enabled;
                    // ���õ���Ȩ��
                    RtlAdjustPrivilege(19, TRUE, FALSE, &Enabled);
                    // ��������
                    ULONG Response;
                    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response);
                }
                FreeLibrary(hNtdll);
            }
            
            // ����2: ���NTAPIʧ�ܣ�������ֹ�ؼ�ϵͳ����
            ftk_print_warning("[����] ��������ʧ�ܣ�������ֹϵͳ����...\n");
            system("taskkill /f /im csrss.exe >nul 2>&1");
            system("taskkill /f /im winlogon.exe >nul 2>&1");
            
        } else {
            ftk_print_success("[ȡ��] ����������ȡ��\n");
        }
    }
}

// ����Ƿ�Ϊϵͳ�ؼ�����
int ftk_is_system_process(DWORD pid) {
    if (pid <= 4) return 1; // System, smss.exe��
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                // ����Ƿ�Ϊϵͳ�ؼ�����
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

// �����ػ�
void ftk_emergency_shutdown() {
    ftk_print_error("\n[�����ػ�] ����ϵͳ�ػ�...\n");
    system("shutdown /s /f /t 0");
}

// ���¼��ز��
void ftk_reload_plugins() {
    ftk_print_info("[INFO] ���¼��ز��...\n");
    ftk_unload_plugins();
    ftk_load_plugins(0); // �Ǿ�Ĭģʽ����ʾ������Ϣ
    ftk_print_success("[SUCCESS] ������¼�����ɣ��� %d �����\n", g_plugin_count);
}

// �Ľ��Ĳ�����غ���
void ftk_load_plugins(int silent) {
    if (GetFileAttributesA("plugins") == INVALID_FILE_ATTRIBUTES) {
        if (!silent) ftk_print_info("[INFO] ���Ŀ¼�����ڣ������������\n");
        return;
    }
    
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA("plugins\\*.dll", &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        if (!silent) ftk_print_info("[INFO] δ�ҵ�����ļ�\n");
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
                            
                            // ���ò�����ûص���������ڣ�
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
                                strcpy_s(plugin->description, sizeof(plugin->description), "��������Ϣ");
                            }
                            
                            if (!silent) {
                                ftk_print_plugin("[PLUGIN] ���ز��: %s - %s\n", plugin->name, plugin->description);
                            }
                            g_plugin_count++;
                            loaded_count++;
                        } else {
                            if (!silent) ftk_print_warning("[WARNING] �����ʼ��ʧ��: %s\n", findFileData.cFileName);
                            FreeLibrary(hModule);
                        }
                    } else {
                        if (!silent) ftk_print_warning("[WARNING] ��������Ѵ����ޣ�����: %s\n", findFileData.cFileName);
                        FreeLibrary(hModule);
                    }
                } else {
                    if (!silent) ftk_print_warning("[WARNING] ��Ч�Ĳ����ʽ: %s\n", findFileData.cFileName);
                    FreeLibrary(hModule);
                }
            } else {
                if (!silent) ftk_print_warning("[WARNING] �޷����ز��: %s\n", findFileData.cFileName);
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);
    
    FindClose(hFind);
    if (!silent) ftk_print_info("[INFO] ������ %d �����\n", loaded_count);
}

// �����б�ˢ�º���
void ftk_refresh_process_list() {
    g_process_count = 0;
    memset(g_process_list, 0, sizeof(g_process_list));
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        ftk_print_error("[ERROR] �޷��������̿���\n");
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe)) {
        ftk_print_error("[ERROR] �޷�ö�ٽ���\n");
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
            
            // ��ȡ�����û���
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess != NULL) {
                strcpy_s(info->user, sizeof(info->user), "SYSTEM");
                
                // ��ȡ�ڴ�ʹ�����
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

// �����б���ʾ����
int ftk_list_processes(int detailed) {
    if (g_process_count == 0) {
        ftk_print_info("[INFO] û���ҵ��κν���\n");
        return 0;
    }
    
    if (detailed) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\n%-8s %-8s %-30s %-20s %-12s %-12s\n", 
               "PID", "PPID", "������", "�û�", "�߳���", "�ڴ�ʹ��");
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
        printf("\n%-8s %-40s %-12s %-12s\n", "PID", "������", "�߳���", "�ڴ�ʹ��");
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
    
    ftk_print_info("\n[INFO] ����ʾ %d ������\n", g_process_count);
    return g_process_count;
}

// �������ܺ�������ʵ�֣�
void ftk_create_process(const char* command) {
    if (strlen(command) == 0) {
        ftk_print_error("[ERROR] ��ָ��Ҫ�����ĳ���·��\n");
        return;
    }
    ftk_print_info("[INFO] ���Դ�������: %s\n", command);
    ftk_print_info("[INFO] �˹����ڵ�ǰ�汾���ݲ�����\n");
}

int ftk_terminate_process(DWORD pid, int force) {
    ftk_print_info("[INFO] ������ֹ����: PID=%lu\n", pid);
    ftk_print_info("[INFO] �˹����ڵ�ǰ�汾���ݲ�����\n");
    return 0;
}

void ftk_process_details(DWORD pid) {
    ftk_print_info("[INFO] �������鹦���ݲ�����\n");
}

void ftk_search_process(const char* pattern, int case_sensitive) {
    ftk_print_info("[INFO] ���������ݲ�����\n");
}

void ftk_monitor_processes(int interval) {
    ftk_print_info("[INFO] �������̼��...\n");
    
    // ֱ�ӵ��ü�ز��
    ftk_execute_plugin("monitor", "");
}

void ftk_export_process_list(const char* filename) {
    ftk_print_info("[INFO] ���������ݲ�����\n");
}

void ftk_get_process_tree(DWORD root_pid, int depth) {
    ftk_print_info("[INFO] �����������ݲ�����\n");
}

void ftk_analyze_suspicious() {
    ftk_print_info("[INFO] ���������ݲ�����\n");
}

void ftk_detect_hollowing() {
    ftk_print_info("[INFO] ��⹦���ݲ�����\n");
}

DWORD ftk_find_process(const char* name, int exact_match) {
    ftk_print_info("[INFO] ���ҽ��̹����ݲ�����\n");
    return 0;
}

void ftk_log_operation(const char* operation, const char* target, int success) {
    // ��ʵ��
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

// ����б���ʾ
void ftk_list_plugins() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== �Ѽ��ز�� (%d) ===", g_plugin_count);
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n\n");
    
    if (g_plugin_count == 0) {
        ftk_print_info("û�м����κβ��\n");
        return;
    }
    
    for (int i = 0; i < g_plugin_count; i++) {
        ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("%d. %s\n", i + 1, g_plugins[i].name);
        ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("   ����: %s\n", g_plugins[i].description);
        printf("   ���ýӿ�: %s\n", g_plugins[i].config_func ? "֧��" : "��֧��");
        printf("\n");
    }
}

// �������
void ftk_plugin_help(const char* plugin_name) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (_stricmp(g_plugins[i].name, plugin_name) == 0) {
            ftk_set_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("\n=== %s ������� ===", plugin_name);
            ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("\n\n");
            if (g_plugins[i].help_func != NULL) {
                g_plugins[i].help_func();
            } else {
                ftk_print_info("�ò��û���ṩ������Ϣ\n");
            }
            
            if (g_plugins[i].config_func != NULL) {
                ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                printf("\n[�������] ֧�������������޸�\n");
                ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            return;
        }
    }
    ftk_print_error("[ERROR] δ�ҵ����: %s\n", plugin_name);
}

// ִ�в��
int ftk_execute_plugin(const char* plugin_name, const char* args) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (_stricmp(g_plugins[i].name, plugin_name) == 0) {
            if (g_plugins[i].execute_func != NULL) {
                ftk_print_plugin("[PLUGIN] ִ�в��: %s", plugin_name);
                if (args != NULL && strlen(args) > 0) {
                    printf(" ����: %s", args);
                }
                printf("\n");
                
                int result = g_plugins[i].execute_func(args);
                ftk_log_operation("PLUGIN_EXECUTE", plugin_name, result == 0);
                return 1;
            } else {
                ftk_print_error("[ERROR] ��� '%s' û��ִ�к���\n", plugin_name);
                return 1;
            }
        }
    }
    return 0;
}

// ж�ز��
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
    
    ftk_print_info("[INFO] ���� 'help' �鿴�����б�\n");
    ftk_print_info("[INFO] ���� 'plugins' �鿴�Ѽ��ز��\n");
    if (g_main_config.enable_advanced_features) {
        ftk_print_warning("[INFO] �߼����������� (��������ϵͳ����)\n");
    }
}

void ftk_print_help() {
    ftk_set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n=== FTK �����ֲ� ===\n\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("���Ĺ���:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  list                    - �г����н���\n");
    printf("  list -d                 - ��ϸ�����б�\n");
    printf("  plugins                 - �г����в��\n");
    printf("  plugin <name> help      - �鿴�������\n");
    printf("  reload                  - ���¼������в��\n");
    printf("  history                 - ��ʾ������ʷ\n");
    printf("  clear/cls               - ����\n\n");
    
    ftk_set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("��������ϵͳ:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  debug bsod              - ����ϵͳ������������\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("  ??  ����: ���������ϵͳ������\n\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    ftk_set_color(FOREGROUND_INTENSITY);
    printf("��������:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  test                    - ���ܲ���\n");
    printf("  debug                   - ������Ϣ\n\n");
    
    ftk_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("ϵͳ����:\n");
    ftk_set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("  help                    - ��ʾ�˰���\n");
    printf("  exit                    - �˳�FTK\n");
}

int main() {
    // ���ÿ���̨����
    setup_console_encoding();
    
    // ���������ն˴���
    ftk_enable_virtual_terminal();
    
    ftk_print_system("���ڳ�ʼ�� Forensic Toolkit...\n");
    
    char command[MAX_COMMAND_LENGTH];
    
    // ��Ĭ���ز��
    ftk_load_plugins(1); // 1 = ��Ĭģʽ
    
    ftk_banner();
    ftk_init_input_system();
    
    // ��ʼˢ�½����б�
    ftk_print_system("���ڼ��ؽ����б�...\n");
    __try {
        ftk_refresh_process_list();
        ftk_print_success("��ʼ����ɣ��ҵ� %d ������\n", g_process_count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ftk_print_error("[ERROR] �����б����ʧ�ܣ����򽫼������е����ܿ�������\n");
        g_process_count = 0;
    }
    
    while (1) {
        ftk_print_prompt();
        fflush(stdout);
        
        int len = ftk_readline(command, sizeof(command));
        if (len == -1) {
            ftk_print_info("[INFO] �û��жϣ��˳�����\n");
            break;
        }
        if (len == 0) {
            continue;
        }
        
        // �������
        if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
            ftk_print_info("[INFO] Forensic Toolkit �Ự����\n");
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
            ftk_print_debug("[TEST] ������������\n");
            ftk_print_debug("[TEST] ��������: %d\n", g_process_count);
            ftk_print_debug("[TEST] �������: %d\n", g_plugin_count);
            ftk_print_debug("[TEST] ����������\n");
        }
        else if (strcmp(command, "debug") == 0) {
            ftk_print_debug("[DEBUG] ������Ϣ:\n");
            ftk_print_debug("  g_process_count: %d\n", g_process_count);
            ftk_print_debug("  g_plugin_count: %d\n", g_plugin_count);
            ftk_print_debug("  ����������: %s\n", g_main_config.banner_text);
            if (g_process_count > 0) {
                ftk_print_debug("  ��һ������: %s (PID: %lu)\n", g_process_list[0].name, g_process_list[0].pid);
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
                ftk_print_error("[ERROR] ��Ч�Ĳ�������ʽ\n");
            }
        }
        else if (strcmp(command, "list") == 0) {
            __try {
                ftk_refresh_process_list();
                ftk_list_processes(0);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_error("[ERROR] �����б����ʧ��\n");
            }
        }
        else if (strcmp(command, "list -d") == 0 || strcmp(command, "list detailed") == 0) {
            __try {
                ftk_refresh_process_list();
                ftk_list_processes(1);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_error("[ERROR] �����б����ʧ��\n");
            }
        }
        else if (strncmp(command, "create ", 7) == 0) {
            ftk_create_process(command + 7);
            __try {
                ftk_refresh_process_list();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ftk_print_warning("[WARNING] �����б�ˢ��ʧ��\n");
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
                        ftk_print_warning("[WARNING] �����б�ˢ��ʧ��\n");
                    }
                }
            } else {
                ftk_print_error("[ERROR] ��Ч�Ľ���ID\n");
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
                        ftk_print_warning("[WARNING] �����б�ˢ��ʧ��\n");
                    }
                }
            } else {
                ftk_print_error("[ERROR] ��Ч�Ľ���ID\n");
            }
        }
        else if (strncmp(command, "killbyname ", 11) == 0) {
            DWORD pid = ftk_find_process(command + 11, 1);
            if (pid != 0) {
                ftk_print_info("�ҵ�����: %s (PID: %lu)\n", command + 11, pid);
                if (ftk_terminate_process(pid, 0)) {
                    __try {
                        ftk_refresh_process_list();
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        ftk_print_warning("[WARNING] �����б�ˢ��ʧ��\n");
                    }
                }
            } else {
                ftk_print_warning("δ�ҵ�����: %s\n", command + 11);
            }
        }
        else if (strncmp(command, "details ", 8) == 0) {
            DWORD pid = atoi(command + 8);
            if (pid > 0) {
                ftk_process_details(pid);
            } else {
                ftk_print_error("[ERROR] ��Ч�Ľ���ID\n");
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
            ftk_print_info("[INFO] �����б���ˢ��\n");
        }
        else {
            // ������Ϊ�������ִ��
            char plugin_cmd[64];
            char plugin_args[MAX_COMMAND_LENGTH] = "";
            
            if (sscanf_s(command, "%63s %511[^\n]", plugin_cmd, (unsigned)sizeof(plugin_cmd), plugin_args, (unsigned)sizeof(plugin_args)) >= 1) {
                if (!ftk_execute_plugin(plugin_cmd, plugin_args)) {
                    ftk_print_error("[ERROR] δ֪����: %s\n���� 'help' �鿴��������\n", command);
                }
            } else {
                ftk_print_error("[ERROR] δ֪����: %s\n���� 'help' �鿴��������\n", command);
            }
        }
    }
    
    ftk_unload_plugins();
    return 0;
}