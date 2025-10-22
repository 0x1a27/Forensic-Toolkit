#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// 特权常量定义
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_TCB_PRIVILEGE (6L)
#define SE_SECURITY_PRIVILEGE (7L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (8L)
#define SE_LOAD_DRIVER_PRIVILEGE (9L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (10L)
#define SE_SYSTEMTIME_PRIVILEGE (11L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (12L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (13L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (14L)
#define SE_CREATE_PERMANENT_PRIVILEGE (15L)
#define SE_BACKUP_PRIVILEGE (16L)
#define SE_RESTORE_PRIVILEGE (17L)
#define SE_SHUTDOWN_PRIVILEGE (18L)
#define SE_DEBUG_PRIVILEGE (19L)
#define SE_AUDIT_PRIVILEGE (20L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (21L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (22L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (23L)
#define SE_UNDOCK_PRIVILEGE (24L)
#define SE_SYNC_AGENT_PRIVILEGE (25L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (26L)
#define SE_MANAGE_VOLUME_PRIVILEGE (27L)
#define SE_IMPERSONATE_PRIVILEGE (28L)
#define SE_CREATE_GLOBAL_PRIVILEGE (29L)

// 常见特权名称映射
const char* GetPrivilegeName(LUID luid) {
    if (luid.LowPart == SE_DEBUG_PRIVILEGE) return "SeDebugPrivilege";
    if (luid.LowPart == SE_TCB_PRIVILEGE) return "SeTcbPrivilege";
    if (luid.LowPart == SE_BACKUP_PRIVILEGE) return "SeBackupPrivilege";
    if (luid.LowPart == SE_RESTORE_PRIVILEGE) return "SeRestorePrivilege";
    if (luid.LowPart == SE_TAKE_OWNERSHIP_PRIVILEGE) return "SeTakeOwnershipPrivilege";
    if (luid.LowPart == SE_LOAD_DRIVER_PRIVILEGE) return "SeLoadDriverPrivilege";
    if (luid.LowPart == SE_SYSTEMTIME_PRIVILEGE) return "SeSystemtimePrivilege";
    if (luid.LowPart == SE_SHUTDOWN_PRIVILEGE) return "SeShutdownPrivilege";
    if (luid.LowPart == SE_SECURITY_PRIVILEGE) return "SeSecurityPrivilege";
    if (luid.LowPart == SE_INCREASE_QUOTA_PRIVILEGE) return "SeIncreaseQuotaPrivilege";
    if (luid.LowPart == SE_ASSIGNPRIMARYTOKEN_PRIVILEGE) return "SeAssignPrimaryTokenPrivilege";
    return "Unknown";
}

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== 进程权限分析 ===\n\n");
    
    DWORD targetPid = 0;
    if (args && strlen(args) > 0) {
        targetPid = atoi(args);
    }
    
    if (targetPid == 0) {
        targetPid = GetCurrentProcessId();
        printf("分析当前进程 (PID: %lu)\n\n", targetPid);
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) {
        printf("[ERROR] 无法打开进程 (PID: %lu) 错误: %lu\n", targetPid, GetLastError());
        return -1;
    }
    
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("[ERROR] 无法打开进程令牌 错误: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    
    // 获取令牌信息
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);
    
    if (tokenInfoLength > 0) {
        PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)malloc(tokenInfoLength);
        if (tokenPrivileges) {
            if (GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, tokenInfoLength, &tokenInfoLength)) {
                printf("特权数量: %lu\n\n", tokenPrivileges->PrivilegeCount);
                printf("%-30s %-10s %s\n", "特权名称", "状态", "属性");
                printf("--------------------------------------------------------\n");
                
                for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
                    const char* privilegeName = GetPrivilegeName(tokenPrivileges->Privileges[i].Luid);
                    const char* state = (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "启用" : "禁用";
                    
                    printf("%-30s %-10s 0x%08lX\n", 
                           privilegeName, state, tokenPrivileges->Privileges[i].Attributes);
                }
            }
            free(tokenPrivileges);
        }
    }
    
    // 获取令牌类型
    TOKEN_TYPE tokenType;
    DWORD returnLength;
    if (GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &returnLength)) {
        printf("\n令牌类型: %s\n", tokenType == TokenPrimary ? "主令牌" : "模拟令牌");
    }
    
    // 获取会话ID
    DWORD sessionId;
    if (ProcessIdToSessionId(targetPid, &sessionId)) {
        printf("会话ID: %lu\n", sessionId);
    }
    
    // 获取用户信息
    DWORD userInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &userInfoLength);
    if (userInfoLength > 0) {
        PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(userInfoLength);
        if (tokenUser && GetTokenInformation(hToken, TokenUser, tokenUser, userInfoLength, &userInfoLength)) {
            SID_NAME_USE snu;
            char userName[256] = {0};
            char domainName[256] = {0};
            DWORD userSize = sizeof(userName);
            DWORD domainSize = sizeof(domainName);
            
            if (LookupAccountSidA(NULL, tokenUser->User.Sid, userName, &userSize, domainName, &domainSize, &snu)) {
                printf("用户: %s\\%s\n", domainName, userName);
            }
        }
        if (tokenUser) free(tokenUser);
    }
    
    CloseHandle(hToken);
    CloseHandle(hProcess);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("权限分析插件帮助:\n");
    printf("  功能: 分析进程的特权和权限信息\n");
    printf("  用法: privileges [PID]\n");
    printf("  参数: PID - 要分析的进程ID (可选，默认为当前进程)\n");
    printf("  输出: 进程特权列表、完整性级别、令牌信息等\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "privileges|进程权限分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}