#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// ��Ȩ��������
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

// ������Ȩ����ӳ��
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
    printf("\n=== ����Ȩ�޷��� ===\n\n");
    
    DWORD targetPid = 0;
    if (args && strlen(args) > 0) {
        targetPid = atoi(args);
    }
    
    if (targetPid == 0) {
        targetPid = GetCurrentProcessId();
        printf("������ǰ���� (PID: %lu)\n\n", targetPid);
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) {
        printf("[ERROR] �޷��򿪽��� (PID: %lu) ����: %lu\n", targetPid, GetLastError());
        return -1;
    }
    
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("[ERROR] �޷��򿪽������� ����: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    
    // ��ȡ������Ϣ
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);
    
    if (tokenInfoLength > 0) {
        PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)malloc(tokenInfoLength);
        if (tokenPrivileges) {
            if (GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, tokenInfoLength, &tokenInfoLength)) {
                printf("��Ȩ����: %lu\n\n", tokenPrivileges->PrivilegeCount);
                printf("%-30s %-10s %s\n", "��Ȩ����", "״̬", "����");
                printf("--------------------------------------------------------\n");
                
                for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
                    const char* privilegeName = GetPrivilegeName(tokenPrivileges->Privileges[i].Luid);
                    const char* state = (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "����" : "����";
                    
                    printf("%-30s %-10s 0x%08lX\n", 
                           privilegeName, state, tokenPrivileges->Privileges[i].Attributes);
                }
            }
            free(tokenPrivileges);
        }
    }
    
    // ��ȡ��������
    TOKEN_TYPE tokenType;
    DWORD returnLength;
    if (GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &returnLength)) {
        printf("\n��������: %s\n", tokenType == TokenPrimary ? "������" : "ģ������");
    }
    
    // ��ȡ�ỰID
    DWORD sessionId;
    if (ProcessIdToSessionId(targetPid, &sessionId)) {
        printf("�ỰID: %lu\n", sessionId);
    }
    
    // ��ȡ�û���Ϣ
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
                printf("�û�: %s\\%s\n", domainName, userName);
            }
        }
        if (tokenUser) free(tokenUser);
    }
    
    CloseHandle(hToken);
    CloseHandle(hProcess);
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("Ȩ�޷����������:\n");
    printf("  ����: �������̵���Ȩ��Ȩ����Ϣ\n");
    printf("  �÷�: privileges [PID]\n");
    printf("  ����: PID - Ҫ�����Ľ���ID (��ѡ��Ĭ��Ϊ��ǰ����)\n");
    printf("  ���: ������Ȩ�б������Լ���������Ϣ��\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "privileges|����Ȩ�޷������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}