#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "advapi32.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== Windows������� ===\n\n");
    
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        printf("[ERROR] �޷��򿪷�����ƹ����� (����: %lu)\n", GetLastError());
        return -1;
    }
    
    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;
    
    // ��һ�ε��û�ȡ���軺������С
    EnumServicesStatusExA(
        scManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        NULL,
        0,
        &bytesNeeded,
        &serviceCount,
        &resumeHandle,
        NULL
    );
    
    if (GetLastError() != ERROR_MORE_DATA) {
        printf("[ERROR] ö�ٷ���ʧ��\n");
        CloseServiceHandle(scManager);
        return -1;
    }
    
    // ���仺����
    BYTE* buffer = (BYTE*)malloc(bytesNeeded);
    if (!buffer) {
        printf("[ERROR] �ڴ����ʧ��\n");
        CloseServiceHandle(scManager);
        return -1;
    }
    
    ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;
    
    // �ڶ��ε��û�ȡ������Ϣ
    if (EnumServicesStatusExA(
        scManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        buffer,
        bytesNeeded,
        &bytesNeeded,
        &serviceCount,
        &resumeHandle,
        NULL)) {
        
        printf("%-40s %-15s %-10s %s\n", "��������", "��ʾ����", "״̬", "����");
        printf("----------------------------------------------------------------------------------------\n");
        
        for (DWORD i = 0; i < serviceCount && i < 50; i++) { // ������ʾ����
            const char* state;
            switch (services[i].ServiceStatusProcess.dwCurrentState) {
                case SERVICE_STOPPED: state = "��ֹͣ"; break;
                case SERVICE_START_PENDING: state = "������"; break;
                case SERVICE_STOP_PENDING: state = "ֹͣ��"; break;
                case SERVICE_RUNNING: state = "������"; break;
                case SERVICE_CONTINUE_PENDING: state = "������"; break;
                case SERVICE_PAUSE_PENDING: state = "��ͣ��"; break;
                case SERVICE_PAUSED: state = "����ͣ"; break;
                default: state = "δ֪";
            }
            
            const char* type;
            switch (services[i].ServiceStatusProcess.dwServiceType) {
                case SERVICE_FILE_SYSTEM_DRIVER: type = "�ļ�ϵͳ����"; break;
                case SERVICE_KERNEL_DRIVER: type = "�ں�����"; break;
                case SERVICE_WIN32_OWN_PROCESS: type = "��������"; break;
                case SERVICE_WIN32_SHARE_PROCESS: type = "�������"; break;
                default: type = "����";
            }
            
            printf("%-40s %-15s %-10s %s\n", 
                   services[i].lpServiceName,
                   services[i].lpDisplayName,
                   state,
                   type);
        }
        
        printf("\n�ܹ����� %lu ������ (��ʾǰ50��)\n", serviceCount);
    }
    
    free(buffer);
    CloseServiceHandle(scManager);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("�������������:\n");
    printf("  ����: ö�ٺͷ���Windows����\n");
    printf("  �÷�: services\n");
    printf("  ���: ���з�������ơ�״̬�����͵���Ϣ\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "services|Windows����������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}