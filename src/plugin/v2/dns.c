#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "iphlpapi.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[DNS] DNS������������ʼ��\n");
    return 0;
}

// ʹ�ü��ݵ�DNS�����ѯ����
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[DNS] ����DNS����...\n\n");
    
    // ʹ��ϵͳ�����ȡDNS���棨�����Ը��õķ�����
    printf("����ִ��ϵͳDNS�����ѯ...\n");
    system("ipconfig /displaydns");
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("DNS��������������:\n");
    printf("  ����: ��ʾϵͳDNS��������\n");
    printf("  �÷�: dns\n");
    printf("  ���: ʹ��ipconfig /displaydns��ʾDNS����\n");
    printf("  ע��: ���ַ���������Windows�汾�϶�����\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "dns|DNS����������";
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