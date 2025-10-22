#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// ��ȫ����ʹ��winsockͷ�ļ���ֱ��ʹ��IP����API
#include <iphlpapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "iphlpapi.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[ARP] ARP����������ʼ��\n");
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[ARP] ����ARP��...\n\n");
    
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    // ��һ�ε��û�ȡ���軺������С
    dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
    if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
        printf("[ERROR] ��ȡARP���Сʧ��: %lu\n", dwRetVal);
        return -1;
    }
    
    // �����ڴ�
    PMIB_IPNETTABLE pArpTable = (PMIB_IPNETTABLE)malloc(dwSize);
    if (pArpTable == NULL) {
        printf("[ERROR] �ڴ����ʧ��\n");
        return -1;
    }
    
    // �ڶ��ε��û�ȡʵ������
    dwRetVal = GetIpNetTable(pArpTable, &dwSize, FALSE);
    if (dwRetVal != NO_ERROR) {
        printf("[ERROR] ��ȡARP��ʧ��: %lu\n", dwRetVal);
        free(pArpTable);
        return -1;
    }
    
    printf("%-15s %-17s %-8s %-12s\n", "IP��ַ", "MAC��ַ", "����", "�ӿ�����");
    printf("----------------------------------------------------\n");
    
    int entry_count = 0;
    for (DWORD i = 0; i < pArpTable->dwNumEntries; i++) {
        MIB_IPNETROW* arpEntry = &pArpTable->table[i];
        
        // ת��IP��ַ
        char ipStr[16];
        sprintf_s(ipStr, sizeof(ipStr), "%d.%d.%d.%d",
                 (arpEntry->dwAddr & 0xFF),
                 ((arpEntry->dwAddr >> 8) & 0xFF),
                 ((arpEntry->dwAddr >> 16) & 0xFF),
                 ((arpEntry->dwAddr >> 24) & 0xFF));
        
        // ת��MAC��ַ
        char macStr[18];
        sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 arpEntry->bPhysAddr[0], arpEntry->bPhysAddr[1], arpEntry->bPhysAddr[2],
                 arpEntry->bPhysAddr[3], arpEntry->bPhysAddr[4], arpEntry->bPhysAddr[5]);
        
        // ��������
        char* typeStr;
        switch (arpEntry->dwType) {
            case 3: typeStr = "��̬"; break;
            case 4: typeStr = "��̬"; break;
            case 2: typeStr = "��Ч"; break;
            default: typeStr = "δ֪"; break;
        }
        
        printf("%-15s %-17s %-8s %-12lu\n", ipStr, macStr, typeStr, arpEntry->dwIndex);
        entry_count++;
    }
    
    if (entry_count == 0) {
        printf("δ�ҵ�ARP����Ŀ\n");
    } else {
        printf("\n����Ŀ��: %d\n", entry_count);
    }
    
    free(pArpTable);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("ARP������������:\n");
    printf("  ����: ��ʾϵͳARP�����\n");
    printf("  �÷�: arp\n");
    printf("  ���: IP��ַ��MAC��ַ�����ͺͽӿ�����\n");
    printf("  ����: ��̬ - ��̬ѧϰ��ARP��Ŀ\n");
    printf("        ��̬ - �ֶ����õ�ARP��Ŀ\n");
    printf("        ��Ч - ��Ч��ARP��Ŀ\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "arp|ARP�����������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}