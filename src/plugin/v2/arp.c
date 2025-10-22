#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// 完全避免使用winsock头文件，直接使用IP帮助API
#include <iphlpapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "iphlpapi.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[ARP] ARP表分析插件初始化\n");
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[ARP] 分析ARP表...\n\n");
    
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    // 第一次调用获取所需缓冲区大小
    dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
    if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
        printf("[ERROR] 获取ARP表大小失败: %lu\n", dwRetVal);
        return -1;
    }
    
    // 分配内存
    PMIB_IPNETTABLE pArpTable = (PMIB_IPNETTABLE)malloc(dwSize);
    if (pArpTable == NULL) {
        printf("[ERROR] 内存分配失败\n");
        return -1;
    }
    
    // 第二次调用获取实际数据
    dwRetVal = GetIpNetTable(pArpTable, &dwSize, FALSE);
    if (dwRetVal != NO_ERROR) {
        printf("[ERROR] 获取ARP表失败: %lu\n", dwRetVal);
        free(pArpTable);
        return -1;
    }
    
    printf("%-15s %-17s %-8s %-12s\n", "IP地址", "MAC地址", "类型", "接口索引");
    printf("----------------------------------------------------\n");
    
    int entry_count = 0;
    for (DWORD i = 0; i < pArpTable->dwNumEntries; i++) {
        MIB_IPNETROW* arpEntry = &pArpTable->table[i];
        
        // 转换IP地址
        char ipStr[16];
        sprintf_s(ipStr, sizeof(ipStr), "%d.%d.%d.%d",
                 (arpEntry->dwAddr & 0xFF),
                 ((arpEntry->dwAddr >> 8) & 0xFF),
                 ((arpEntry->dwAddr >> 16) & 0xFF),
                 ((arpEntry->dwAddr >> 24) & 0xFF));
        
        // 转换MAC地址
        char macStr[18];
        sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 arpEntry->bPhysAddr[0], arpEntry->bPhysAddr[1], arpEntry->bPhysAddr[2],
                 arpEntry->bPhysAddr[3], arpEntry->bPhysAddr[4], arpEntry->bPhysAddr[5]);
        
        // 类型描述
        char* typeStr;
        switch (arpEntry->dwType) {
            case 3: typeStr = "动态"; break;
            case 4: typeStr = "静态"; break;
            case 2: typeStr = "无效"; break;
            default: typeStr = "未知"; break;
        }
        
        printf("%-15s %-17s %-8s %-12lu\n", ipStr, macStr, typeStr, arpEntry->dwIndex);
        entry_count++;
    }
    
    if (entry_count == 0) {
        printf("未找到ARP表条目\n");
    } else {
        printf("\n总条目数: %d\n", entry_count);
    }
    
    free(pArpTable);
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("ARP表分析插件帮助:\n");
    printf("  功能: 显示系统ARP缓存表\n");
    printf("  用法: arp\n");
    printf("  输出: IP地址、MAC地址、类型和接口索引\n");
    printf("  类型: 动态 - 动态学习的ARP条目\n");
    printf("        静态 - 手动配置的ARP条目\n");
    printf("        无效 - 无效的ARP条目\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "arp|ARP缓存表分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}