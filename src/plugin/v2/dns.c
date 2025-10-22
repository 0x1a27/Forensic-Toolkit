#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "iphlpapi.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[DNS] DNS缓存分析插件初始化\n");
    return 0;
}

// 使用兼容的DNS缓存查询方法
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[DNS] 分析DNS缓存...\n\n");
    
    // 使用系统命令获取DNS缓存（兼容性更好的方法）
    printf("正在执行系统DNS缓存查询...\n");
    system("ipconfig /displaydns");
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("DNS缓存分析插件帮助:\n");
    printf("  功能: 显示系统DNS缓存内容\n");
    printf("  用法: dns\n");
    printf("  输出: 使用ipconfig /displaydns显示DNS缓存\n");
    printf("  注意: 这种方法在所有Windows版本上都可用\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "dns|DNS缓存分析插件";
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