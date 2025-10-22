#include <windows.h>
#include <stdio.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// 检查自启动位置
void CheckAutoRunLocations(void) {
    const char* locations[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    };
    
    const char* hives[] = {"HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"};
    HKEY rootKeys[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
    
    for (int hive = 0; hive < 2; hive++) {
        printf("%s:\n", hives[hive]);
        
        for (int i = 0; i < 5; i++) {
            HKEY hKey;
            if (RegOpenKeyExA(rootKeys[hive], locations[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                printf("  [√] %s\n", locations[i]);
                
                DWORD index = 0;
                char valueName[256];
                char valueData[1024];
                DWORD valueNameSize, valueDataSize, valueType;
                
                while (1) {
                    valueNameSize = sizeof(valueName);
                    valueDataSize = sizeof(valueData);
                    
                    if (RegEnumValueA(hKey, index, valueName, &valueNameSize, 
                        NULL, &valueType, (BYTE*)valueData, &valueDataSize) != ERROR_SUCCESS) {
                        break;
                    }
                    
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                        printf("      %s = %s\n", valueName, valueData);
                    }
                    
                    index++;
                }
                
                RegCloseKey(hKey);
            }
        }
        printf("\n");
    }
}

// 检查服务
void CheckServiceRegistry(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("系统服务 (显示前20个):\n");
        
        DWORD index = 0;
        char serviceName[256];
        DWORD serviceNameSize = sizeof(serviceName);
        
        int count = 0;
        while (RegEnumKeyExA(hKey, index, serviceName, &serviceNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && count < 20) {
            HKEY hServiceKey;
            char servicePath[512] = "";
            
            if (RegOpenKeyExA(hKey, serviceName, 0, KEY_READ, &hServiceKey) == ERROR_SUCCESS) {
                DWORD dataSize = sizeof(servicePath);
                RegQueryValueExA(hServiceKey, "ImagePath", NULL, NULL, (BYTE*)servicePath, &dataSize);
                RegCloseKey(hServiceKey);
                
                if (strlen(servicePath) > 0) {
                    printf("  %s\n      -> %s\n", serviceName, servicePath);
                    count++;
                }
            }
            
            index++;
            serviceNameSize = sizeof(serviceName);
        }
        
        RegCloseKey(hKey);
    }
}

// 检查浏览器插件
void CheckBrowserExtensions(void) {
    const char* browserKeys[] = {
        "SOFTWARE\\Microsoft\\Internet Explorer\\Extensions",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Internet Explorer\\Extensions",
        "SOFTWARE\\Google\\Chrome\\Extensions",
        "SOFTWARE\\Mozilla\\Firefox"
    };
    
    for (int i = 0; i < 4; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, browserKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            printf("浏览器扩展: %s\n", browserKeys[i]);
            
            DWORD index = 0;
            char subkeyName[256];
            DWORD subkeyNameSize = sizeof(subkeyName);
            
            while (RegEnumKeyExA(hKey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                printf("  %s\n", subkeyName);
                index++;
                subkeyNameSize = sizeof(subkeyName);
            }
            
            RegCloseKey(hKey);
        }
    }
}

FTK_PLUGIN_API int ftk_plugin_init(void) {
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("\n=== 注册表取证分析 ===\n\n");
    
    // 检查常见的自启动位置
    printf("=== 自启动项分析 ===\n\n");
    CheckAutoRunLocations();
    
    // 检查服务
    printf("\n=== 服务注册表项 ===\n\n");
    CheckServiceRegistry();
    
    // 检查浏览器插件
    printf("\n=== 浏览器插件 ===\n\n");
    CheckBrowserExtensions();
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("注册表分析插件帮助:\n");
    printf("  功能: 分析注册表中的自启动项、服务和浏览器插件\n");
    printf("  用法: registry\n");
    printf("  输出: 自启动程序、系统服务、浏览器扩展等注册表项\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "registry|注册表取证分析插件";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}