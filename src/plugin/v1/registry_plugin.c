#include <windows.h>
#include <stdio.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// ���������λ��
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
                printf("  [��] %s\n", locations[i]);
                
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

// ������
void CheckServiceRegistry(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("ϵͳ���� (��ʾǰ20��):\n");
        
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

// �����������
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
            printf("�������չ: %s\n", browserKeys[i]);
            
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
    printf("\n=== ע���ȡ֤���� ===\n\n");
    
    // ��鳣����������λ��
    printf("=== ����������� ===\n\n");
    CheckAutoRunLocations();
    
    // ������
    printf("\n=== ����ע����� ===\n\n");
    CheckServiceRegistry();
    
    // �����������
    printf("\n=== �������� ===\n\n");
    CheckBrowserExtensions();
    
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("ע�������������:\n");
    printf("  ����: ����ע����е���������������������\n");
    printf("  �÷�: registry\n");
    printf("  ���: ����������ϵͳ�����������չ��ע�����\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "registry|ע���ȡ֤�������";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}