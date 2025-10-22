#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "advapi32.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[HASH] 哈希计算插件初始化\n");
    return 0;
}

// 计算文件哈希
int calculate_file_hash(const char* filename, const char* hash_type) {
    ALG_ID algorithm;
    char* algorithm_name;
    
    if (strcmp(hash_type, "md5") == 0) {
        algorithm = CALG_MD5;
        algorithm_name = "MD5";
    } else if (strcmp(hash_type, "sha1") == 0) {
        algorithm = CALG_SHA1;
        algorithm_name = "SHA1";
    } else if (strcmp(hash_type, "sha256") == 0) {
        algorithm = CALG_SHA_256;
        algorithm_name = "SHA256";
    } else {
        printf("[ERROR] 不支持的哈希算法: %s\n", hash_type);
        return -1;
    }
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] 无法打开文件: %s\n", filename);
        return -1;
    }
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[64]; // 足够存放各种哈希值
    DWORD hash_len = 0;
    DWORD bytes_read = 0;
    BYTE buffer[4096];
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        printf("[ERROR] 无法获取加密上下文\n");
        return -1;
    }
    
    if (!CryptCreateHash(hProv, algorithm, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        printf("[ERROR] 无法创建哈希对象\n");
        return -1;
    }
    
    // 读取文件并更新哈希
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        if (!CryptHashData(hHash, buffer, bytes_read, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            printf("[ERROR] 哈希计算失败\n");
            return -1;
        }
    }
    
    // 获取哈希值
    DWORD dwHashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &dwHashLen, 0)) {
        printf("[ERROR] 无法获取哈希值\n");
    } else {
        printf("%s 哈希值 (%s):\n", filename, algorithm_name);
        for (DWORD i = 0; i < dwHashLen; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    
    return 0;
}

FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    char filename[MAX_PATH];
    char hash_type[10] = "md5";
    
    if (!args || strlen(args) == 0) {
        printf("[ERROR] 请指定文件名和哈希类型\n");
        printf("用法: hash <文件名> [哈希类型]\n");
        printf("哈希类型: md5, sha1, sha256 (默认: md5)\n");
        return -1;
    }
    
    // 解析参数
    if (sscanf_s(args, "%255s %9s", filename, (unsigned)sizeof(filename), 
                 hash_type, (unsigned)sizeof(hash_type)) < 1) {
        printf("[ERROR] 参数解析失败\n");
        return -1;
    }
    
    return calculate_file_hash(filename, hash_type);
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("哈希计算插件帮助:\n");
    printf("  功能: 计算文件的哈希值\n");
    printf("  用法: hash <文件名> [哈希类型]\n");
    printf("  哈希类型: md5, sha1, sha256\n");
    printf("  示例: hash suspect.exe md5\n");
    printf("         hash malware.dll sha256\n");
    printf("         hash document.txt\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "hash|文件哈希计算插件";
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