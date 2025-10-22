#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#define FTK_PLUGIN_API __declspec(dllexport)

#pragma comment(lib, "advapi32.lib")

FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[HASH] ��ϣ��������ʼ��\n");
    return 0;
}

// �����ļ���ϣ
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
        printf("[ERROR] ��֧�ֵĹ�ϣ�㷨: %s\n", hash_type);
        return -1;
    }
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] �޷����ļ�: %s\n", filename);
        return -1;
    }
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[64]; // �㹻��Ÿ��ֹ�ϣֵ
    DWORD hash_len = 0;
    DWORD bytes_read = 0;
    BYTE buffer[4096];
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        printf("[ERROR] �޷���ȡ����������\n");
        return -1;
    }
    
    if (!CryptCreateHash(hProv, algorithm, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        printf("[ERROR] �޷�������ϣ����\n");
        return -1;
    }
    
    // ��ȡ�ļ������¹�ϣ
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        if (!CryptHashData(hHash, buffer, bytes_read, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            printf("[ERROR] ��ϣ����ʧ��\n");
            return -1;
        }
    }
    
    // ��ȡ��ϣֵ
    DWORD dwHashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &dwHashLen, 0)) {
        printf("[ERROR] �޷���ȡ��ϣֵ\n");
    } else {
        printf("%s ��ϣֵ (%s):\n", filename, algorithm_name);
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
        printf("[ERROR] ��ָ���ļ����͹�ϣ����\n");
        printf("�÷�: hash <�ļ���> [��ϣ����]\n");
        printf("��ϣ����: md5, sha1, sha256 (Ĭ��: md5)\n");
        return -1;
    }
    
    // ��������
    if (sscanf_s(args, "%255s %9s", filename, (unsigned)sizeof(filename), 
                 hash_type, (unsigned)sizeof(hash_type)) < 1) {
        printf("[ERROR] ��������ʧ��\n");
        return -1;
    }
    
    return calculate_file_hash(filename, hash_type);
}

FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("��ϣ����������:\n");
    printf("  ����: �����ļ��Ĺ�ϣֵ\n");
    printf("  �÷�: hash <�ļ���> [��ϣ����]\n");
    printf("  ��ϣ����: md5, sha1, sha256\n");
    printf("  ʾ��: hash suspect.exe md5\n");
    printf("         hash malware.dll sha256\n");
    printf("         hash document.txt\n");
}

FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "hash|�ļ���ϣ������";
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