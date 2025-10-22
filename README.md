Forensic Toolkit (FTK) - 进程取证分析工具
📖 项目简介
Forensic Toolkit (FTK) 是一个专业的Windows进程取证分析工具，提供完整的进程管理、系统监控和紧急避险功能。采用模块化插件架构，支持功能扩展和自定义开发。

🚀 功能特性
核心功能
进程管理: 完整进程列表、详细信息查看、进程搜索

系统监控: 实时进程监控、资源使用分析

安全分析: 可疑进程检测、进程空心化检测

紧急避险: 系统蓝屏触发、紧急关机保护

高级特性
插件系统: 动态加载、热重载、配置接口

智能输入: Tab补全、命令历史、光标编辑

语言支持: 中文界面、GBK编码兼容

🛠️ 安装与使用
系统要求
Windows 7/8/10/11

Visual Studio 编译环境

管理员权限（部分功能）

编译说明
bash
# 使用 Visual Studio 编译
cl ftk_main.c /link user32.lib psapi.lib advapi32.lib ws2_32.lib iphlpapi.lib shell32.lib ntdll.lib
基本使用
bash
Forensic_Toolkit> help          # 查看帮助
Forensic_Toolkit> list          # 列出进程
Forensic_Toolkit> list -d       # 详细进程列表
Forensic_Toolkit> plugins       # 查看插件
Forensic_Toolkit> reload        # 重新加载插件
🔌 插件开发规范
插件文件结构
text
plugins/
├── example_plugin.dll          # 插件主文件
├── sysinfo_plugin.dll          # 系统信息插件
└── network_plugin.dll          # 网络分析插件
插件接口规范
1. 基本插件模板
c
#include <windows.h>
#include <stdio.h>

#define FTK_PLUGIN_API __declspec(dllexport)

// 必需函数: 插件初始化
FTK_PLUGIN_API int ftk_plugin_init(void) {
    printf("[PLUGIN] 示例插件初始化成功\n");
    return 0; // 返回0表示成功
}

// 必需函数: 插件信息
FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "example|示例插件描述信息";
}

// 必需函数: 插件执行
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("[EXAMPLE] 执行插件，参数: %s\n", args ? args : "无");
    // 插件主要逻辑
    return 0;
}

// 可选函数: 插件帮助
FTK_PLUGIN_API void ftk_plugin_help(void) {
    printf("示例插件帮助信息:\n");
    printf("  功能: 演示插件基本功能\n");
    printf("  用法: example [参数]\n");
    printf("  参数说明:\n");
    printf("    -info    显示详细信息\n");
    printf("    -test    测试模式\n");
}

// 可选函数: 主程序配置回调
FTK_PLUGIN_API void ftk_plugin_config(FTK_MAIN_CONFIG* config) {
    // 修改主程序配置
    strcpy(config->banner_text, "🔍 高级取证工具包 - 示例插件增强版");
    strcpy(config->welcome_message, "版本 2.2 | 示例插件 | 动态配置");
    config->enable_advanced_features = 1;
    printf("[PLUGIN] 示例插件已修改主程序配置\n");
}

// DLL入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL加载时的初始化
            break;
        case DLL_PROCESS_DETACH:
            // DLL卸载时的清理
            break;
    }
    return TRUE;
}
2. 插件信息格式
c
// 格式: "插件名称|插件描述"
FTK_PLUGIN_API const char* ftk_plugin_info(void) {
    return "sysinfo|系统信息收集插件 - 显示硬件和系统信息";
}
3. 返回值规范
0: 执行成功

1: 执行失败

-1: 参数错误

插件类型示例
系统信息插件
c
// sysinfo_plugin.c
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    if (args && strcmp(args, "cpu") == 0) {
        // 显示CPU信息
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        printf("CPU核心数: %lu\n", sysInfo.dwNumberOfProcessors);
    } else if (args && strcmp(args, "memory") == 0) {
        // 显示内存信息
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        GlobalMemoryStatusEx(&statex);
        printf("物理内存: %.2f GB\n", (double)statex.ullTotalPhys / (1024*1024*1024));
    } else {
        // 默认显示所有信息
        printf("系统信息插件 - 使用 'sysinfo cpu' 或 'sysinfo memory'\n");
    }
    return 0;
}
网络分析插件
c
// network_plugin.c
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    printf("网络连接分析:\n");
    // 实现网络连接枚举逻辑
    system("netstat -ano");
    return 0;
}

FTK_PLUGIN_API void ftk_plugin_config(FTK_MAIN_CONFIG* config) {
    strcpy(config->banner_text, "🌐 网络取证工具包");
    config->enable_advanced_features = 1;
}
文件分析插件
c
// file_plugin.c
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    if (!args) {
        printf("文件分析插件 - 请指定文件路径\n");
        return -1;
    }
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(args, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        printf("文件: %s\n", findData.cFileName);
        printf("大小: %lu bytes\n", findData.nFileSizeLow);
        FindClose(hFind);
    } else {
        printf("文件未找到: %s\n", args);
    }
    return 0;
}
插件开发指南
1. 编译插件
bash
# 编译为DLL
cl /LD example_plugin.c /link user32.lib

# 或使用Visual Studio项目
# 设置项目类型为"动态链接库(.dll)"
2. 插件部署
将编译好的DLL文件放入 plugins 目录：

text
Forensic_Toolkit.exe
plugins/
    example_plugin.dll
    sysinfo_plugin.dll
    network_plugin.dll
3. 插件调试
bash
# 在主程序中使用以下命令测试插件
Forensic_Toolkit> plugins           # 查看已加载插件
Forensic_Toolkit> example_plugin    # 执行插件
Forensic_Toolkit> reload            # 重新加载插件
高级插件功能
1. 配置主程序界面
c
FTK_PLUGIN_API void ftk_plugin_config(FTK_MAIN_CONFIG* config) {
    // 修改主程序标题和欢迎信息
    strcpy(config->banner_text, "🛡️ 安全分析平台 - 专业版");
    strcpy(config->welcome_message, "高级威胁检测 | 实时监控 | 应急响应");
    
    // 启用高级功能
    config->enable_advanced_features = 1;
    
    // 隐藏敏感信息（可选）
    config->hide_sensitive_info = 0;
}
2. 参数解析示例
c
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    if (!args || strlen(args) == 0) {
        printf("使用方法: plugin_name [选项]\n");
        printf("选项:\n");
        printf("  -scan    快速扫描\n");
        printf("  -deep    深度扫描\n");
        printf("  -report  生成报告\n");
        return 0;
    }
    
    if (strstr(args, "-scan")) {
        printf("执行快速扫描...\n");
        // 扫描逻辑
    } else if (strstr(args, "-deep")) {
        printf("执行深度扫描...\n");
        // 深度扫描逻辑
    } else if (strstr(args, "-report")) {
        printf("生成分析报告...\n");
        // 报告生成逻辑
    }
    
    return 0;
}
3. 错误处理最佳实践
c
FTK_PLUGIN_API int ftk_plugin_execute(const char* args) {
    __try {
        // 插件主要逻辑
        if (!some_operation()) {
            printf("[ERROR] 操作失败\n");
            return 1;
        }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[CRITICAL] 插件执行异常\n");
        return -1;
    }
}
插件开发注意事项
内存管理: 确保分配的内存正确释放

异常处理: 使用结构化异常处理避免崩溃

线程安全: 如果使用多线程，确保线程安全

资源清理: 在DLL卸载时清理所有资源

版本兼容: 确保与主程序版本的兼容性

常用Windows API参考
c
// 进程相关
CreateToolhelp32Snapshot()
Process32First()
Process32Next()
OpenProcess()
GetProcessMemoryInfo()

// 文件相关
CreateFile()
ReadFile()
WriteFile()
FindFirstFile()
FindNextFile()

// 系统信息
GetSystemInfo()
GlobalMemoryStatusEx()
GetVersionEx()

// 注册表
RegOpenKeyEx()
RegQueryValueEx()
RegEnumValue()

// 网络
GetTcpTable()
GetUdpTable()
GetAdaptersInfo()
⚠️ 安全警告
紧急避险功能
bash
# 触发系统蓝屏（需要确认）
Forensic_Toolkit> debug bsod

# 确认输入: CONFIRM_BSOD
警告: 此功能将导致系统立即崩溃，所有未保存数据将丢失！

🤝 贡献指南
Fork 本项目

创建功能分支 (git checkout -b feature/AmazingFeature)

提交更改 (git commit -m 'Add some AmazingFeature')

推送到分支 (git push origin feature/AmazingFeature)

开启 Pull Request

📄 许可证
本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。

🆘 技术支持
如有问题或建议，请提交 Issue 或联系开发团队。

注意: 本工具仅供教育和授权测试使用，不当使用造成的后果由使用者自行承担。
