#include <windows.h>
#include "../detours/detours.h"
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <mutex>
#include <vector>
#include <thread>
#include <set>
#include <cctype>
#include <algorithm>
#include <future>
#include <deque>
#include <condition_variable>

// 线程池类
class ThreadPool {
public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop_front();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace_back(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers)
            worker.join();
    }

private:
    std::vector<std::thread> workers;
    std::deque<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// 全局线程池
ThreadPool* globalThreadPool = nullptr;

// 导出函数声明
extern "C" __declspec(dllexport) void StartHook();

// 日志全局变量
std::ofstream logFile;
std::mutex logMutex;
bool stopBackground = false;
std::vector<std::thread> backgroundThreads;

// 已经转储的文件路径（避免重复转储）
std::set<std::wstring> dumpedFiles;
std::mutex dumpedFilesMutex;

// 辅助函数：宽字符串转换为UTF-8
std::string WideToUTF8(const wchar_t* wstr) {
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size == 0) return "";
    
    std::vector<char> buffer(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer.data(), utf8Size, nullptr, nullptr);
    return std::string(buffer.data(), buffer.size() - 1); // 去掉null终止符
}

// 全局配置变量
int g_mode = 0;
std::set<std::wstring> g_suffixSet; // 后缀名列表集合

// 加载配置文件
void LoadConfig() {
    const wchar_t* iniPath = L".\\FilesDumper.ini";
    
    // 检查配置文件是否存在，不存在则创建
    if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
        WritePrivateProfileStringW(L"Settings", L"mode", L"0", iniPath);
        WritePrivateProfileStringW(L"Settings", L"suffixlist", L"vfa,exe,mp4", iniPath);
    }
    
    // 读取模式设置
    g_mode = GetPrivateProfileIntW(L"Settings", L"mode", 0, iniPath);
    
    // 读取后缀名列表
    // 读取后缀名列表
    wchar_t suffixList[256] = {0};
    GetPrivateProfileStringW(L"Settings", L"suffixlist", L"vfa,exe,mp4", suffixList, _countof(suffixList), iniPath);
    
    // 复制一份后缀列表用于日志（因为wcstok_s会修改原始字符串）
    wchar_t suffixListForLog[256];
    wcscpy_s(suffixListForLog, suffixList);
    
    // 分割后缀名并转换为小写
    wchar_t* next_token = nullptr;
    wchar_t* token = wcstok_s(suffixList, L",", &next_token);
    g_suffixSet.clear();
    while (token != nullptr) {
        std::wstring suffix = token;
        std::transform(suffix.begin(), suffix.end(), suffix.begin(), 
                       [](wchar_t c){ return std::tolower(c); });
        g_suffixSet.insert(suffix);
        token = wcstok_s(nullptr, L",", &next_token);
    }
    
    // 记录当前配置
    if (logFile.is_open()) {
        std::wstring modeDesc = (g_mode == 0) ? L"黑名单模式" : 
                                (g_mode == 1) ? L"白名单模式" : L"禁用模式";
        wchar_t buffer[256];
        swprintf_s(buffer, L"配置文件加载成功: mode=%d (%s)\r\n", g_mode, modeDesc.c_str());
        logFile << WideToUTF8(buffer) << WideToUTF8(L"后缀过滤列表: ") << WideToUTF8(suffixListForLog) << "\r\n";
        logFile.flush();
    }
}


// 初始化日志文件
void InitLogFile() {
    wchar_t logFilePath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, logFilePath);
    PathAppendW(logFilePath, L"FilesDumper.log");
    
    // 每次启动覆盖日志而不是追加
    logFile.open(logFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (logFile.is_open()) {
        // 写入UTF-8 BOM
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        logFile.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        
        // 写入初始日志并刷新
        logFile << WideToUTF8(L"===== Hook DLL 已加载 =====\r\n");
        logFile.flush();  // 确保日志实时写入
    }
}

#pragma comment(lib, "shlwapi.lib")

// 原始函数指针
static HANDLE (WINAPI * TrueCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) = CreateFileA;

// 安全转储文件（支持大文件分块处理）
void SafeDumpFile(wchar_t const* wpath) {
    // 检查是否已经转储过
    {
        std::lock_guard<std::mutex> lock(dumpedFilesMutex);
        if (dumpedFiles.find(wpath) != dumpedFiles.end()) {
            // 已经转储过，直接返回
            return;
        }
    }

    HANDLE hReadFile = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hReadFile == INVALID_HANDLE_VALUE) {
        if (logFile.is_open()) {
            wchar_t logBuffer[512];
            swprintf_s(logBuffer, L"打开文件失败: %s (错误代码: %lu)\r\n", wpath, GetLastError());
            logFile << WideToUTF8(logBuffer);
            logFile.flush();
        }
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hReadFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hReadFile);
        return;
    }

    // 创建转储目录
    wchar_t dumpDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, dumpDir);
    PathCombineW(dumpDir, dumpDir, L"dumpfiles");
    CreateDirectoryW(dumpDir, NULL);

    // 提取纯净文件名
    const wchar_t* lastBackslash = wcsrchr(wpath, L'\\');
    if (!lastBackslash) lastBackslash = wcsrchr(wpath, L'/');
    const wchar_t* pureFilename = lastBackslash ? lastBackslash + 1 : wpath;

    wchar_t dumpPath[MAX_PATH];
    PathCombineW(dumpPath, dumpDir, pureFilename);

    HANDLE hDumpFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hReadFile);
        if (logFile.is_open()) {
            wchar_t logBuffer[512];
            swprintf_s(logBuffer, L"创建转储文件失败: %s (错误代码: %lu)\r\n", dumpPath, GetLastError());
            logFile << WideToUTF8(logBuffer);
            logFile.flush();
        }
        return;
    }

    try {
        const DWORD bufferSize = 10 * 1024 * 1024; // 10MB 缓冲区
        std::vector<BYTE> buffer(bufferSize);
        DWORD64 totalBytesWritten = 0;
        DWORD bytesRead = 0;
        DWORD bytesWritten = 0;

        while (totalBytesWritten < static_cast<DWORD64>(fileSize.QuadPart)) {
            if (!ReadFile(hReadFile, buffer.data(), bufferSize, &bytesRead, NULL)) {
                // 读取错误处理
                DWORD error = GetLastError();
                if (logFile.is_open()) {
                    wchar_t logBuffer[512];
                    swprintf_s(logBuffer, L"文件读取错误: %s (位置: %llu, 错误代码: %lu)\r\n", 
                              wpath, totalBytesWritten, error);
                    logFile << WideToUTF8(logBuffer);
                    logFile.flush();
                }
                break;
            }

            if (bytesRead == 0) break; // 文件结束

            DWORD bytesToWrite = bytesRead;
            BYTE* currentPos = buffer.data();

            while (bytesToWrite > 0) {
                if (!WriteFile(hDumpFile, currentPos, bytesToWrite, &bytesWritten, NULL)) {
                    // 写入错误处理
                    if (logFile.is_open()) {
                        wchar_t logBuffer[512];
                        swprintf_s(logBuffer, L"转储写入错误: %s (位置: %llu, 错误代码: %lu)\r\n", 
                                  dumpPath, totalBytesWritten + (bytesRead - bytesToWrite), GetLastError());
                        logFile << WideToUTF8(logBuffer);
                        logFile.flush();
                    }
                    break;
                }

                bytesToWrite -= bytesWritten;
                currentPos += bytesWritten;
                totalBytesWritten += bytesWritten;
            }
        }

        // 成功转储日志
        if (logFile.is_open()) {
            wchar_t logBuffer[512];
            swprintf_s(logBuffer, L"文件转储完成: %s (大小: %llu 字节)\r\n", wpath, totalBytesWritten);
            logFile << WideToUTF8(logBuffer);
            logFile.flush();
        }

        // 添加到已转储集合
        std::lock_guard<std::mutex> lock(dumpedFilesMutex);
        dumpedFiles.insert(wpath);
    }
    catch (...) {
        if (logFile.is_open()) {
            wchar_t logBuffer[512];
            swprintf_s(logBuffer, L"转储过程中发生异常: %s\r\n", wpath);
            logFile << WideToUTF8(logBuffer);
            logFile.flush();
        }
    }

    CloseHandle(hReadFile);
    CloseHandle(hDumpFile);
}

// 钩子函数
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // 转换ANSI路径为宽字符
    int wlen = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, NULL, 0);
    wchar_t* wpath = new wchar_t[wlen];
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wpath, wlen);
    
    // === 新增：配置过滤逻辑开始 ===
    // 如果配置模式为禁用（-1），则不进行转储
    if (g_mode == -1) {
        // 记录日志：禁用模式跳过
        {
            std::lock_guard<std::mutex> lock(logMutex);
            if (logFile.is_open()) {
                wchar_t logBuffer[512];
                swprintf_s(logBuffer, L"文件跳过（禁用模式）: %s\r\n", wpath);
                logFile << WideToUTF8(logBuffer);
                logFile.flush();
            }
        }
        delete[] wpath;
        return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                              lpSecurityAttributes, dwCreationDisposition,
                              dwFlagsAndAttributes, hTemplateFile);
    }
    
    // 获取文件扩展名并检查是否匹配配置
    const wchar_t* ext = PathFindExtensionW(wpath);
    if (ext != NULL && *ext != L'\0') {
        std::wstring fileExt(ext + 1); // 去掉点号
        std::transform(fileExt.begin(), fileExt.end(), fileExt.begin(),
                      [](wchar_t c){ return std::tolower(c); });
                      
        bool inList = (g_suffixSet.find(fileExt) != g_suffixSet.end());
        
        // 黑白名单检查
        if (g_mode == 0) { // 黑名单模式：在名单中的跳过
    if (inList) {
        // 记录日志：黑名单模式跳过
        {
            std::lock_guard<std::mutex> lock(logMutex);
            if (logFile.is_open()) {
                wchar_t logBuffer[512];
                swprintf_s(logBuffer, L"文件跳过（黑名单模式）: %s\r\n", wpath);
                logFile << WideToUTF8(logBuffer);
                logFile.flush();
            }
        }
        delete[] wpath;
        return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                              lpSecurityAttributes, dwCreationDisposition,
                              dwFlagsAndAttributes, hTemplateFile);
    }
        } else if (g_mode == 1) { // 白名单模式：不在名单中的跳过
        if (!inList) {
            // 记录日志：白名单模式跳过
            {
                std::lock_guard<std::mutex> lock(logMutex);
                if (logFile.is_open()) {
                    wchar_t logBuffer[512];
                    swprintf_s(logBuffer, L"文件跳过（白名单模式）: %s\r\n", wpath);
                    logFile << WideToUTF8(logBuffer);
                    logFile.flush();
                }
            }
            delete[] wpath;
            return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                                  lpSecurityAttributes, dwCreationDisposition,
                                  dwFlagsAndAttributes, hTemplateFile);
        }
        }
    }
    // === 新增：配置过滤逻辑结束 ===
    
    HANDLE hFile = TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                                    lpSecurityAttributes, dwCreationDisposition,
                                    dwFlagsAndAttributes, hTemplateFile);
    if (hFile == INVALID_HANDLE_VALUE) {
        delete[] wpath;
        return hFile;
    }

    // 在后台线程进行文件转储
    if (globalThreadPool) {
        globalThreadPool->enqueue([wpath] {
            SafeDumpFile(wpath);
            delete[] wpath;
        });
    } else {
        // 失败时同步转储（应避免）
        SafeDumpFile(wpath);
        delete[] wpath;
    }

    return hFile;
}


// Detours入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        InitLogFile();
        LoadConfig(); // 新增：在初始化后加载配置
        
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourTransactionCommit();
        
        if (logFile.is_open()) {
            logFile << WideToUTF8(L"FilesDumper 已安装成功\r\n");
            logFile.flush();
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        // 首先卸载钩子，防止新任务加入线程池
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourTransactionCommit();

        // 删除线程池，让线程池优雅关闭
        if (globalThreadPool) {
            delete globalThreadPool;
            globalThreadPool = nullptr;
        }
    }
    
    return TRUE;
}

// 导出函数实现
extern "C" __declspec(dllexport) void StartHook() {
    // 占位函数
}
