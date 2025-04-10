// Note: Most of this was written by GPT.
#include <iostream>
#include <windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <thread>

UINT chromiumFormat = RegisterClipboardFormat(L"Chromium internal source URL");
UINT mozillaFormat = RegisterClipboardFormat(L"text/x-moz-url-priv");
UINT ieFormat = RegisterClipboardFormat(L"msSourceUrl");

std::string WideStringToNarrow(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wide[0], (int)wide.size(), NULL, 0, NULL, NULL);
    std::string narrow(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wide[0], (int)wide.size(), &narrow[0], size_needed, NULL, NULL);
    return narrow;
}

std::wstring NarrowStringToWide(const std::string& narrow) {
    if (narrow.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &narrow[0], (int)narrow.size(), NULL, 0);
    std::wstring wide(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &narrow[0], (int)narrow.size(), &wide[0], size_needed);
    return wide;
}

std::string toLower(std::string str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Function to get clipboard text
std::string GetClipboardText() {
    if (!OpenClipboard(nullptr)) return "";

    HANDLE hClipboardData = GetClipboardData(CF_UNICODETEXT);
    if (hClipboardData == nullptr) {
        CloseClipboard();
        return "";
    }

    wchar_t* pchData = (wchar_t*)GlobalLock(hClipboardData);
    if (pchData == nullptr) {
        CloseClipboard();
        return "";
    }

    std::string text = WideStringToNarrow(pchData);

    GlobalUnlock(hClipboardData);
    CloseClipboard();

    return text;
}

void ClearClipboard() {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }
}

void ShowMessageBoxOnThread(HWND hwnd, std::string message) {
    MessageBoxA(hwnd, message.c_str(), "DANGER!", MB_OK | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_ICONWARNING);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CLIPBOARDUPDATE: {
        // If the clipboard content was not added by a web platform, let it go.
        if (!IsClipboardFormatAvailable(chromiumFormat) &&
            !IsClipboardFormatAvailable(mozillaFormat) &&
            !IsClipboardFormatAvailable(ieFormat))
        {
            return 0;
        }

        std::string clipboardText = GetClipboardText();
        std::string lowerClipboardText = toLower(clipboardText);
        // TODO: Add your strings here IN LOWERCASE!
        std::vector<std::string> searchStrings = { "powershell", "mshta", "cmd.exe" };

        for (const auto& searchString : searchStrings) {
            if (lowerClipboardText.find(searchString) != std::string::npos) {
                std::string alertMessage = "Suspicious content from the Internet was found on the clipboard!\n\n" + clipboardText;
                OutputDebugStringA(alertMessage.c_str());
                std::thread(ShowMessageBoxOnThread, hwnd, alertMessage).detach(); // Start MessageBox on a new thread
                ClearClipboard();
                break;
            }
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"ClipboardListenerClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"ClipShield Listener", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 240, nullptr, nullptr, hInstance, nullptr);
    if (hwnd == nullptr) {
        return -1;
    }

    // Register for notification of clipboard changes.
    AddClipboardFormatListener(hwnd);

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveClipboardFormatListener(hwnd);
    return 0;
}