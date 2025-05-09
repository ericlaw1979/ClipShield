// https://textslashplain.com/2025/04/15/vibe-coding-for-security/
#include <iostream>
#include <windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <thread>
#include <amsi.h>
#include <chrono>

UINT chromiumFormat = RegisterClipboardFormat(L"Chromium internal source URL");
UINT mozillaFormat = RegisterClipboardFormat(L"text/x-moz-url-priv");
UINT ieFormat = RegisterClipboardFormat(L"msSourceUrl");
#define IDI_CLIPSHIELD 107

std::chrono::system_clock::time_point lastClipboardUpdate = std::chrono::system_clock::now();
HHOOK hKeyboardHook = nullptr;
bool bClipboardContentSuspicious = false;
HWND wndMain;

HAMSICONTEXT hAmsiContext = nullptr;
HAMSISESSION hAmsiSession = nullptr;

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

void ReplaceClipboardWithText(const std::string& text) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
        if (hMem) {
            wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
            if (pMem) {
                std::wstring wText = NarrowStringToWide(text);
                wcscpy_s(pMem, wText.size() + 1, wText.c_str());
                GlobalUnlock(hMem);
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
            else {
                GlobalFree(hMem);
            }
        }
        CloseClipboard();
    }
}

void ClearClipboard() {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }
}

/// <summary>
/// If the clipboard contents came from a web surface, return the content's URL.
/// </summary>
/// <returns>An empty string if the content isn't from a web surface, a URL if it did, or "about:internet" if the URL could not be read.</returns>
std::string GetAnySourceURL() {
    if (!IsClipboardFormatAvailable(chromiumFormat) && !IsClipboardFormatAvailable(mozillaFormat) && !IsClipboardFormatAvailable(ieFormat)) return "";

    if (!OpenClipboard(nullptr)) return "about:internet";

    HANDLE hClipboardData = GetClipboardData(chromiumFormat);
    if (hClipboardData == nullptr) {
        hClipboardData = GetClipboardData(mozillaFormat);
        if (hClipboardData == nullptr) {
            hClipboardData = GetClipboardData(ieFormat);
            if (hClipboardData == nullptr) {
                CloseClipboard();
                return "about:internet";
            }
        }
    }
    char* pchData = (char*)GlobalLock(hClipboardData);
    if (pchData == nullptr) {
        CloseClipboard();
        return "about:internet";
    }
    std::string text = pchData;
    GlobalUnlock(hClipboardData);
    CloseClipboard();
    return text;
}

void ShowMessageBoxOnThread(HWND hwnd, std::string message) {
    // ISSUE: MB_SYSTEMMODAL dialog boxes will show an icon in the title bar. But it's the wrong one!
    // TODO: Should we not pass the hwnd because it'll make the window show up on the wrong monitor (we want to show on the active monitor).
    MessageBoxA(hwnd, message.c_str(), "DANGER!", MB_OK | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_ICONWARNING);
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        PKBDLLHOOKSTRUCT pKeyStruct = (PKBDLLHOOKSTRUCT)lParam;
        if (wParam == WM_KEYDOWN) {
            PKBDLLHOOKSTRUCT pKeyStruct = (PKBDLLHOOKSTRUCT)lParam;
            if (pKeyStruct->vkCode == 'R') {
                if (GetAsyncKeyState(VK_LWIN) & 0x8000) {
                    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
                    std::chrono::seconds diff = std::chrono::duration_cast<std::chrono::seconds>(now - lastClipboardUpdate);
                    if (diff.count() <= 30) {
                        std::string alertMessage = "Pasting web content into the Run dialog is dangerous and could "
                                                   "result in attackers taking over your computer. Use extreme caution.";
                        std::thread(ShowMessageBoxOnThread, wndMain, alertMessage).detach();
                    }
                }
            }
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CLIPBOARDUPDATE: {
        lastClipboardUpdate = std::chrono::system_clock::now();
        bClipboardContentSuspicious = false;

        // If the clipboard content was not added by a web platform, let it go.
        std::string sURL = GetAnySourceURL();
        if (sURL.empty()) return 0;

        std::string clipboardText = GetClipboardText();
        std::string lowerClipboardText = toLower(clipboardText);

        // TODO: Add your first filter strings here IN LOWERCASE!
        std::vector<std::string> searchStrings = { "powershell", "mshta", "cmd", "msiexec"};

        bool bHadVirus = false;

        for (const auto& searchString : searchStrings) {
            if (lowerClipboardText.find(searchString) != std::string::npos) {
                bClipboardContentSuspicious = true;
                break;
            }
        }

        if (bClipboardContentSuspicious) {
            OutputDebugStringA("ClipShieldAMSIScanner found a suspicious web-originating string on the clipboard. Calling AV...");
            std::string avScanResultText = "";
            if (hAmsiContext != nullptr && hAmsiSession != nullptr) {
                AMSI_RESULT amsiResult;
                std::wstring wideClipboardText = NarrowStringToWide(clipboardText);
                std::wstring contentName = L"Clipboard Data from " + NarrowStringToWide(sURL);
                HRESULT hr = AmsiScanString(hAmsiContext, wideClipboardText.c_str(), contentName.c_str(), hAmsiSession, &amsiResult);

                std::wstringstream ss;
                ss << L"ClipShieldAMSIScanner AMSI Scan String" << std::endl << contentName.c_str() << std::endl << L"HRESULT: 0x" << std::hex << hr << std::endl;
                OutputDebugStringW(ss.str().c_str());

                if (SUCCEEDED(hr)) {
                    if (amsiResult == AMSI_RESULT_DETECTED) {
                        OutputDebugStringA("ClipShieldAMSIScanner AMSI Detected Malicious Content\n");
                        avScanResultText = "\n\n^^^ AV Scan indicates that this content is malicious, wiping it. ^^^";
                        bHadVirus = true;
                    }
                    else if (amsiResult == AMSI_RESULT_NOT_DETECTED) {
                        avScanResultText = "\n\nNo malicious content detected, but use caution when pasting anyway.";
                    }
                    else {
                        avScanResultText = "\n\nAV Scan was inconclusive. Use caution when pasting.";
                    }
                }
                else {
                    OutputDebugStringA("ClipShieldAMSIScanner AMSI Scan failed\n");
                }
            }

            std::string alertMessage = "Suspicious content from the Internet was found on the clipboard!\n\n" + clipboardText + avScanResultText;
            OutputDebugStringA(alertMessage.c_str());
            std::thread(ShowMessageBoxOnThread, hwnd, alertMessage).detach();
            if (bHadVirus) {
                bClipboardContentSuspicious = false;
                ReplaceClipboardWithText("ClipShield: Dangerous web content was removed from the clipboard.");
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

    HANDLE hSingleInstanceMutex = CreateMutex(nullptr, TRUE, L"ClipShieldSingleInstanceMutex");
    if (hSingleInstanceMutex == nullptr) return 2;

    // Another instance is already running
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hSingleInstanceMutex);
        return 3;
    }

    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CLIPSHIELD));
    RegisterClass(&wc);

    wndMain = CreateWindowEx(0, CLASS_NAME, L"ClipShield Listener", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 240, nullptr, nullptr, hInstance, nullptr);
    if (wndMain == nullptr) {
        OutputDebugStringA("ClipShield: Failed to create the hidden window.");
        CloseHandle(hSingleInstanceMutex);
        return -1;
    }

    // Debug Only
    // ShowWindow(wndMain, SW_SHOWDEFAULT);
    /* I had hoped that setting the icon this way would fix the sys-menu icon on the MessageBox, but it does not.
    HICON hIcon = static_cast<HICON>(LoadImage(
        GetModuleHandle(NULL), // Instance handle (use GetModuleHandle(NULL) for the current module)
        MAKEINTRESOURCE(IDI_CLIPSHIELD), // Resource identifier (replace IDI_CLIPSHIELD with your icon's ID)
        IMAGE_ICON,           // Type of image to load
        0,                    // Desired width (0 for default)
        0,                    // Desired height (0 for default)
        LR_DEFAULTSIZE        // Flags (use default size)
    ));

    if (hIcon) {
        // Set the large icon
        SendMessage(wndMain, WM_SETICON, ICON_BIG, (LPARAM)hIcon);

        // Optionally, set the small icon
         SendMessage(wndMain, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }*/

    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, hInstance, 0);
    if (hKeyboardHook == nullptr) {
        OutputDebugStringA("ClipShield: Failed to set keyboard hook.");
    }

    // Initialize AMSI
    HRESULT hr;

    hr = AmsiInitialize(L"ClipShieldAMSIScanner", &hAmsiContext);
    if (FAILED(hr)) {
        OutputDebugStringA("AMSI Initialization Failed\n");
        // Handle AMSI initialization failure (e.g., show a message box)
    }
    else {
        hr = AmsiOpenSession(hAmsiContext, &hAmsiSession);
        if (FAILED(hr)) {
            OutputDebugStringA("ClipShieldAMSIScanner AMSI Session Failed\n");
            AmsiUninitialize(hAmsiContext);
            hAmsiContext = nullptr;
        }
        else OutputDebugStringA("ClipShieldAMSIScanner AMSI Session Created\n");
    }

    // Register for notification of clipboard changes.
    AddClipboardFormatListener(wndMain);

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveClipboardFormatListener(wndMain);

    if (hKeyboardHook != nullptr) UnhookWindowsHookEx(hKeyboardHook);

    // Uninitialize AMSI
    if (hAmsiSession != nullptr && hAmsiContext != nullptr) {
        AmsiCloseSession(hAmsiContext, hAmsiSession);
    }
    if (hAmsiContext != nullptr) {
        AmsiUninitialize(hAmsiContext);
    }

    ReleaseMutex(hSingleInstanceMutex);
    CloseHandle(hSingleInstanceMutex);
    return 0;
}