#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")

// Функция для преобразования string в wstring
std::wstring s2ws(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// Функция для кодирования данных для URL
std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~' || c == ':' || c == '/' || c == '+') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int((unsigned char)c);
        }
    }

    return escaped.str();
}

// Функция для экранирования JSON-строки
std::string json_escape(const std::string& str) {
    std::string result = str;
    size_t pos = 0;
    while ((pos = result.find("\\", pos)) != std::string::npos) {
        result.replace(pos, 1, "\\\\");
        pos += 2;
    }
    pos = 0;
    while ((pos = result.find("\"", pos)) != std::string::npos) {
        result.replace(pos, 1, "\\\"");
        pos += 2;
    }
    pos = 0;
    while ((pos = result.find("\n", pos)) != std::string::npos) {
        result.replace(pos, 1, "\\n");
        pos += 2;
    }
    pos = 0;
    while ((pos = result.find("\r", pos)) != std::string::npos) {
        result.replace(pos, 1, "\\r");
        pos += 2;
    }
    return result;
}

int main(int argc, char* argv[]) {
    // === ПРОВЕРКА НА --HELP ===
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Avalon Configure v1.0.0" << std::endl;
            std::cout << "Anton Vinogradov (tg: @vinantole) 2026" << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: AvalonConfigure.exe [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --url <IP>          Server IP address (required)" << std::endl;
            std::cout << "  --user <user>       Username (default: root)" << std::endl;
            std::cout << "  --password <pass>   Password (default: root)" << std::endl;
            std::cout << "  --pool1 <url>       Pool 1 URL" << std::endl;
            std::cout << "  --worker1 <name>    Worker 1 Name" << std::endl;
            std::cout << "  --passwd1 <pass>    Worker 1 Password" << std::endl;
            std::cout << "  --pool2 <url>       Pool 2 URL" << std::endl;
            std::cout << "  --worker2 <name>    Worker 2 Name" << std::endl;
            std::cout << "  --passwd2 <pass>    Worker 2 Password" << std::endl;
            std::cout << "  --pool3 <url>       Pool 3 URL" << std::endl;
            std::cout << "  --worker3 <name>    Worker 3 Name" << std::endl;
            std::cout << "  --passwd3 <pass>    Worker 3 Password" << std::endl;
            std::cout << "  --mode <mode>       Mode" << std::endl;
            std::cout << "  --moreoption <opt>  More options" << std::endl;
            return 0;
        }
    }

    // === ПАРСИНГ АРГУМЕНТОВ ===
    std::map<std::string, std::string> params;
    
    std::vector<std::string> requiredKeys = {
        "url", "user", "password", 
        "pool1", "worker1", "passwd1", 
        "pool2", "worker2", "passwd2", 
        "pool3", "worker3", "passwd3", 
        "mode", "moreoption"
    };

    for (const auto& key : requiredKeys) {
        params[key] = "";
    }

    for (int i = 1; i < argc; i++) {
        std::string key = argv[i];
        if (key.rfind("--", 0) == 0) {
            key = key.substr(2);
        }
        
        if (i + 1 < argc) {
            params[key] = argv[i + 1];
            i++;
        }
    }

    if (params["url"].empty()) {
        std::cerr << "Error: --url is required." << std::endl;
        std::cerr << "Usage: AvalonConfigure.exe --url <IP> --user <user> --password <pass> ..." << std::endl;
        return 1;
    }

    std::string userName = params["user"].empty() ? "root" : params["user"];
    std::string password = params["password"].empty() ? "root" : params["password"];

    // === ПОДГОТОВКА POST ДАННЫХ ===
    std::string postData;
    std::vector<std::string> order = {"pool1", "worker1", "passwd1", "pool2", "worker2", "passwd2", "pool3", "worker3", "passwd3", "mode", "moreoption"};

    for (size_t i = 0; i < order.size(); ++i) {
        if (!params[order[i]].empty()) {
            if (!postData.empty()) postData += "&";
            postData += order[i] + "=" + url_encode(params[order[i]]);
        }
    }

    // === ИНИЦИАЛИЗАЦИЯ ПЕРЕМЕННЫХ ДЛЯ WINHTTP ===
    std::wstring serverName = s2ws(params["url"]);
    std::wstring wUserName = s2ws(userName);
    std::wstring wPassword = s2ws(password);
    std::wstring objectName = L"/cgconf.cgi";
    std::wstring wPostData = s2ws(postData);
    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded";
    
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL; 
    HINTERNET  hConnect = NULL; 
    HINTERNET  hRequest = NULL;
    DWORD dwStatusCode = 0;
    std::string responseBody;
    std::string statusStr = "error";
    std::string message = ""; // Инициализируем message здесь, чтобы избежать ошибки компилятора
    DWORD lastError = 0;

    // === WINHTTP ===
    hSession = WinHttpOpen(L"AvalonConfigure/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpOpen failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    // === УСТАНОВКА ТАЙМАУТА (1 СЕКУНДА) ===
    DWORD dwTimeout = 1000; // 1000 мс = 1 секунда
    if (hSession) {
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
    }

    hConnect = WinHttpConnect(hSession, serverName.c_str(), INTERNET_DEFAULT_PORT, 0);
    if (!hConnect) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpConnect failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", objectName.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpOpenRequest failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    bResults = WinHttpAddRequestHeaders(hRequest, headers.c_str(), headers.length(), WINHTTP_ADDREQ_FLAG_ADD);
    if (!bResults) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpAddRequestHeaders failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    bResults = WinHttpSetCredentials(hRequest, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_DIGEST, wUserName.c_str(), wPassword.c_str(), NULL);
    if (!bResults) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpSetCredentials failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)wPostData.c_str(), wPostData.length(), wPostData.length(), 0);
    if (!bResults) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpSendRequest failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        lastError = GetLastError();
        std::cerr << "Error: WinHttpReceiveResponse failed. Code: " << lastError << std::endl;
        goto cleanup;
    }

    DWORD dwSizeOfStatusCode = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSizeOfStatusCode, WINHTTP_NO_HEADER_INDEX);

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer) break;

        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            delete[] pszOutBuffer;
            break;
        }
        
        responseBody.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;

    } while (dwSize > 0);

    statusStr = (bResults && dwStatusCode >= 200 && dwStatusCode < 300) ? "success" : "error";

    // === ФОРМИРОВАНИЕ СООБЩЕНИЯ ===
    if (statusStr == "success") {
        message = "Configuration request sent to " + params["url"];
    } else {
        message = "Failed to connect to " + params["url"] + " (Error code: " + std::to_string(lastError) + ")";
    }

    // === ВЫВОД JSON ===
    std::cout << "{" << std::endl;
    std::cout << "  \"status\": \"" << statusStr << "\"," << std::endl;
    std::cout << "  \"http_code\": " << dwStatusCode << "," << std::endl;
    std::cout << "  \"message\": \"" << json_escape(message) << "\"," << std::endl;
    std::cout << "  \"credentials\": {" << std::endl;
    std::cout << "    \"user\": \"" << userName << "\"," << std::endl;
    std::cout << "    \"password\": \"" << password << "\"" << std::endl;
    std::cout << "  }," << std::endl;
    std::cout << "  \"request\": {" << std::endl;
    
    for (size_t i = 0; i < order.size(); ++i) {
        std::cout << "    \"" << order[i] << "\": \"" << json_escape(params[order[i]]) << "\"";
        if (i < order.size() - 1) std::cout << ",";
        std::cout << std::endl;
    }
    
    std::cout << "  }," << std::endl;
    std::cout << "}" << std::endl;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return 0;
}        
