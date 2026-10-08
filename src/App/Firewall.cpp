#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600  // Требуется для Windows Vista/7 и выше

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <cfgmgr32.h>  // Для CM_Get_DevNode_Status
#include <netfw.h>     // Для Windows Firewall API
#include <comdef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <tchar.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <stdio.h>
#include <thread>
#include <vector>


// подключение классов + lib

#include "../Core/FirewallManager.h"
#include "../Network/ConnectionMonitor.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ws2_32.lib")

#ifndef DN_STARTED
#define DN_STARTED 0x00000800
#endif

void ListNetworkAdapters();
void ListFirewallRules();
void CheckForThreatsAndEnableFirewall(FirewallManager& firewallManager);
void TestWfpPortBlock(FirewallManager& firewallManager);

int main() {
    setlocale(LC_ALL, "Russian");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    // Инициализация Winsock + firewallManager
    FirewallManager fw;
    ConnectionMonitor connectionMonitor;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::wcerr << L"WSAStartup failed" << std::endl;
        return 1;
    }

    while (true) {
        std::wcout << L"\nВыберите действие:\n"
            << L"1. Список сетевых адаптеров\n"
            << L"2. Правила брандмауэра\n"
            << L"3. Включить брандмауэр\n"
            << L"4. Мониторинг соединений\n"
            << L"5. Тест WFP: временно заблокировать TCP-порт\n"
            << L"6. Выход\n";

        wchar_t choice;
        std::wcout << L"> ";
        std::wcin >> choice;

        switch (choice) {
        case L'1':
            ListNetworkAdapters();
            break;
        case L'2':
            ListFirewallRules();
            break;
        case L'3':
            fw.EnableFirewall();
            break;
        case L'4':
            connectionMonitor.ListActiveConnections();
            connectionMonitor.DetectVulnerabilities();
            CheckForThreatsAndEnableFirewall(fw);
            break;
        case L'5':
            TestWfpPortBlock(fw);
            break;
        case L'6':
            std::wcout << L"Выход из программы\n";
            WSACleanup();
            return 0;
        default:
            std::wcout << L"Неверный выбор. Попробуйте снова.\n";
            break;
        }

        std::wcout << std::endl;
        Sleep(1000);
    }

    return 0;
}

void TestWfpPortBlock(FirewallManager& firewallManager)
{
    const DWORD initializeResult = firewallManager.InitializeRules();
    if (initializeResult != ERROR_SUCCESS && initializeResult != ERROR_ALREADY_INITIALIZED)
    {
        std::wcerr << L"WFP initialization failed. Error: 0x"
            << std::hex << initializeResult << std::dec << std::endl;
        return;
    }

    unsigned int port = 0;
    std::wcout << L"Введите удалённый TCP-порт (1-65535): ";
    if (!(std::wcin >> port) || port == 0 || port > 65535)
    {
        std::wcin.clear();
        std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
        std::wcout << L"Некорректный номер порта." << std::endl;
        return;
    }

    FirewallRule rule;
    rule.name = L"Temporary outbound TCP block";
    rule.remotePort = static_cast<std::uint16_t>(port);

    std::uint64_t ruleId = 0;
    const DWORD addResult = firewallManager.AddRule(rule, ruleId);

    if (addResult != ERROR_SUCCESS)
    {
        std::wcerr << L"WFP filter creation failed. Error: 0x"
            << std::hex << addResult << std::dec << std::endl;
        return;
    }

    std::wcout << L"Правило добавлено. ID: " << ruleId
        << L". Нажмите Enter для удаления фильтра." << std::endl;
    std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
    std::wcin.get();

    const DWORD removeResult = firewallManager.RemoveRule(ruleId);
    if (removeResult == ERROR_SUCCESS)
    {
        std::wcout << L"Фильтр удалён." << std::endl;
    }
    else
    {
        std::wcerr << L"WFP filter removal failed. Error: 0x"
            << std::hex << removeResult << std::dec << std::endl;
    }
}

// Вывод списка сетевых адаптеров

void ListNetworkAdapters()
{
    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Error: SetupDiGetClassDevs failed." << std::endl;
        return;
    }

    SP_DEVINFO_DATA deviceInfoData;
    ZeroMemory(&deviceInfoData, sizeof(SP_DEVINFO_DATA));
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    DWORD deviceIndex = 0;
    TCHAR deviceDescription[1024];
    TCHAR deviceName[1024];
    DWORD requiredSize = 0;
    DWORD propertyRegDataType = 0;

    while (SetupDiEnumDeviceInfo(deviceInfoSet, deviceIndex, &deviceInfoData))
    {
        if (SetupDiGetDeviceRegistryProperty(
            deviceInfoSet,
            &deviceInfoData,
            SPDRP_DEVICEDESC,
            &propertyRegDataType,
            (PBYTE)deviceDescription,
            sizeof(deviceDescription),
            &requiredSize))
        {
            std::wcout << L"Adapter " << (deviceIndex + 1) << L": "
                << deviceDescription << std::endl;
            if (SetupDiGetDeviceRegistryProperty(
                deviceInfoSet,
                &deviceInfoData,
                SPDRP_FRIENDLYNAME,
                &propertyRegDataType,
                (PBYTE)deviceName,
                sizeof(deviceName),
                &requiredSize))
            {
                std::wcout << L"   Friendly Name: " << deviceName << std::endl;
            }
            ULONG status = 0, problemCode = 0;
            CONFIGRET cr = CM_Get_DevNode_Status(&status, &problemCode, deviceInfoData.DevInst, 0);
            if (cr == CR_SUCCESS)
            {
                std::wcout << L"   Status: " << ((status &   DN_STARTED) ? L"Started" : L"Stopped") << std::endl;
            }
            else
            {
                std::wcerr << L"   Status query failed (Error: 0x" << std::hex << cr << L")" << std::endl;
            }
        }
        deviceIndex++;
    }

    if (deviceIndex == 0)
        std::wcout << L"No network adapters found." << std::endl;

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}

// Вывод правил брандмауэра через netsh
void ListFirewallRules()
{
    std::wcout << L"Displaying firewall rules using netsh..." << std::endl;
    system("netsh advfirewall firewall show rule name=all");
}

// Проверка угроз: если вывод правил netsh слишком короткий, включаем брандмауэр
void CheckForThreatsAndEnableFirewall(FirewallManager& firewallManager)
{
    const wchar_t* tempFile = L"fw_temp.txt";
    std::wstring command = L"netsh advfirewall firewall show rule name=all > ";
    command += tempFile;
    system(std::string(command.begin(), command.end()).c_str());
    std::wifstream infile(tempFile);
    std::wstringstream wss;
    wss << infile.rdbuf();
    std::wstring fileContent = wss.str();
    infile.close();
    DeleteFile(tempFile);

    if (fileContent.length() < 500)
    {
        std::wcout << L"Threat detected (insufficient firewall rules). Enabling firewall..." << std::endl;
        firewallManager.EnableFirewall();
    }
    else
    {
        std::wcout << L"No threats detected based on firewall rules output." << std::endl;
    }
}

