#include "ConnectionMonitor.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

namespace
{
	bool QueryTcpTable(std::vector<BYTE>& buffer)
	{
		DWORD size = 0;
		DWORD result = GetExtendedTcpTable(
			nullptr,
			&size,
			FALSE,
			AF_INET,
			TCP_TABLE_OWNER_PID_ALL,
			0);

		if (result != ERROR_INSUFFICIENT_BUFFER)
		{
			std::wcerr << L"GetExtendedTcpTable failed to get size: " << result << std::endl;
			return false;
		}

		buffer.resize(size);
		result = GetExtendedTcpTable(
			buffer.data(),
			&size,
			FALSE,
			AF_INET,
			TCP_TABLE_OWNER_PID_ALL,
			0);

		if (result != NO_ERROR)
		{
			std::wcerr << L"GetExtendedTcpTable failed with error: " << result << std::endl;
			return false;
		}

		return true;
	}

	WORD GetDefaultConsoleColor()
	{
		HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO consoleInfo{};
		if (!GetConsoleScreenBufferInfo(console, &consoleInfo))
		{
			return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
		}

		return consoleInfo.wAttributes;
	}

	std::wstring ToWide(const char* value)
	{
		if (value == nullptr)
		{
			return {};
		}

		return std::wstring(value, value + std::strlen(value));
	}
}

void ConnectionMonitor::ListActiveConnections() const
{
	std::vector<BYTE> buffer;
	if (!QueryTcpTable(buffer))
	{
		return;
	}

	const auto* tcpTable = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
	std::wcout << L"Active TCP Connections:" << std::endl;

	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	const WORD defaultColor = GetDefaultConsoleColor();

	for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i)
	{
		const MIB_TCPROW_OWNER_PID& tcpRow = tcpTable->table[i];

		char localIp[INET_ADDRSTRLEN]{};
		char remoteIp[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &tcpRow.dwLocalAddr, localIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &tcpRow.dwRemoteAddr, remoteIp, INET_ADDRSTRLEN);

		const USHORT localPort = ntohs(static_cast<u_short>(tcpRow.dwLocalPort));
		const USHORT remotePort = ntohs(static_cast<u_short>(tcpRow.dwRemotePort));

		if (tcpRow.dwState == MIB_TCP_STATE_ESTAB)
		{
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_INTENSITY);
		}
		else
		{
			SetConsoleTextAttribute(console, defaultColor);
		}

		std::wcout << L"Connection " << (i + 1)
			<< L": Local: " << ToWide(localIp) << L":" << localPort
			<< L"  Remote: " << ToWide(remoteIp) << L":" << remotePort
			<< L"  State: " << tcpRow.dwState
			<< L"  PID: " << tcpRow.dwOwningPid << std::endl;
	}

	SetConsoleTextAttribute(console, defaultColor);
}

void ConnectionMonitor::DetectVulnerabilities() const
{
	std::vector<BYTE> buffer;
	if (!QueryTcpTable(buffer))
	{
		return;
	}

	const auto* tcpTable = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
	constexpr int vulnerablePorts[] = { 21, 22, 23, 25, 80, 443, 445, 3306, 3389 };

	std::wofstream outputFile(L"vulnerable_connections.txt", std::ios::app);
	if (!outputFile.is_open())
	{
		std::wcerr << L"Failed to open vulnerable_connections.txt for writing." << std::endl;
	}

	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	const WORD defaultColor = GetDefaultConsoleColor();
	bool vulnerabilitiesFound = false;

	for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i)
	{
		const MIB_TCPROW_OWNER_PID& tcpRow = tcpTable->table[i];
		const USHORT localPort = ntohs(static_cast<u_short>(tcpRow.dwLocalPort));

		for (int vulnerablePort : vulnerablePorts)
		{
			if (localPort != vulnerablePort)
			{
				continue;
			}

			vulnerabilitiesFound = true;
			SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_INTENSITY);

			std::wcout << L"Vulnerability detected: Active connection on vulnerable local port "
				<< localPort << L", PID: " << tcpRow.dwOwningPid << std::endl;

			if (outputFile.is_open())
			{
				outputFile << L"Vulnerability detected: Active connection on vulnerable local port "
					<< localPort << L", PID: " << tcpRow.dwOwningPid << std::endl;
			}

			SetConsoleTextAttribute(console, defaultColor);
			break;
		}
	}

	if (!vulnerabilitiesFound)
	{
		std::wcout << L"No vulnerable connections detected." << std::endl;
	}
}
