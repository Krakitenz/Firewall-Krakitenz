#include "FirewallManager.h"
#include "RuleManager.h"

#include <iostream>
#include <sstream>
#include <utility>

FirewallManager::FirewallManager()
	: vulnerablePorts{ 21, 22, 23, 25, 80, 443, 445, 3306, 3389 },
		ruleManager(std::make_unique<RuleManager>())
{
}

FirewallManager::~FirewallManager() = default;

void FirewallManager::EnableFirewall()
{
	std::wcout << L"Enabling firewall for all profiles..." << std::endl;
	std::system("netsh advfirewall set allprofiles state on");
	std::wcout << L"Firewall enabled." << std::endl;

	for (int port : vulnerablePorts)
	{
		std::ostringstream command;
		command << "netsh advfirewall firewall add rule name=\"BlockPort_"
			<< port
			<< "\" dir=in protocol=TCP localport="
			<< port
			<< " action=block";

		std::system(command.str().c_str());
		std::wcout << L"Blocked port: " << port << std::endl;
	}
}

void FirewallManager::BlockConnection(const std::string& remoteIp, int remotePort)
{
	std::ostringstream command;
	command << "netsh advfirewall firewall add rule name=\"BlockSuspicious_"
		<< remoteIp << "_" << remotePort
		<< "\" dir=out remoteip=" << remoteIp
		<< " remoteport=" << remotePort
		<< " action=block";

	std::system(command.str().c_str());
	std::cout << "Blocked suspicious connection: "
		<< remoteIp << ':' << remotePort << std::endl;
}

const std::vector<int>& FirewallManager::GetVulnerablePorts() const
{
	return vulnerablePorts;
}

DWORD FirewallManager::InitializeRules()
{
	return ruleManager->Initialize();
}

DWORD FirewallManager::AddRule(FirewallRule rule, std::uint64_t& ruleId)
{
	return ruleManager->AddRule(std::move(rule), ruleId);
}

DWORD FirewallManager::RemoveRule(std::uint64_t ruleId)
{
	return ruleManager->RemoveRule(ruleId);
}

const std::vector<FirewallRule>& FirewallManager::GetRules() const
{
	return ruleManager->GetRules();
}
