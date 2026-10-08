#pragma once

#include "FirewallRule.h"

#include <windows.h>

#include <memory>
#include <string>
#include <vector>

class RuleManager;

class FirewallManager
{
public:
    FirewallManager();
    ~FirewallManager();

    FirewallManager(const FirewallManager&) = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;

    void EnableFirewall();
    void BlockConnection(const std::string& remoteIp, int remotePort);

    const std::vector<int>& GetVulnerablePorts() const;

    DWORD InitializeRules();
    DWORD AddRule(FirewallRule rule, std::uint64_t& ruleId);
    DWORD RemoveRule(std::uint64_t ruleId);
    const std::vector<FirewallRule>& GetRules() const;

private:
    std::vector<int> vulnerablePorts;
    std::unique_ptr<RuleManager> ruleManager;
};