#pragma once

#include "FirewallRule.h"

#include <windows.h>

#include <cstdint>
#include <memory>
#include <vector>

class WfpFirewall;

class RuleManager
{
public:
	RuleManager();
	~RuleManager();

	RuleManager(const RuleManager&) = delete;
	RuleManager& operator=(const RuleManager&) = delete;

	DWORD Initialize();
	DWORD AddRule(FirewallRule rule, std::uint64_t& ruleId);
	DWORD RemoveRule(std::uint64_t ruleId);
	DWORD RemoveAllRules();

	const std::vector<FirewallRule>& GetRules() const;

private:
	std::unique_ptr<WfpFirewall> wfpFirewall;
	std::vector<FirewallRule> rules;
	std::uint64_t nextRuleId = 1;
};
