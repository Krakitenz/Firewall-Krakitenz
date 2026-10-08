#include "RuleManager.h"

#include "../Platform/WfpFirewall.h"

#include <algorithm>
#include <utility>

RuleManager::RuleManager()
	: wfpFirewall(std::make_unique<WfpFirewall>())
{
}

RuleManager::~RuleManager()
{
	RemoveAllRules();
}

DWORD RuleManager::Initialize()
{
	return wfpFirewall->Initialize();
}

DWORD RuleManager::AddRule(FirewallRule rule, std::uint64_t& ruleId)
{
	ruleId = 0;

	UINT64 wfpFilterId = 0;
	const DWORD result = wfpFirewall->AddRule(rule, wfpFilterId);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	rule.id = nextRuleId++;
	rule.wfpFilterId = wfpFilterId;
	rules.push_back(std::move(rule));
	ruleId = rules.back().id;
	return ERROR_SUCCESS;
}

DWORD RuleManager::RemoveRule(std::uint64_t ruleId)
{
	const auto ruleIterator = std::find_if(
		rules.begin(),
		rules.end(),
		[ruleId](const FirewallRule& rule)
		{
			return rule.id == ruleId;
		});

	if (ruleIterator == rules.end())
	{
		return ERROR_NOT_FOUND;
	}

	const DWORD result = wfpFirewall->RemoveFilter(ruleIterator->wfpFilterId);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	rules.erase(ruleIterator);
	return ERROR_SUCCESS;
}

DWORD RuleManager::RemoveAllRules()
{
	DWORD firstError = ERROR_SUCCESS;

	for (auto ruleIterator = rules.begin(); ruleIterator != rules.end();)
	{
		const DWORD result = wfpFirewall->RemoveFilter(ruleIterator->wfpFilterId);
		if (result == ERROR_SUCCESS)
		{
			ruleIterator = rules.erase(ruleIterator);
			continue;
		}

		if (firstError == ERROR_SUCCESS)
		{
			firstError = result;
		}

		++ruleIterator;
	}

	return firstError;
}

const std::vector<FirewallRule>& RuleManager::GetRules() const
{
	return rules;
}
