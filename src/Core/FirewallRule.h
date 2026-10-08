#pragma once

#include <cstdint>
#include <string>

enum class RuleDirection
{
	Outbound
};

enum class RuleProtocol
{
	Tcp
};

enum class RuleAction
{
	Block
};

struct FirewallRule
{
	std::uint64_t id = 0;
	std::wstring name;
	RuleDirection direction = RuleDirection::Outbound;
	RuleProtocol protocol = RuleProtocol::Tcp;
	RuleAction action = RuleAction::Block;
	std::uint16_t remotePort = 0;
	std::uint64_t wfpFilterId = 0;
};
