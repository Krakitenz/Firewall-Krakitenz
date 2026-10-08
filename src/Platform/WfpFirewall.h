#pragma once

#include <windows.h>

struct FirewallRule;

class WfpFirewall
{
public:
	WfpFirewall() = default;
	~WfpFirewall();

	WfpFirewall(const WfpFirewall&) = delete;
	WfpFirewall& operator=(const WfpFirewall&) = delete;

	DWORD Initialize();
	DWORD AddRule(const FirewallRule& rule, UINT64& filterId);
	DWORD AddOutboundTcpPortBlock(USHORT remotePort, UINT64& filterId);
	DWORD RemoveFilter(UINT64 filterId) const;

private:
	HANDLE engineHandle = nullptr;
	bool sublayerRegistered = false;
};
