#include "WfpFirewall.h"
#include "../Core/FirewallRule.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>

#pragma comment(lib, "fwpuclnt.lib")

namespace
{
	// {3B8A5A93-2F8C-4F65-9A57-7F9F8D7C5C01}
	const GUID WfpSubLayerGuid =
	{ 0x3b8a5a93, 0x2f8c, 0x4f65, { 0x9a, 0x57, 0x7f, 0x9f, 0x8d, 0x7c, 0x5c, 0x01 } };
}

WfpFirewall::~WfpFirewall()
{
	if (engineHandle != nullptr)
	{
		if (sublayerRegistered)
		{
			FwpmSubLayerDeleteByKey0(engineHandle, &WfpSubLayerGuid);
			sublayerRegistered = false;
		}

		FwpmEngineClose0(engineHandle);
		engineHandle = nullptr;
	}
}

DWORD WfpFirewall::Initialize()
{
	if (engineHandle != nullptr)
	{
		return ERROR_ALREADY_INITIALIZED;
	}

	DWORD result = FwpmEngineOpen0(
		nullptr,
		RPC_C_AUTHN_WINNT,
		nullptr,
		nullptr,
		&engineHandle);

	if (result != ERROR_SUCCESS)
	{
		engineHandle = nullptr;
		return result;
	}

	FWPM_SUBLAYER0 subLayer{};
	subLayer.subLayerKey = WfpSubLayerGuid;
	subLayer.displayData.name = const_cast<wchar_t*>(L"Firewall application sublayer");
	subLayer.displayData.description = const_cast<wchar_t*>(L"Rules managed by Firewall application");
	subLayer.weight = 0x100;

	result = FwpmSubLayerAdd0(engineHandle, &subLayer, nullptr);
	if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS)
	{
		FwpmEngineClose0(engineHandle);
		engineHandle = nullptr;
		return result;
	}

	sublayerRegistered = true;
	return ERROR_SUCCESS;
}

DWORD WfpFirewall::AddOutboundTcpPortBlock(USHORT remotePort, UINT64& filterId)
{
	FirewallRule rule;
	rule.name = L"Firewall TCP port block";
	rule.remotePort = remotePort;
	return AddRule(rule, filterId);
}

DWORD WfpFirewall::AddRule(const FirewallRule& rule, UINT64& filterId)
{
	filterId = 0;

	if (engineHandle == nullptr || !sublayerRegistered)
	{
		return ERROR_INVALID_HANDLE;
	}

	if (rule.direction != RuleDirection::Outbound
		|| rule.protocol != RuleProtocol::Tcp
		|| rule.action != RuleAction::Block
		|| rule.remotePort == 0)
	{
		return ERROR_NOT_SUPPORTED;
	}

	FWPM_FILTER_CONDITION0 conditions[2]{};

	conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	conditions[0].matchType = FWP_MATCH_EQUAL;
	conditions[0].conditionValue.type = FWP_UINT8;
	conditions[0].conditionValue.uint8 = IPPROTO_TCP;

	conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	conditions[1].matchType = FWP_MATCH_EQUAL;
	conditions[1].conditionValue.type = FWP_UINT16;
	conditions[1].conditionValue.uint16 = rule.remotePort;

	FWPM_FILTER0 filter{};
	filter.displayData.name = const_cast<wchar_t*>(L"Firewall TCP port block");
	if (!rule.name.empty())
	{
		filter.displayData.name = const_cast<wchar_t*>(rule.name.c_str());
	}
	filter.displayData.description = const_cast<wchar_t*>(L"Blocks outbound TCP connections to a remote port");
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = WfpSubLayerGuid;
	filter.action.type = FWP_ACTION_BLOCK;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xF;
	filter.numFilterConditions = ARRAYSIZE(conditions);
	filter.filterCondition = conditions;

	return FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
}

DWORD WfpFirewall::RemoveFilter(UINT64 filterId) const
{
	if (engineHandle == nullptr || !sublayerRegistered)
	{
		return ERROR_INVALID_HANDLE;
	}

	return FwpmFilterDeleteById0(engineHandle, filterId);
}
