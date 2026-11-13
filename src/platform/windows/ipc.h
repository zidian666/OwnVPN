#pragma once
#include "windows_platform.h"
#include "core.h"
namespace ownvpn {
bool SendPacket(HANDLE pipe, uint32_t type, const std::vector<std::string>& fields);
bool ReceivePacket(HANDLE pipe, uint32_t& type, std::vector<std::string>& fields);
bool PipeReady(HANDLE pipe);
} // namespace ownvpn
