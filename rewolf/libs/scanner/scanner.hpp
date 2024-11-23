#pragma once

#include "../../util/util.hpp"
#include "../../include.hpp"

namespace scanner_utils
{
	std::optional<std::vector<std::uintptr_t>> pattern_scan(const std::string& mod_name, const std::string& aob, const std::string& mask);
}