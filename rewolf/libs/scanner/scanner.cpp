#include "scanner.hpp"

namespace scanner_utils
{
	const auto page_flag_check = [](const std::uintptr_t page_flags) -> bool
	{
		return !(page_flags & (PAGE_NOACCESS | PAGE_GUARD)) && (page_flags & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ)) && !(page_flags == PAGE_EXECUTE && !(page_flags & (PAGE_GUARD | PAGE_NOACCESS)));
	};
	std::optional<std::vector<std::uintptr_t>> pattern_scan(const std::string& mod_name, const std::string& aob, const std::string& mask)
	{
		std::vector<std::uintptr_t> ret;
		MODULEINFO mod_info;
		if (!K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(mod_name.c_str()), &mod_info, sizeof(mod_info)))
			return util::log("Failed to get module information: {:02llX}", GetLastError()), std::nullopt;
		const auto  scan_base_address = reinterpret_cast<std::uintptr_t>(mod_info.lpBaseOfDll);
		MEMORY_BASIC_INFORMATION mbi;

		for (auto scan_addr = scan_base_address; scan_addr < (scan_base_address + mod_info.SizeOfImage);)
		{
			if (!VirtualQuery(reinterpret_cast<void*>(scan_addr), &mbi, sizeof MEMORY_BASIC_INFORMATION) && page_flag_check(mbi.Protect))
				break;

			while (scan_addr < (mbi.RegionSize + reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)))
			{
				for (auto j = 0ull; j < mask.length(); j++) {
					if (mask[j] != '?' and (*reinterpret_cast<std::uint8_t*>(scan_addr + j) != static_cast<std::uint8_t>(aob[j])))
						goto out_of_scope;
				}

				ret.push_back(scan_addr);

			out_of_scope:
				scan_addr++;
			}
		}

		// fucking stupid compiler
		if (ret.empty())
			return std::nullopt;
		return ret;
	}

}