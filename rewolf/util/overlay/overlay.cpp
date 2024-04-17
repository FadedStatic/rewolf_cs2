#include "overlay.hpp"

namespace overlay_util
{
	std::pair < std::uintptr_t, std::uintptr_t> overlay::find_mpo_and_dwm()
	{
		const auto scan_results = scanner_utils::pattern_scan("d2d1.dll", 
			"\x48\x89\x69\x24\x69\x48\x89\x69\x24\x69\x48\x89\x69\x24\x69\x57\x48\x83\xEC\x69\x48\x8B\x69\x41\x8B\x69\x48\x8B\x89\x69\x69\x00\x00"
				, "xx?x?xx?x?xx?x?xxxx?xx?xx?xxx??xx");
		if (scan_results.has_value())
		{
			const auto& res = scan_results.value();
			return { res[0], res[1] };
		}
		return { 0, 0 };
	}
}