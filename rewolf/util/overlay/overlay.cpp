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
	long long presentmpo_new(void* a1, IDXGISwapChain* a2, unsigned a3, unsigned a4, int a5, void* a6, std::uint64_t* a7, std::uint64_t a8)
	{
		util::log("PresentMPO called...");
		return presentmpo_orig(a1, a2, a3, a4, a5, a6, a7, a8);
	}
	long long presentdwm_new(void* a1, IDXGISwapChain* a2, unsigned a3, unsigned a4, const tagRECT* a5, unsigned a6, void* a7, unsigned a8, void* a9, unsigned a10)
	{
		util::log("PresentDWM called...");
		return presentdwm_orig(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
	}

}