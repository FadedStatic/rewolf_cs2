#include "overlay.hpp"

namespace overlay_util
{
	std::pair < std::uintptr_t, std::uintptr_t> overlay::find_mpo_and_dwm()
	{

		const auto scan_results = scanner_utils::pattern_scan("dwmcore.dll", 
			"\x48\x89\x69\x24\x69\x48\x89\x69\x24\x69\x57\x48\x83\xEC\x69\x8B\x99\x69\x69\x69\x69\x48\x8B\xF2\x48\x8B\xF9"
				, "xx?x?xx?x?xxxx?xx????xxxxxx");
		if (scan_results.has_value())
		{
			const auto& res = scan_results.value();
			return { res[0], res[1] };
		}
		return { 0, 0 };
	}
	long long presentmpo_new(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4)
	{
		return presentmpo_orig(thisptr, a2, a3, a4);
	}

}