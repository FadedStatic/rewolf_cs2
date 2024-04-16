#include "overlay.hpp"

namespace overlay_util
{
	using presentmpo_ty = __int64(__fastcall*)(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, int a5, void* a6, std::uint64_t* a7, std::uint64_t a8);
    using presentdwm_ty = __int64(__fastcall*)(void*, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, const tagRECT* a5, unsigned int a6, void* a7, unsigned int a8, void* a9, unsigned int a10);

	std::pair < std::uintptr_t, std::uintptr_t> overlay::find_mpo_and_dwm()
	{
		const auto presentmpo_addr = scanner_utils::pattern_scan("d2d1.dll", 
			"\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x40\x48\x8B\xE9\x41\x8B\xD9\x48\x8B\x89\x00\x00\x00\x00\x41\x8B\xF8\x48\x8B\xF2\x48\x8B\x01\x49\xBA"
				, "xxxx?xxxx?xxxx?xxxxxxxxxxxxxx????xxxxxxxxxxx");
		const auto presentdwm_addr = scanner_utils::pattern_scan("d2d1.dll",
			"\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x50\x48\x8B\xE9\x41\x8B\xD9\x48\x8B\x89\x00\x00\x00\x00\x41\x8B\xF8\x48\x8B\xF2\x48\x8B\x01" 
				,"xxxx?xxxx?xxxx?xxxxxxxxxxxxxx????xxxxxxxxx");
		return {0, 0};
	}
}