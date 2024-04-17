#pragma once

#include "../../libs/scanner/scanner.hpp"

namespace overlay_util
{
	//using presentmpo_ty = __int64(__fastcall*)(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, int a5, void* a6, std::uint64_t* a7, std::uint64_t a8);
//   using presentdwm_ty = __int64(__fastcall*)(void*, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, const tagRECT* a5, unsigned int a6, void* a7, unsigned int a8, void* a9, unsigned int a10);

	struct overlay
	{
		// first is MPO, second is DWM
		std::pair < std::uintptr_t, std::uintptr_t> find_mpo_and_dwm();

		overlay() noexcept{
			const auto addrs = find_mpo_and_dwm();
			if (addrs.first && addrs.second)
			{
				// initialize hook.
			}
		}
	};
}