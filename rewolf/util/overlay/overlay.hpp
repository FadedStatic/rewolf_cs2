#pragma once

#include "../../libs/scanner/scanner.hpp"
#include "../../libs/minhook/MinHook.hpp"

namespace overlay_util
{
	using presentmpo_ty = __int64(__fastcall*)(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4);

	DECLSPEC_SELECTANY extern presentmpo_ty presentmpo_orig{};
	__int64 __fastcall presentmpo_new(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4);

	struct overlay
	{
		bool is_initialized{ false };
		// first is MPO, second is DWM
		std::pair < std::uintptr_t, std::uintptr_t> find_mpo_and_dwm();

		overlay() noexcept{
			const auto [first, second] = find_mpo_and_dwm();
			if (first && second)
			{
				util::log("Initialized hook!");
				MH_Initialize();
				MH_CreateHook(reinterpret_cast<void*>(first), presentmpo_new, reinterpret_cast<LPVOID*>(&presentmpo_orig));
				MH_EnableHook(nullptr);
			}
		}
	};
}