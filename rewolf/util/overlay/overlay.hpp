#pragma once

#include "../../libs/scanner/scanner.hpp"
#include "../../libs/minhook/MinHook.hpp"

namespace overlay_util
{
	using presentmpo_ty = __int64(__fastcall*)(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, int a5, void* a6, std::uint64_t* a7, std::uint64_t a8);
	using presentdwm_ty = __int64(__fastcall*)(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, const tagRECT* a5, unsigned int a6, void* a7, unsigned int a8, void* a9, unsigned int a10);

	DECLSPEC_SELECTANY extern presentmpo_ty presentmpo_orig{};
	DECLSPEC_SELECTANY extern presentdwm_ty presentdwm_orig{};
	__int64 __fastcall presentmpo_new(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, int a5, void* a6, std::uint64_t* a7, std::uint64_t a8);
	__int64 __fastcall presentdwm_new(void* a1, IDXGISwapChain* a2, unsigned int a3, unsigned int a4, const tagRECT* a5, unsigned int a6, void* a7, unsigned int a8, void* a9, unsigned int a10);

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
				MH_CreateHook(reinterpret_cast<void*>(second), presentdwm_new, reinterpret_cast<LPVOID*>(&presentdwm_orig));
				MH_EnableHook(nullptr);
			}
		}
	};
}