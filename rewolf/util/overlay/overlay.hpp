#pragma once

#include "../../libs/scanner/scanner.hpp"
#include "../../libs/minhook/MinHook.hpp"
#include "../../libs/imgui/imgui_impl_win32.h"
#include "../../libs/imgui/imgui.h"
#include "../../libs/imgui/imgui_impl_dx11.h"

namespace overlay_util
{
	using presentmpo_ty = __int64(__fastcall*)(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4);

	DECLSPEC_SELECTANY extern presentmpo_ty presentmpo_orig{};
	__int64 __fastcall presentmpo_new(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4);

	static bool is_initialized{ false };
	static ID3D11Device* d3d_device_ptr{};
	static ID3D11DeviceContext* d3d_device_ctx_ptr{};
	static IDXGISwapChain* swap_chain_ptr{};
	static ID3D11RenderTargetView* render_target_view_ptr{};


	struct overlay
	{
		// first is MPO, second is DWM
		static std::pair < std::uintptr_t, std::uintptr_t> find_mpo_and_dwm();
		void init_imgui();
		void draw_overlay(IDXGISwapChain* swap_chain);

		overlay() noexcept{
			const auto [first, second] = find_mpo_and_dwm();
			if (first && second)
			{
				util::log("Hooked...");
				MH_Initialize();
				MH_CreateHook(reinterpret_cast<void*>(first), presentmpo_new, reinterpret_cast<LPVOID*>(&presentmpo_orig));
				MH_EnableHook(nullptr);
			}
		}
	};
}