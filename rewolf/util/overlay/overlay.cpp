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

	void init_imgui()
	{
		if (SUCCEEDED(swap_chain_ptr->GetDevice(__uuidof(ID3D11Device), (void**)&d3d_device_ptr))) {
			d3d_device_ptr->GetImmediateContext(&d3d_device_ctx_ptr);
		}
		ID3D11Texture2D* RenderTargetTexture = nullptr;
		if (SUCCEEDED(swap_chain_ptr->GetBuffer(0, IID_PPV_ARGS(&RenderTargetTexture)))) {
			d3d_device_ptr->CreateRenderTargetView(RenderTargetTexture, NULL, &render_target_view_ptr);
			if (!render_target_view_ptr)
				return;
			RenderTargetTexture->Release();
		}
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui_ImplWin32_Init(FindWindow(L"Progman", L"Program Manager"));
		ImGui_ImplDX11_Init(d3d_device_ptr, d3d_device_ctx_ptr);
		ImGui::StyleColorsLight();
		ImGuiIO& io = ImGui::GetIO();
		io.ConfigFlags = ImGuiConfigFlags_NoMouseCursorChange;
	}

	void draw_overlay(IDXGISwapChain* swap_chain) {
		swap_chain_ptr = swap_chain;
		if (!is_initialized)
		{
			is_initialized = true;
			init_imgui();
		}
		else {
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();
			ImGui::Begin("Hello, world!");
			ImGui::Text("Hi mom!");
			ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
			ImGui::End();
			d3d_device_ctx_ptr->OMSetRenderTargets(1, &render_target_view_ptr, NULL);
			ImGui::Render();
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
			ImGui::EndFrame();
		}
	}

	long long presentmpo_new(void* thisptr, IDXGISwapChain* a2, __int64 a3, char a4)
	{
		draw_overlay(a2);
		return presentmpo_orig(thisptr, a2, a3, a4);
	}

}