#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

using MmGetPhysicalAddress_ty = std::uint64_t(__stdcall*)(PVOID);
int main()
{
	util::log("Hi Mom!");

	//auto drv = driver_util::driver();

	//const auto mmgetphys = [&](std::uint64_t va) -> void* {
	//	const auto res = drv.call_ntproc<std::uint64_t*, std::uint64_t>("MmGetPhysicalAddress", va);
	//	if (!res.has_value())
	//		return util::log("call failed"), nullptr;
	//	return res.value();
	//};

	//util::log("PA of rewolf.exe: %p", mmgetphys(reinterpret_cast<std::uint64_t>(GetModuleHandleA("rewolf.exe"))));

	//std::cin.get();
	return 0;
}

int __stdcall DllMain(
	HINSTANCE dll_instance,
	DWORD     reason_for_call,
	LPVOID    reserved
)
{
	switch (reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		std::thread{ main }.detach();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return 1;
}

// DO NOT FORGET TO STOP MEMLEAK