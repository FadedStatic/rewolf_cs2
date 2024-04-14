#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

using MmGetPhysicalAddress_ty = std::uint64_t(__stdcall*)(PVOID);
int main()
{
	auto drv = driver_util::driver();

	const auto mmgetphys = [&](std::uint64_t va) -> void* {
		const auto res = drv.call_ntproc<std::uint64_t*, std::uint64_t>("MmGetPhysicalAddress", va);
		if (!res.has_value())
			return util::log("call failed"), nullptr;
		return res.value();
	};

	util::log("PA of rewolf.exe: %p", mmgetphys(reinterpret_cast<std::uint64_t>(GetModuleHandleA("rewolf.exe"))));

	std::cin.get();
	return 0;
}

// DO NOT FORGET TO STOP MEMLEAK