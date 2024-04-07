#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

using MmGetPhysicalAddress_ty = std::uint64_t(__stdcall*)(PVOID);
int main()
{
	auto drv = driver_util::driver();
	const auto ntproc_pa = drv.get_ntproc_pa("NtReadFileScatter");
	const auto base_mod_pa = drv.call_ntproc<std::uint64_t, void*>({ ntproc_pa, "NtReadFileScatter" }, "MmGetPhysicalAddress", GetModuleHandleA("rewolf.exe"));
	util::log("Physical address of rewolf.exe: %X", base_mod_pa);
	util::log("MZ: %x", *reinterpret_cast<std::uint16_t*>(drv.read_phys_mem<2>(base_mod_pa)));
	return 0;
}