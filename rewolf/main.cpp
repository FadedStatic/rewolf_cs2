#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

using MmGetPhysicalAddress_ty = std::uint64_t(__stdcall*)(PVOID);
int main()
{
	auto drv = driver_util::driver();
	
	const auto kva = drv.ntoskrnl_base_address + (size_t)GetProcAddress(drv.kernel_handle, "MmGetPhysicalAddress") - (size_t)drv.kernel_handle;
	const auto base_mod_pa = drv.call_ntproc<std::uint64_t, void*>({ drv.get_ntproc_pa("NtReadFileScatter"), "NtReadFileScatter" }, "MmGetPhysicalAddress", kva);
	util::log("Physical address of KVA: %p", base_mod_pa);
	return 0;
}