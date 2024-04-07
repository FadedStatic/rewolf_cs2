#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

using MmGetPhysicalAddress_ty = std::uint64_t(__stdcall*)(PVOID);
int main()
{
	const auto drv = driver_util::driver();
	LoadLibraryA("ntoskrnl.exe");
	const auto ntproc_addr = driver_util::get_modproc_phys_addr(drv, "ntoskrnl.exe", "NtReadFileScatter");
	driver_util::hook_ntproc(drv, ntproc_addr);
	return 0;
}