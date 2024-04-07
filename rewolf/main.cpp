#include "util/game/game.hpp"
#include "util/driver/driver.hpp"

int main()
{
	const auto drv = driver_util::driver();
	LoadLibraryA("ntoskrnl.exe");
	const auto ntproc_addr = driver_util::get_modproc_phys_addr(drv, "ntoskrnl.exe", "NtReadFileScatter");
	
	return 0;
}