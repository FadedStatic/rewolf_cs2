#include "driver.hpp"

namespace driver_util {
    constexpr auto hook_sz = 12;

    std::optional<std::vector<phys_mem_range>> get_physmem_ranges() {
        util::log("Retrieving physical memory ranges...");

        HKEY key{};
        if (const auto res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(HARDWARE\RESOURCEMAP\System Resources\Physical Memory)", 0, KEY_READ, &key); res != ERROR_SUCCESS)
            return util::log("Failed to open registry key for physical memory ranges. Error code:  %d", res), std::nullopt;

        auto data_type{ 0ul };
        auto data_size{ 0ul };

        if (const auto res = RegQueryValueExA(key, ".Translated", nullptr, &data_type, nullptr, &data_size); res != ERROR_SUCCESS)
            return util::log("Failed to query registry key for physical memory ranges. Error code:  %d", res), std::nullopt;


        const auto data = std::make_unique_for_overwrite<unsigned char[]>(data_size);
        if (const auto res = RegQueryValueExA(key, ".Translated", nullptr, &data_type, data.get(), &data_size); res != ERROR_SUCCESS)
            return util::log("Failed to query registry key for physical memory ranges. Error code:  %d", res), std::nullopt;

        const auto descriptor_count = *reinterpret_cast<DWORD*>(data.get() + 16);
        auto mem_record = data.get() + 24;

        std::vector<phys_mem_range> phys_mem_ranges{};
        for (auto i = 0u; i < descriptor_count; ++i) {
            phys_mem_ranges.push_back(phys_mem_range{ *reinterpret_cast<std::size_t*>(mem_record), *reinterpret_cast<std::uint64_t*>(mem_record + 8) });
            mem_record += 0x14;
        }
        RegCloseKey(key);
        return phys_mem_ranges;
    }

    [[nodiscard]] std::size_t driver::get_ntproc_pa(const char* proc_name) {
        util::log("Retrieving NT procedure physical address...");

        std::vector<phys_mem_range> phys_mem_ranges{};

        try {
            phys_mem_ranges = get_physmem_ranges().value();
        }
        catch (const std::bad_optional_access& err) {
            return util::log("Failed to retrieve physical memory ranges. Error message: %s", err.what()), 0;
        }

        std::uint8_t bytes[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50, 0x10, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56 };

        const auto ntdll_export = GetProcAddress(this->kernel_handle, proc_name);
        if (!ntdll_export)
            return util::log("Failed to retrieve %s virtual address. Error code: %d", proc_name, GetLastError()), 0;

        const auto export_page_offset = reinterpret_cast<std::size_t>(ntdll_export) % 0x1000;
        for (auto& [range_start, range_length] : phys_mem_ranges) {
            for (std::size_t page_cursor = range_start + export_page_offset; page_cursor < (range_start + range_length); page_cursor += 0x1000) {
                const auto read_bytes = std::unique_ptr<std::uint8_t>(read_phys_mem<24>(page_cursor));

                if (!read_bytes)
                    continue;
                if (!std::memcmp(read_bytes.get(), bytes, 24)) {
                    util::log("%s physical address: %p", proc_name, page_cursor);
                    return page_cursor;
                }
            }
        }
        util::log("Failed to find physical address of %s", proc_name);
        return 0;
    }

    typedef struct SYSTEM_MODULE {
        ULONG                Reserved1;
        ULONG                Reserved2;
#ifdef _WIN64
        ULONG				Reserved3;
#endif
        PVOID                ImageBaseAddress;
        ULONG                ImageSize;
        ULONG                Flags;
        WORD                 Id;
        WORD                 Rank;
        WORD                 w018;
        WORD                 NameOffset;
        CHAR                 Name[260];
    }SYSTEM_MODULE, * PSYSTEM_MODULE;

    typedef struct SYSTEM_MODULE_INFORMATION {
        ULONG                ModulesCount;
        SYSTEM_MODULE        Modules[1];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


    std::size_t driver::get_mod_base_addr(const char* mod)
    {
        ULONG retn;
        NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0xB), nullptr, 0, &retn);
        const auto minf = static_cast<PSYSTEM_MODULE_INFORMATION>(GlobalAlloc(GMEM_ZEROINIT, retn));
        util::log("%X", NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0xB), minf, sizeof SYSTEM_MODULE_INFORMATION, &retn));
        for (unsigned int i = 0; i < minf->ModulesCount; i++) {
            PVOID kernelImageBase = minf->Modules[i].ImageBaseAddress;
            const auto kernelImage = reinterpret_cast<PCHAR>(minf->Modules[i].Name);
            std::string final;
            for (int j = 0; kernelImage[j] != '\x00' && j < 260; j++)
                final.append(std::format("{:02X}", kernelImage[j]));
            if (final.empty())
                continue;
            util::log("Mod name %s", final.c_str());
            util::log("Base Addr 0x%llx\r\n", kernelImageBase);
        }
        return 0;
    }

    [[nodiscard]] bool driver::hk_pa(std::size_t target_hk_pa, const char* target_nt_proc) {
        util::log("Hooking NT procedure...");
        char bytes[]{ 0x48, '\xB8', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '\xFF', '\xE0'};

        const auto nt_proc_va = reinterpret_cast<std::uint64_t>(GetProcAddress(this->kernel_handle, target_nt_proc));
        if (!nt_proc_va)
            return util::log("Failed to get %s address. Error code: %d", target_nt_proc, GetLastError()), false;

        util::log("%s address: %x", target_nt_proc, nt_proc_va);
        *reinterpret_cast<std::uint64_t*>(bytes + 2) = nt_proc_va;

        this->original_instr = read_phys_mem<hook_sz>(target_hk_pa);
        if (!this->original_instr)
            return util::log("Failed to read native procedure's original instructions. Can't proceed"), false;

        const auto res = write_phys_mem<hook_sz>(target_hk_pa, bytes);
        if (!res)
            return false;
        const auto read_bytes = read_phys_mem<12>(target_hk_pa);
        util::log("fx: %X", *reinterpret_cast<std::uint64_t*>(bytes + 2));

        this->hk_addr = target_hk_pa;
        util::log("Hooked at %X", target_hk_pa);
        return true;
    }

    bool driver::unhk_pa() const {
        util::log("Unhooking native procedure...");

        if (!this->hk_addr)
            return util::log("Call hook_ntproc before calling unhook_ntproc!"), false;

        std::uint8_t buf[hook_sz]{};
        std::memcpy(buf, this->original_instr, hook_sz);
		const auto res = write_phys_mem<hook_sz>(this->hk_addr, buf);

        delete[] this->original_instr;
        if (!res)
           return util::log("Failed to unhook NT procedure"), false;
        util::log("Unhooked native procedure");
        return true;

    }
}

