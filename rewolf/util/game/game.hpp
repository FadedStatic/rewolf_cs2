#pragma once

#include <TlHelp32.h>
#include "../util.hpp"

namespace game_util {

    struct game_data {
        DWORD proc_id{};
        HMODULE game_module{};
        HMODULE client_module{};

        game_data() noexcept {
            util::log("%s", "Retrieving Counter-Strike 2 process ID...");
            HWND wnd_handle{ nullptr };

            do {
                wnd_handle = FindWindowA(nullptr, "Counter-Strike 2");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } while (!wnd_handle);

            GetWindowThreadProcessId(wnd_handle, &this->proc_id);
            util::log("%s %d", "Counter-Strike 2 process ID:", this->proc_id);

            util::log("Retrieving Counter-Strike 2 base module...");
            const auto mod_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proc_id);

            if (!mod_snapshot) {
                util::log("%s %d", "Failed to create snapshot of process modules. Error code: ", GetLastError());
                return;
            }

            MODULEENTRY32 mod_entry{};
            mod_entry.dwSize = sizeof(mod_entry);
            while (Module32Next(mod_snapshot, &mod_entry)) {
                if (std::string_view{ mod_entry.szModule }.compare("cs2.exe")) {
                    this->game_module = mod_entry.hModule;
                    util::log("%s %p", "Counter-Strike 2 base module:", this->game_module);
                    return;
                }
            }
        }
    };
}