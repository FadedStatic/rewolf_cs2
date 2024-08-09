#pragma once

#include <thread>
#include <Windows.h>
#include <TlHelp32.h>
#include "../util.hpp"

namespace game_util {

    struct game_data {
        std::uintptr_t game_base{};

        game_data() noexcept {
           
        }
    };
}