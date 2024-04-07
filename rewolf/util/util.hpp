#pragma once
#include "includes.hpp"
#include <iostream>

namespace util {
    template < typename... args_t >
    inline void log(const char* format, args_t&&... args) {
        std::printf((std::string("[+] ") + format).c_str(), std::forward< args_t >(args)...);
        std::cout << '\n';
    }
}