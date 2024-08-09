#pragma once
#include "..\include.hpp"
#include <iostream>

namespace util {
    template < typename... args_t >
    inline void log(const std::string& format, args_t... args) {
        // if you want to make this a fucking pain in the ass go ahead (im not dealing with the refs)
        const std::string message = "[+] " + std::vformat(format, std::make_format_args(args...)) + '\n';
        OutputDebugStringA(message.c_str());
    }
}