#include "Helpers.h"

std::uint32_t Helpers::mod_add(std::initializer_list<std::uint32_t> list, std::uint64_t mod)
{
    std::uint64_t out = 0;

    for (auto n : list)
    {
        out += n;
        if (out >= mod)
            out %= mod;
    }

    return static_cast<std::uint32_t>(out);
}
