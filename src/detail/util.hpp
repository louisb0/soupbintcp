#pragma once

#include "detail/assert.hpp"

#include <cstddef>
#include <random>
#include <string_view>

namespace soupbin::detail {

inline void preserving_close(int fd) noexcept {
    int saved = errno;
    close(fd);
    errno = saved;
}

inline void pad_field_left(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, (dst + width) - src.size());
}

inline void pad_field_right(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, dst);
}

// NOLINTBEGIN
inline std::string generate_session_id(size_t length) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        int val = dis(gen);
        result += (val < 10) ? ('0' + val) : ('a' + val - 10);
    }

    return result;
}
// NOLINTEND

} // namespace soupbin::detail
