#pragma once

#include "detail/assert.hpp"

#include <cstddef>
#include <string_view>

namespace soupbin::detail {

inline void pad_field_left(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, dst);
}

inline void pad_field_right(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, (dst + width) - src.size());
}

} // namespace soupbin::detail
