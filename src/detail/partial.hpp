#pragma once

#include "detail/assert.hpp"
#include "detail/messages.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <span>

namespace soupbin::detail {

class partial {
    std::array<std::byte, detail::max_message_size> buffer{};
    size_t size{};

public:
    void store(std::span<const std::byte> input) {
        ASSERT(size == 0);
        std::memcpy(buffer.data(), input.data(), input.size());
        size = input.size();
    }

    size_t load(std::span<std::byte> output) {
        std::memcpy(output.data(), buffer.data(), size);
        size_t result = size;
        size = 0;
        return result;
    }
};

} // namespace soupbin::detail
