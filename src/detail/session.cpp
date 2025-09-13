#include "detail/session.hpp"

#include "detail/assert.hpp"
#include "detail/client_manager.hpp"
#include "detail/messages.hpp"

#include <cerrno>
#include <cstdint>

#include <arpa/inet.h>
#include <sys/socket.h>

namespace soupbin::detail {

std::error_code session::replay(detail::client *c, size_t from_seq) {
    DEBUG_ASSERT(c != nullptr);
    DEBUG_ASSERT(c->in_use());
    DEBUG_ASSERT(c->authenticated());
    DEBUG_ASSERT(c->session == this);

    if (!msg_offsets_.empty()) {
        ASSERT(from_seq < msg_offsets_.size());

        size_t start_byte = msg_offsets_[from_seq];
        if (send(c->fd, &msg_buffer_[start_byte], msg_buffer_.size() - start_byte, 0) == -1) {
            return { errno, std::system_category() };
        }
    }

    return {};
}

void session::add_seq_msg(std::span<const std::byte> data) noexcept {
    const detail::msg_sequenced msg = detail::msg_sequenced::build(data.size());
    const auto *msg_bytes = reinterpret_cast<const std::byte *>(&msg);

    msg_offsets_.push_back(msg_buffer_.size());
    msg_buffer_.insert(msg_buffer_.end(), msg_bytes, msg_bytes + sizeof(msg));
    msg_buffer_.insert(msg_buffer_.end(), data.begin(), data.end());
}

} // namespace soupbin::detail
