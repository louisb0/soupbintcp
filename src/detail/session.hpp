#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace soupbin::detail {

struct client;

class session {
    std::string owner_username_;

    std::vector<std::byte> msg_buffer_;
    std::vector<size_t> msg_offsets_;

public:
    session(std::string owner_username) : owner_username_(std::move(owner_username)) {}

    [[nodiscard]] const std::string &owner_username() const noexcept { return owner_username_; }
    [[nodiscard]] size_t sequence_num() const noexcept { return msg_offsets_.size(); }

    [[nodiscard]] std::error_code replay(detail::client *c, size_t from_seq);
    void add_seq_msg(std::span<const std::byte>) noexcept;
};

} // namespace soupbin::detail
