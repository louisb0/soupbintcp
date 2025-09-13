local proto = Proto("soupbin", "SoupBinTCP_custom")

-- Field definitions
local f = proto.fields
f.length = ProtoField.uint16("soupbin.payload_length", "Payload Length", base.DEC)
f.msg_type = ProtoField.char("soupbin.type", "Message Type")
f.username = ProtoField.string("soupbin.username", "Username")
f.password = ProtoField.string("soupbin.password", "Password")
f.session_id = ProtoField.string("soupbin.session_id", "Session ID")
f.sequence_num = ProtoField.string("soupbin.sequence_num", "Sequence Number")
f.reject_code = ProtoField.string("soupbin.reject_code", "Reject Code")
f.data = ProtoField.bytes("soupbin.data", "Data")
f.direction = ProtoField.string("soupbin.direction", "Direction")
f.conversation = ProtoField.string("soupbin.conversation", "Conversation ID")

-- Message type definitions
local MSG_DEBUG = '+'
local MSG_LOGIN_REQUEST = 'L'
local MSG_LOGIN_ACCEPTED = 'A'
local MSG_LOGIN_REJECTED = 'J'
local MSG_CLIENT_HEARTBEAT = 'R'
local MSG_SERVER_HEARTBEAT = 'H'
local MSG_UNSEQUENCED = 'U'
local MSG_SEQUENCED = 'S'
local MSG_END_SESSION = 'Z'
local MSG_LOGOUT_REQUEST = 'O'

-- Conversation tracking table
local tcp_stream_field = Field.new("tcp.stream")
local conversations = {}  -- Key: stream_num, Value: {session_id, username, authenticated_at_frame}

-- Message type info
local message_info = {
    [MSG_DEBUG] = {
        name = "Debug",
        dissector = function(buffer, pinfo, tree)
            local data_len = buffer:len() - 3
            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
            return "[Debug]"
        end
    },
    [MSG_LOGIN_REQUEST] = {
        name = "Login Request",
        dissector = function(buffer, pinfo, tree, stream_num)
            local username = buffer(3, 6):string():gsub("%s+$", "")
            local session = buffer(19, 10):string():gsub("^%s+", ""):gsub("%s+$", "")
            local seq = buffer(29, 20):string():gsub("^%s+", "")

            tree:add(f.username, buffer(3, 6))
            tree:add(f.password, buffer(9, 10))
            tree:add(f.session_id, buffer(19, 10))
            tree:add(f.sequence_num, buffer(29, 20))

            conversations[stream_num] = {
                session_id = session,
                username = username,
                authenticated_at_frame = nil
            }

            return "[LoginRequest] user='" .. username .. "' session='" .. session .. "' seq=" .. seq
        end
    },
    [MSG_LOGIN_ACCEPTED] = {
        name = "Login Accepted",
        dissector = function(buffer, pinfo, tree, stream_num)
            local session = buffer(3, 10):string():gsub("^%s+", ""):gsub("%s+$", "")
            local seq = buffer(13, 20):string():gsub("^%s+", "")

            conversations[stream_num].authenticated_at_frame = pinfo.number
            conversations[stream_num].session_id = session

            local username = conversations[stream_num].username

            tree:add(f.session_id, buffer(3, 10))
            tree:add(f.sequence_num, buffer(13, 20))

            return "[LoginAccepted] user='" .. username .. "' session='" .. session .. "' seq=" .. seq
        end
    },
    [MSG_LOGIN_REJECTED] = {
        name = "Login Rejected",
        dissector = function(buffer, pinfo, tree, stream_num)
            local reject_reasons = {
                ['A'] = "not authorized",
                ['S'] = "session not available"
            }

            local reject_code = buffer(3, 1):string()
            local reason = reject_reasons[reject_code] or ("unknown (" .. reject_code .. ")")

            tree:add(f.reject_code, buffer(3, 1)):append_text(" (" .. reason .. ")")

            conversations[stream_num] = nil

            return "[LoginRejected] reason=" .. reason
        end
    },
    [MSG_CLIENT_HEARTBEAT] = {
        name = "Client Heartbeat",
        dissector = function(buffer, pinfo, tree)
            return "[ClientHeartbeat]"
        end
    },
    [MSG_SERVER_HEARTBEAT] = {
        name = "Server Heartbeat",
        dissector = function(buffer, pinfo, tree)
            return "[ServerHeartbeat]"
        end
    },
    [MSG_UNSEQUENCED] = {
        name = "Unsequenced",
        dissector = function(buffer, pinfo, tree)
            local data_len = buffer:len() - 3
            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
            return "[Unsequenced]"
        end
    },
    [MSG_SEQUENCED] = {
        name = "Sequenced",
        dissector = function(buffer, pinfo, tree)
            local data_len = buffer:len() - 3
            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
            return "[Sequenced]"
        end
    },
    [MSG_END_SESSION] = {
        name = "End of Session",
        dissector = function(buffer, pinfo, tree, stream_num)
            conversations[stream_num] = nil
            return "[EndofSession]"
        end
    },
    [MSG_LOGOUT_REQUEST] = {
        name = "Logout Request",
        dissector = function(buffer, pinfo, tree, stream_num)
            conversations[stream_num] = nil
            return "[LogoutRequest]"
        end
    }
}

local function dissect_message(buffer, pinfo, tree, tcp_stream, direction, conv_info)
    if buffer:len() < 3 then
        return 0
    end

    -- Get message length from header
    local msg_length = buffer(0, 2):uint()
    local total_length = 3 + msg_length  -- header (3) + payload

    -- Check if we have the complete message
    if buffer:len() < total_length then
        return 0  -- Need more data
    end

    -- Extract message type
    local msg_type_char = buffer(2, 1):string()
    local msg_info = message_info[msg_type_char]

    -- Create subtree for this message
    local msg_tree = tree:add(proto, buffer(0, total_length), "SoupBinTCP Message")

    -- Add direction
    msg_tree:add(f.direction, direction):set_generated()

    -- Add conversation info if available
    if conv_info and conv_info.authenticated_at_frame and pinfo.number > conv_info.authenticated_at_frame then
        local conv_id = string.format("%s@%s", conv_info.username or "?", conv_info.session_id or "?")
        msg_tree:add(f.conversation, conv_id):set_generated()
    end

    -- Add header
    local header_tree = msg_tree:add(proto, buffer(0, 3), "Header")
    header_tree:add(f.length, buffer(0, 2))

    -- Process message body
    local info_str = ""
    if msg_info then
        header_tree:add(f.msg_type, buffer(2, 1)):append_text(" (" .. msg_info.name .. ")")

        if msg_length > 0 then
            local body_tree = msg_tree:add(proto, buffer(3, msg_length), msg_info.name)
            info_str = msg_info.dissector(buffer(0, total_length), pinfo, body_tree, tcp_stream)
        else
            info_str = msg_info.dissector(buffer(0, total_length), pinfo, msg_tree, tcp_stream)
        end
    else
        local msg_type_byte = buffer(2, 1):uint()
        header_tree:add(f.msg_type, buffer(2, 1)):append_text((" (Unknown 0x%02x)"):format(msg_type_byte))
        info_str = string.format("[Unknown 0x%02x]", msg_type_byte)

        if msg_length > 0 then
            msg_tree:add(f.data, buffer(3, msg_length))
        end
    end

    return total_length, info_str
end

function proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "soupbin"

    -- Fetch conversation info
    local direction
    if pinfo.src_port == proto.prefs.port then
        direction = "S->C"
    elseif pinfo.dst_port == proto.prefs.port then
        direction = "C->S"
    else
        direction = "???"
    end

    local tcp_stream = tonumber(tostring(tcp_stream_field()))
    local conv_info = conversations[tcp_stream]

    -- Process all messages in the buffer
    local subtree = tree:add(proto, buffer(), "SoupBinTCP")

    local offset = 0
    local info_strings = {}
    local msg_count = 0

    while offset < buffer:len() do
        if buffer:len() - offset < 3 then
            pinfo.desegment_len = 3 - (buffer:len() - offset)
            pinfo.desegment_offset = offset
            return
        end

        local msg_length = buffer(offset, 2):uint()
        local total_length = 3 + msg_length

        if buffer:len() - offset < total_length then
            pinfo.desegment_len = total_length - (buffer:len() - offset)
            pinfo.desegment_offset = offset
            return
        end

        local msg_buffer = buffer(offset):tvb()

        local bytes_consumed, info_str = dissect_message(
            msg_buffer, pinfo, subtree, tcp_stream, direction, conv_info
        )

        offset = offset + bytes_consumed
        msg_count = msg_count + 1

        if info_str and info_str ~= "" then
            table.insert(info_strings, info_str)
        end
    end

    -- Build info column
    pinfo.cols.info = ""
    pinfo.cols.info:append("[" .. direction .. "] ")

    if conv_info and conv_info.authenticated_at_frame and pinfo.number > conv_info.authenticated_at_frame then
        local conv_id = string.format("%s@%s", conv_info.username or "?", conv_info.session_id or "?")
        pinfo.cols.info:append("[" .. conv_id .. "] ")
    end

    if msg_count > 1 then
        -- Avoid clutter for large replays
        pinfo.cols.info:append(string.format("[%d messages] ", msg_count))
    else
        pinfo.cols.info:append(table.concat(info_strings, " "))
    end
end

-- Register the dissector
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(8888, proto)

-- Preferences
proto.prefs.port = Pref.uint("Port", 8888, "SoupBinTCP server port")

function proto.prefs_changed()
    tcp_port_table:remove(8888, proto)
    tcp_port_table:add(proto.prefs.port, proto)
end

-- Export for debugging
function proto.init()
    conversations = {}
end
