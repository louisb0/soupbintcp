local proto = Proto("soupbin", "SoupBinTCP_custom")

-- Field definitions
local f = proto.fields
f.length = ProtoField.uint16("soupbin.payload_payload_length", "Payload Length", base.DEC)
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
            pinfo.cols.info:append("[Debug]")

            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
        end
    },
    [MSG_LOGIN_REQUEST] = {
        name = "Login Request",
        dissector = function(buffer, pinfo, tree, stream_num)
            local username = buffer(3, 6):string():gsub("%s+$", "")
            local session = buffer(19, 10):string():gsub("^%s+", ""):gsub("%s+$", "")
            local seq = buffer(29, 20):string():gsub("^%s+", "")

            pinfo.cols.info:append("[LoginRequest] user='" .. username .. "' session='" .. session .. "' seq=" .. seq)

            tree:add(f.username, buffer(3, 6))
            tree:add(f.password, buffer(9, 10))
            tree:add(f.session_id, buffer(19, 10))
            tree:add(f.sequence_num, buffer(29, 20))

            conversations[stream_num] = {
                session_id = session,
                username = username,
                authenticated_at_frame = nil
            }
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

            pinfo.cols.info:append("[LoginAccepted] user='" .. username .. "' session='" .. session .. "' seq=" .. seq)

            tree:add(f.session_id, buffer(3, 10))
            tree:add(f.sequence_num, buffer(13, 20))
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
            pinfo.cols.info:append("[LoginRejected] reason=" .. reason)

            tree:add(f.reject_code, buffer(3, 1)):append_text(" (" .. reason .. ")")

            conversations[stream_num] = nil
        end
    },
    [MSG_CLIENT_HEARTBEAT] = {
        name = "Client Heartbeat",
        dissector = function(buffer, pinfo, tree)
            pinfo.cols.info:append("[ClientHeartbeat]")
        end
    },
    [MSG_SERVER_HEARTBEAT] = {
        name = "Server Heartbeat",
        dissector = function(buffer, pinfo, tree)
            pinfo.cols.info:append("[ServerHeartbeat]")
        end
    },
    [MSG_UNSEQUENCED] = {
        name = "Unsequenced",
        dissector = function(buffer, pinfo, tree)
            local data_len = buffer:len() - 3
            pinfo.cols.info:append("[Unsequenced]")

            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
        end
    },
    [MSG_SEQUENCED] = {
        name = "Sequenced",
        dissector = function(buffer, pinfo, tree)
            local data_len = buffer:len() - 3
            pinfo.cols.info:append("[Sequenced]")

            if data_len > 0 then
                tree:add(f.data, buffer(3, data_len))
            end
        end
    },
    [MSG_END_SESSION] = {
        name = "End of Session",
        dissector = function(buffer, pinfo, tree, stream_num)
            pinfo.cols.info:append("[EndofSession]")

            conversations[stream_num] = nil
        end
    },
    [MSG_LOGOUT_REQUEST] = {
        name = "Logout Request",
        dissector = function(buffer, pinfo, tree, stream_num)
            pinfo.cols.info:append("[LogoutRequest]")

            conversations[stream_num] = nil
        end
    }
}

function proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "soupbin"

    -- Add direction
    local direction
    if pinfo.src_port == proto.prefs.port then
        direction = "S->C"
    elseif pinfo.dst_port == proto.prefs.port then
        direction = "C->S"
    else
        direction = "???"
    end

    local subtree = tree:add(proto, buffer(), "SoupBinTCP")
    subtree:add(f.direction, direction):set_generated()

    pinfo.cols.info = ""
    pinfo.cols.info:append("[" .. direction .. "] ")

    -- Add conversation - only if after the authentication frame
    local tcp_stream = tonumber(tostring(tcp_stream_field()))
    local conv_info = conversations[tcp_stream]
    local msg_type_char = buffer(2, 1):string()

    if conv_info and conv_info.authenticated_at_frame and pinfo.number > conv_info.authenticated_at_frame then
        local conv_id = string.format("%s@%s", conv_info.username or "?", conv_info.session_id or "?")
        subtree:add(f.conversation, conv_id):set_generated()
        pinfo.cols.info:append("[" .. conv_id .. "] ")
    end

    -- Add header
    local header_tree = subtree:add(proto, buffer(0, 3), "Header")
    header_tree:add(f.length, buffer(0, 2))

    -- Add body
    local msg_info = message_info[msg_type_char]

    if msg_info then
        header_tree:add(f.msg_type, buffer(2, 1)):append_text(" (" .. msg_info.name .. ")")

        if buffer:len() > 3 then
            local body_tree = subtree:add(proto, buffer(3), msg_info.name)
            msg_info.dissector(buffer, pinfo, body_tree, tcp_stream)
        else
            msg_info.dissector(buffer, pinfo, subtree, tcp_stream)
        end
    else
        local msg_type_byte = buffer(2, 1):uint()
        header_tree:add(f.msg_type, buffer(2, 1)):append_text((" (Unknown 0x%02x)"):format(msg_type_byte))

        if buffer:len() > 3 then
            subtree:add(f.data, buffer(3))
        end
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
