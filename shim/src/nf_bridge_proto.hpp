#pragma once
// Shared loopback IPC protocol between Windows/Wine nfapi.dll shim (inside
// ExitLag.exe) and the native Linux kernel TPROXY redirector (exitlag-nf-redir).
// Portable C++20 header usable cleanly on both Windows (clang-cl) and Linux (g++).

#include <cstdint>
#include <cstring>
#include <vector>

namespace shim::nf_proto {

constexpr std::uint16_t kDefaultNfIpcPort = 19850;
constexpr std::uint32_t kProtoVersion = 1;
constexpr std::uint32_t kMaxFrameBytes = 4u * 1024u * 1024u;

enum MsgType : std::uint8_t {
    kMsgHello = 1,             // nfapi.dll -> Linux
    kMsgTcpConnectReq = 2,     // Linux -> nfapi.dll
    kMsgTcpConnectResp = 3,    // nfapi.dll -> Linux
    kMsgTcpClosed = 4,         // Linux -> nfapi.dll
    kMsgUdpCreated = 5,        // Linux -> nfapi.dll
    kMsgUdpSend = 6,           // Linux -> nfapi.dll
    kMsgUdpClosed = 7,         // Linux -> nfapi.dll
    kMsgUdpPostSend = 8,       // nfapi.dll -> Linux
    kMsgUdpPostRecv = 9,       // nfapi.dll -> Linux
    kMsgUdpDisableFilter = 10, // nfapi.dll -> Linux
    kMsgUdpEnableFilter = 11,  // nfapi.dll -> Linux
    kMsgPing = 12,
    kMsgPong = 13,
};

enum TcpAction : std::uint8_t {
    kTcpAllowDirect = 0,
    kTcpBlock = 1,
    kTcpRedirect = 2,
};

// Always use kAf4 / kAf6 on the wire so Linux AF_INET6 (10) vs Windows AF_INET6 (23)
// never mismatches across the Wine boundary.
constexpr std::uint8_t kAf4 = 4;
constexpr std::uint8_t kAf6 = 6;

#pragma pack(push, 1)

struct MsgHeader {
    std::uint8_t type;
    std::uint8_t flags;
    std::uint16_t reserved;
    std::uint32_t length;  // payload byte count after this 8-byte header
};
static_assert(sizeof(MsgHeader) == 8);

struct MsgHello {
    std::uint32_t exitlag_pid;
    std::uint32_t proto_version;
};
static_assert(sizeof(MsgHello) == 8);

// Followed by proc_name_len UTF-8 bytes
struct MsgTcpConnectReq {
    std::uint64_t conn_id;
    std::uint32_t linux_pid;
    std::uint8_t af;  // 4 or 6
    std::uint8_t pad0;
    std::uint16_t proc_name_len;
    std::uint8_t local_ip[16];
    std::uint16_t local_port_be;
    std::uint16_t remote_port_be;
    std::uint8_t remote_ip[16];
};
static_assert(sizeof(MsgTcpConnectReq) == 52);

struct MsgTcpConnectResp {
    std::uint64_t conn_id;
    std::uint8_t action;  // TcpAction
    std::uint8_t af;      // 4 or 6
    std::uint16_t new_remote_port_be;
    std::uint8_t new_remote_ip[16];
};
static_assert(sizeof(MsgTcpConnectResp) == 28);

struct MsgTcpClosed {
    std::uint64_t conn_id;
    std::uint32_t linux_pid;
    std::uint8_t af;
    std::uint8_t pad[3];
    std::uint8_t local_ip[16];
    std::uint16_t local_port_be;
    std::uint16_t remote_port_be;
    std::uint8_t remote_ip[16];
};
static_assert(sizeof(MsgTcpClosed) == 52);

// Followed by proc_name_len UTF-8 bytes
struct MsgUdpCreated {
    std::uint64_t conn_id;
    std::uint32_t linux_pid;
    std::uint8_t af;
    std::uint8_t pad0;
    std::uint16_t proc_name_len;
    std::uint8_t local_ip[16];
    std::uint16_t local_port_be;
    std::uint16_t pad1;
};
static_assert(sizeof(MsgUdpCreated) == 36);

// Header for kMsgUdpSend, kMsgUdpPostSend, kMsgUdpPostRecv; followed by raw UDP payload
struct MsgUdpPacket {
    std::uint64_t conn_id;
    std::uint8_t af;
    std::uint8_t pad0;
    std::uint16_t remote_port_be;
    std::uint8_t remote_ip[16];
};
static_assert(sizeof(MsgUdpPacket) == 28);

struct MsgUdpClosed {
    std::uint64_t conn_id;
    std::uint32_t linux_pid;
    std::uint8_t af;
    std::uint8_t pad[3];
    std::uint8_t local_ip[16];
    std::uint16_t local_port_be;
    std::uint16_t pad1;
};
static_assert(sizeof(MsgUdpClosed) == 36);

struct MsgUdpConnId {
    std::uint64_t conn_id;
};
static_assert(sizeof(MsgUdpConnId) == 8);

#pragma pack(pop)

inline void append_frame(std::vector<std::uint8_t>& out, MsgType type, const void* hdr,
                         std::size_t hdr_len, const void* extra = nullptr,
                         std::size_t extra_len = 0) {
    MsgHeader mh{};
    mh.type = static_cast<std::uint8_t>(type);
    mh.flags = 0;
    mh.reserved = 0;
    mh.length = static_cast<std::uint32_t>(hdr_len + extra_len);
    const std::size_t old_sz = out.size();
    out.resize(old_sz + sizeof(MsgHeader) + hdr_len + extra_len);
    std::uint8_t* p = out.data() + old_sz;
    std::memcpy(p, &mh, sizeof(MsgHeader));
    p += sizeof(MsgHeader);
    if (hdr_len > 0 && hdr) {
        std::memcpy(p, hdr, hdr_len);
        p += hdr_len;
    }
    if (extra_len > 0 && extra) {
        std::memcpy(p, extra, extra_len);
    }
}

}  // namespace shim::nf_proto
