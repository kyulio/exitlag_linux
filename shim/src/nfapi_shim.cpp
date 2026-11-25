// Drop-in replacement for nfapi.dll (NetFilter SDK 2, Extensions v8) that bridges
// ExitLag.exe's NF_EventHandler callbacks over a loopback TCP socket (127.0.0.1:19850)
// to the native Linux kernel TPROXY redirector (exitlag-nf-redir).

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static_assert(offsetof(ICMP_ECHO_REPLY, Reserved) == 0x0e,
              "Unexpected ICMP_ECHO_REPLY::Reserved offset");
static_assert(offsetof(ICMPV6_ECHO_REPLY, Status) == 0x1c,
              "Unexpected ICMPV6_ECHO_REPLY::Status offset");
static_assert(sizeof(MIB_TCPROW_OWNER_PID) == 24, "Unexpected MIB_TCPROW_OWNER_PID size");
static_assert(offsetof(MIB_TCPTABLE_OWNER_PID, table) == 4,
              "Unexpected MIB_TCPTABLE_OWNER_PID::table offset");
static_assert(offsetof(MIB_TCPROW_OWNER_PID, dwLocalPort) == 0x08,
              "Unexpected MIB_TCPROW_OWNER_PID::dwLocalPort offset");
static_assert(offsetof(MIB_TCPROW_OWNER_PID, dwOwningPid) == 0x14,
              "Unexpected MIB_TCPROW_OWNER_PID::dwOwningPid offset");
static_assert(sizeof(MIB_TCP6ROW_OWNER_PID) == 56, "Unexpected MIB_TCP6ROW_OWNER_PID size");
static_assert(offsetof(MIB_TCP6TABLE_OWNER_PID, table) == 4,
              "Unexpected MIB_TCP6TABLE_OWNER_PID::table offset");
static_assert(offsetof(MIB_TCP6ROW_OWNER_PID, dwLocalPort) == 0x14,
              "Unexpected MIB_TCP6ROW_OWNER_PID::dwLocalPort offset");
static_assert(offsetof(MIB_TCP6ROW_OWNER_PID, dwOwningPid) == 0x34,
              "Unexpected MIB_TCP6ROW_OWNER_PID::dwOwningPid offset");

#include "nf_bridge_proto.hpp"

namespace np = shim::nf_proto;

namespace {

constexpr DWORD kExtensionsVersion = 8;
constexpr int kNfStatusSuccess = 0;
constexpr int kNfStatusFail = -1;
constexpr std::uint16_t kWinAfInet = 2;
constexpr std::uint16_t kWinAfInet6 = 23;

#pragma pack(push, 1)

struct NF_TCP_CONN_INFO {
    std::uint32_t filteringFlag;
    std::uint32_t processId;
    std::uint8_t direction;
    std::uint16_t ip_family;
    std::uint8_t localAddress[28];
    std::uint8_t remoteAddress[28];
};
static_assert(sizeof(NF_TCP_CONN_INFO) == 67);

struct NF_UDP_CONN_INFO {
    std::uint32_t processId;
    std::uint16_t ip_family;
    std::uint8_t localAddress[28];
};
static_assert(sizeof(NF_UDP_CONN_INFO) == 34);

struct NF_UDP_CONN_REQUEST {
    std::uint32_t filteringFlag;
    std::uint32_t processId;
    std::uint16_t ip_family;
    std::uint8_t localAddress[28];
    std::uint8_t remoteAddress[28];
};
static_assert(sizeof(NF_UDP_CONN_REQUEST) == 66);

struct NF_UDP_OPTIONS {
    std::uint32_t flags;
    std::int32_t optionsLength;
    std::uint8_t options[8];
};

struct NF_FLOWCTL_STAT {
    std::uint64_t inBytes;
    std::uint64_t outBytes;
};
static_assert(sizeof(NF_FLOWCTL_STAT) == 16);

#pragma pack(pop)

// Exact MSVC vtable order verified against ExitLag.exe WinpkFilterThread (0x14654f950).
struct NF_EventHandler {
    virtual void threadStart() = 0;
    virtual void threadEnd() = 0;
    virtual void tcpConnectRequest(std::uint64_t id, NF_TCP_CONN_INFO* pConnInfo) = 0;
    virtual void tcpConnected(std::uint64_t id, NF_TCP_CONN_INFO* pConnInfo) = 0;
    virtual void tcpClosed(std::uint64_t id, NF_TCP_CONN_INFO* pConnInfo) = 0;
    virtual void tcpReceive(std::uint64_t id, const char* buf, int len) = 0;
    virtual void tcpSend(std::uint64_t id, const char* buf, int len) = 0;
    virtual void tcpCanReceive(std::uint64_t id) = 0;
    virtual void tcpCanSend(std::uint64_t id) = 0;
    virtual void udpCreated(std::uint64_t id, NF_UDP_CONN_INFO* pConnInfo) = 0;
    virtual void udpConnectRequest(std::uint64_t id, NF_UDP_CONN_REQUEST* pConnReq) = 0;
    virtual void udpClosed(std::uint64_t id, NF_UDP_CONN_INFO* pConnInfo) = 0;
    virtual void udpReceive(std::uint64_t id, const unsigned char* remoteAddress, const char* buf,
                            int len, NF_UDP_OPTIONS* options) = 0;
    virtual void udpSend(std::uint64_t id, const unsigned char* remoteAddress, const char* buf,
                         int len, NF_UDP_OPTIONS* options) = 0;
    virtual void udpCanReceive(std::uint64_t id) = 0;
    virtual void udpCanSend(std::uint64_t id) = 0;
};

std::mutex g_log_mtx;
FILE* g_log_fp = nullptr;
bool g_log_inited = false;

void log_msg(const char* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (!g_log_inited) {
        g_log_inited = true;
        // EXITLAG_NF_LOG (set by run_exitlag.sh), else %TEMP%\nfapi_shim.log.
        wchar_t path_buf[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableW(L"EXITLAG_NF_LOG", path_buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
            DWORD t = GetTempPathW(MAX_PATH, path_buf);
            if (t == 0 || t + 16 >= MAX_PATH) return;
            wcscat_s(path_buf, MAX_PATH, L"nfapi_shim.log");
        }
        const wchar_t* path = path_buf;
        if (_wfopen_s(&g_log_fp, path, L"a") != 0) {
            g_log_fp = nullptr;
        }
    }
    if (!g_log_fp) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(g_log_fp, "%02u:%02u:%02u.%03u ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(g_log_fp, fmt, ap);
    va_end(ap);
    std::fputc('\n', g_log_fp);
    std::fflush(g_log_fp);
}

std::mutex g_lifecycle_mtx;
NF_EventHandler* g_handler = nullptr;
std::atomic<bool> g_running{false};
std::atomic<std::uint32_t> g_next_fc_handle{1};
std::thread g_worker;

std::mutex g_send_mtx;
SOCKET g_ipc_sock = INVALID_SOCKET;

std::mutex g_proc_mtx;
std::unordered_map<std::uint32_t, std::wstring> g_proc_names;

struct ActiveTcpEntry {
    std::uint32_t nf_pid = 0;
    std::uint8_t af = 0;
    std::uint8_t local_ip[16]{};
    std::uint16_t local_port_be = 0;
    std::uint8_t remote_ip[16]{};
    std::uint16_t remote_port_be = 0;
};
std::mutex g_active_tcp_mtx;
std::unordered_map<std::uint64_t, ActiveTcpEntry> g_active_tcp;

std::wstring utf8_to_wide(const char* s, std::size_t len) {
    if (!s || len == 0) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s, static_cast<int>(len), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, static_cast<int>(len), out.data(), needed);
    return out;
}

void store_proc_name(std::uint32_t nf_pid, const char* utf8, std::uint16_t len) {
    if (len == 0 || !utf8) return;
    std::wstring w = utf8_to_wide(utf8, len);
    if (w.empty()) return;
    std::lock_guard<std::mutex> lk(g_proc_mtx);
    if (g_proc_names.size() > 8192) {
        g_proc_names.clear();
    }
    g_proc_names[nf_pid] = std::move(w);
}

std::uint32_t map_linux_pid(std::uint32_t linux_pid) {
    // High bit avoids colliding with ExitLag.exe's own Wine PID check.
    return 0x40000000u | (linux_pid & 0x3FFFFFFFu);
}

void fill_win_sockaddr(std::uint8_t af, const std::uint8_t ip[16], std::uint16_t port_be,
                       std::uint8_t out[28]) {
    std::memset(out, 0, 28);
    if (af == np::kAf4) {
        auto* s4 = reinterpret_cast<sockaddr_in*>(out);
        s4->sin_family = AF_INET;  // 2
        s4->sin_port = port_be;
        std::memcpy(&s4->sin_addr, ip, 4);
    } else {
        auto* s6 = reinterpret_cast<sockaddr_in6*>(out);
        s6->sin6_family = AF_INET6;  // Windows AF_INET6 == 23
        s6->sin6_port = port_be;
        std::memcpy(&s6->sin6_addr, ip, 16);
    }
}

bool extract_win_sockaddr(const std::uint8_t* addr, std::uint8_t& af, std::uint8_t ip[16],
                          std::uint16_t& port_be) {
    std::memset(ip, 0, 16);
    if (!addr) return false;
    std::uint16_t fam = 0;
    std::memcpy(&fam, addr, 2);
    if (fam == AF_INET) {
        const auto* s4 = reinterpret_cast<const sockaddr_in*>(addr);
        af = np::kAf4;
        port_be = s4->sin_port;
        std::memcpy(ip, &s4->sin_addr, 4);
        return true;
    }
    if (fam == AF_INET6 || fam == kWinAfInet6) {
        const auto* s6 = reinterpret_cast<const sockaddr_in6*>(addr);
        af = np::kAf6;
        port_be = s6->sin6_port;
        std::memcpy(ip, &s6->sin6_addr, 16);
        return true;
    }
    return false;
}

bool send_all(SOCKET s, const std::uint8_t* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        int rc = send(s, reinterpret_cast<const char*>(data + off),
                      static_cast<int>(len - off), 0);
        if (rc <= 0) return false;
        off += static_cast<std::size_t>(rc);
    }
    return true;
}

bool send_frame(np::MsgType type, const void* hdr, std::size_t hdr_len,
                const void* extra = nullptr, std::size_t extra_len = 0) {
    std::vector<std::uint8_t> buf;
    np::append_frame(buf, type, hdr, hdr_len, extra, extra_len);
    std::lock_guard<std::mutex> lk(g_send_mtx);
    if (g_ipc_sock == INVALID_SOCKET) return false;
    if (!send_all(g_ipc_sock, buf.data(), buf.size())) {
        shutdown(g_ipc_sock, SD_BOTH);
        return false;
    }
    return true;
}

bool recv_exact(SOCKET s, std::uint8_t* dst, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        if (!g_running.load()) return false;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        timeval tv{0, 200000};
        int sr = select(0, &rfds, nullptr, nullptr, &tv);
        if (sr == 0) continue;
        if (sr < 0) return false;
        int rc = recv(s, reinterpret_cast<char*>(dst + off), static_cast<int>(len - off), 0);
        if (rc <= 0) return false;
        off += static_cast<std::size_t>(rc);
    }
    return true;
}

void parse_ipc_endpoint(std::uint32_t& ip_be, std::uint16_t& port_be) {
    ip_be = htonl(INADDR_LOOPBACK);
    port_be = htons(np::kDefaultNfIpcPort);
    char buf[128]{};
    DWORD n = GetEnvironmentVariableA("EXITLAG_NF_IPC", buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return;
    std::string spec(buf, n);
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) return;
    std::string host = spec.substr(0, colon);
    unsigned long p = std::strtoul(spec.substr(colon + 1).c_str(), nullptr, 10);
    in_addr ia{};
    if (inet_pton(AF_INET, host.c_str(), &ia) == 1 && p > 0 && p <= 65535) {
        ip_be = ia.s_addr;
        port_be = htons(static_cast<std::uint16_t>(p));
    }
}

SOCKET connect_ipc_interruptible(std::uint32_t ip_be, std::uint16_t port_be) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be;
    sa.sin_port = port_be;

    int rc = connect(s, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        while (g_running.load()) {
            fd_set wfds, efds;
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            FD_SET(s, &wfds);
            FD_SET(s, &efds);
            timeval tv{0, 200000};
            int sr = select(0, nullptr, &wfds, &efds, &tv);
            if (sr > 0) {
                int so_err = 0;
                int slen = sizeof(so_err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &slen);
                if (so_err != 0 || FD_ISSET(s, &efds)) {
                    closesocket(s);
                    return INVALID_SOCKET;
                }
                break;
            }
            if (sr < 0) {
                closesocket(s);
                return INVALID_SOCKET;
            }
        }
    }
    if (!g_running.load()) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
    return s;
}

void handle_message(np::MsgType type, const std::vector<std::uint8_t>& payload) {
    NF_EventHandler* h = g_handler;
    if (!h) return;

    switch (type) {
        case np::kMsgTcpConnectReq: {
            if (payload.size() < sizeof(np::MsgTcpConnectReq)) break;
            np::MsgTcpConnectReq req{};
            std::memcpy(&req, payload.data(), sizeof(req));
            if (payload.size() < sizeof(req) + req.proc_name_len) break;

            std::uint32_t nf_pid = map_linux_pid(req.linux_pid);
            if (req.proc_name_len > 0) {
                store_proc_name(nf_pid,
                                reinterpret_cast<const char*>(payload.data() + sizeof(req)),
                                req.proc_name_len);
            }

            NF_TCP_CONN_INFO info{};
            info.filteringFlag = 0x10;  // NF_INDICATE_CONNECT_REQUESTS
            info.processId = nf_pid;
            info.direction = 2;  // NF_D_OUT
            info.ip_family = (req.af == np::kAf4) ? kWinAfInet : kWinAfInet6;
            fill_win_sockaddr(req.af, req.local_ip, req.local_port_be, info.localAddress);
            fill_win_sockaddr(req.af, req.remote_ip, req.remote_port_be, info.remoteAddress);

            // Call ExitLag without holding g_send_mtx.
            h->tcpConnectRequest(req.conn_id, &info);

            np::MsgTcpConnectResp resp{};
            resp.conn_id = req.conn_id;
            std::uint8_t out_af = req.af;
            std::uint8_t out_ip[16]{};
            std::uint16_t out_port_be = req.remote_port_be;

            if ((info.filteringFlag & 1u) != 0) {
                resp.action = np::kTcpBlock;
            } else if (extract_win_sockaddr(info.remoteAddress, out_af, out_ip, out_port_be)) {
                const std::size_t addr_bytes = (out_af == np::kAf4) ? 4 : 16;
                const bool changed = (out_af != req.af) ||
                                     (out_port_be != req.remote_port_be) ||
                                     (std::memcmp(out_ip, req.remote_ip, addr_bytes) != 0);
                resp.action = changed ? np::kTcpRedirect : np::kTcpAllowDirect;
                resp.af = out_af;
                resp.new_remote_port_be = out_port_be;
                std::memcpy(resp.new_remote_ip, out_ip, 16);
            } else {
                resp.action = np::kTcpAllowDirect;
                resp.af = req.af;
                resp.new_remote_port_be = req.remote_port_be;
                std::memcpy(resp.new_remote_ip, req.remote_ip, 16);
            }
            if (resp.action == np::kTcpRedirect) {
                ActiveTcpEntry entry{};
                entry.nf_pid = nf_pid;
                entry.af = req.af;
                std::memcpy(entry.local_ip, req.local_ip, 16);
                entry.local_port_be = req.local_port_be;
                std::memcpy(entry.remote_ip, req.remote_ip, 16);
                entry.remote_port_be = req.remote_port_be;
                {
                    std::lock_guard<std::mutex> tlk(g_active_tcp_mtx);
                    g_active_tcp[req.conn_id] = entry;
                }
                if (!send_frame(np::kMsgTcpConnectResp, &resp, sizeof(resp))) {
                    std::lock_guard<std::mutex> tlk(g_active_tcp_mtx);
                    g_active_tcp.erase(req.conn_id);
                }
            } else {
                send_frame(np::kMsgTcpConnectResp, &resp, sizeof(resp));
            }
            break;
        }
        case np::kMsgTcpClosed: {
            if (payload.size() < sizeof(np::MsgTcpClosed)) break;
            np::MsgTcpClosed msg{};
            std::memcpy(&msg, payload.data(), sizeof(msg));
            {
                std::lock_guard<std::mutex> tlk(g_active_tcp_mtx);
                g_active_tcp.erase(msg.conn_id);
            }
            NF_TCP_CONN_INFO info{};
            info.filteringFlag = 0;
            info.processId = map_linux_pid(msg.linux_pid);
            info.direction = 2;
            info.ip_family = (msg.af == np::kAf4) ? kWinAfInet : kWinAfInet6;
            fill_win_sockaddr(msg.af, msg.local_ip, msg.local_port_be, info.localAddress);
            fill_win_sockaddr(msg.af, msg.remote_ip, msg.remote_port_be, info.remoteAddress);
            h->tcpClosed(msg.conn_id, &info);
            break;
        }
        case np::kMsgUdpCreated: {
            if (payload.size() < sizeof(np::MsgUdpCreated)) break;
            np::MsgUdpCreated msg{};
            std::memcpy(&msg, payload.data(), sizeof(msg));
            if (payload.size() < sizeof(msg) + msg.proc_name_len) break;
            std::uint32_t nf_pid = map_linux_pid(msg.linux_pid);
            if (msg.proc_name_len > 0) {
                store_proc_name(nf_pid,
                                reinterpret_cast<const char*>(payload.data() + sizeof(msg)),
                                msg.proc_name_len);
            }
            NF_UDP_CONN_INFO info{};
            info.processId = nf_pid;
            info.ip_family = (msg.af == np::kAf4) ? kWinAfInet : kWinAfInet6;
            fill_win_sockaddr(msg.af, msg.local_ip, msg.local_port_be, info.localAddress);
            h->udpCreated(msg.conn_id, &info);
            break;
        }
        case np::kMsgUdpSend: {
            if (payload.size() < sizeof(np::MsgUdpPacket)) break;
            np::MsgUdpPacket hdr{};
            std::memcpy(&hdr, payload.data(), sizeof(hdr));
            std::uint8_t remote_addr[28]{};
            fill_win_sockaddr(hdr.af, hdr.remote_ip, hdr.remote_port_be, remote_addr);
            const char* pkt_data =
                reinterpret_cast<const char*>(payload.data() + sizeof(hdr));
            const int pkt_len = static_cast<int>(payload.size() - sizeof(hdr));
            NF_UDP_OPTIONS opts{};
            opts.flags = 0;
            opts.optionsLength = 0;
            // ExitLag synchronously calls nf_udpPostSend / nf_udpDisableFiltering inside udpSend.
            h->udpSend(hdr.conn_id, remote_addr, pkt_data, pkt_len, &opts);
            break;
        }
        case np::kMsgUdpClosed: {
            if (payload.size() < sizeof(np::MsgUdpClosed)) break;
            np::MsgUdpClosed msg{};
            std::memcpy(&msg, payload.data(), sizeof(msg));
            NF_UDP_CONN_INFO info{};
            info.processId = map_linux_pid(msg.linux_pid);
            info.ip_family = (msg.af == np::kAf4) ? kWinAfInet : kWinAfInet6;
            fill_win_sockaddr(msg.af, msg.local_ip, msg.local_port_be, info.localAddress);
            h->udpClosed(msg.conn_id, &info);
            break;
        }
        case np::kMsgPing: {
            send_frame(np::kMsgPong, nullptr, 0);
            break;
        }
        default:
            break;
    }
}

void ipc_worker_main() {
    if (g_handler) {
        g_handler->threadStart();
    }

    std::uint32_t ip_be = 0;
    std::uint16_t port_be = 0;
    parse_ipc_endpoint(ip_be, port_be);
    log_msg("ipc worker started (target port=%u)", ntohs(port_be));

    std::vector<std::uint8_t> payload;
    while (g_running.load()) {
        SOCKET s = connect_ipc_interruptible(ip_be, port_be);
        if (s == INVALID_SOCKET) {
            if (!g_running.load()) break;
            Sleep(500);
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(g_send_mtx);
            g_ipc_sock = s;
        }
        log_msg("ipc connected");

        np::MsgHello hello{GetCurrentProcessId(), np::kProtoVersion};
        if (send_frame(np::kMsgHello, &hello, sizeof(hello))) {
            while (g_running.load()) {
                np::MsgHeader mh{};
                if (!recv_exact(s, reinterpret_cast<std::uint8_t*>(&mh), sizeof(mh))) break;
                if (mh.length > np::kMaxFrameBytes) {
                    log_msg("ipc oversized frame: %u", mh.length);
                    break;
                }
                payload.resize(mh.length);
                if (mh.length > 0 && !recv_exact(s, payload.data(), mh.length)) break;
                handle_message(static_cast<np::MsgType>(mh.type), payload);
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_send_mtx);
            if (g_ipc_sock == s) {
                g_ipc_sock = INVALID_SOCKET;
            }
        }
        closesocket(s);
        {
            std::lock_guard<std::mutex> tlk(g_active_tcp_mtx);
            g_active_tcp.clear();
        }
        log_msg("ipc disconnected");
        if (g_running.load()) Sleep(500);
    }

    if (g_handler) {
        g_handler->threadEnd();
    }
    log_msg("ipc worker stopped");
}

void install_compat_hooks();

}  // namespace

extern "C" {

int shim_nf_init(const char* driverName, NF_EventHandler* pHandler) {
    install_compat_hooks();
    std::lock_guard<std::mutex> lk(g_lifecycle_mtx);
    log_msg("nf_init(driver=%s, handler=%p)", driverName ? driverName : "(null)", pHandler);
    if (!pHandler) return kNfStatusFail;
    if (g_running.load()) {
        g_running.store(false);
        {
            std::lock_guard<std::mutex> slk(g_send_mtx);
            if (g_ipc_sock != INVALID_SOCKET) shutdown(g_ipc_sock, SD_BOTH);
        }
        if (g_worker.joinable()) g_worker.join();
    }
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    g_handler = pHandler;
    g_running.store(true);
    g_worker = std::thread(ipc_worker_main);
    return kNfStatusSuccess;
}

void shim_nf_free() {
    std::lock_guard<std::mutex> lk(g_lifecycle_mtx);
    log_msg("nf_free()");
    g_running.store(false);
    {
        std::lock_guard<std::mutex> slk(g_send_mtx);
        if (g_ipc_sock != INVALID_SOCKET) {
            shutdown(g_ipc_sock, SD_BOTH);
        }
    }
    if (g_worker.joinable()) {
        g_worker.join();
    }
    {
        std::lock_guard<std::mutex> tlk(g_active_tcp_mtx);
        g_active_tcp.clear();
    }
    g_handler = nullptr;
}

unsigned long shim_nf_getExtensionsVersion() {
    log_msg("nf_getExtensionsVersion() -> %lu", static_cast<unsigned long>(kExtensionsVersion));
    return kExtensionsVersion;
}

int shim_nf_setRulesEx(void* /*pRules*/, int nCount) {
    log_msg("nf_setRulesEx(count=%d)", nCount);
    return kNfStatusSuccess;
}

void shim_nf_setIPEventHandler(void* pHandler) {
    log_msg("nf_setIPEventHandler(%p)", pHandler);
}

int shim_nf_getProcessNameFromKernel(unsigned long processId, wchar_t* buf, unsigned long len) {
    if (!buf || len == 0) return 0;
    std::wstring name;
    {
        std::lock_guard<std::mutex> lk(g_proc_mtx);
        auto it = g_proc_names.find(static_cast<std::uint32_t>(processId));
        if (it != g_proc_names.end()) {
            name = it->second;
        }
    }
    static std::atomic<int> proc_log_count{0};
    const int log_idx = proc_log_count.fetch_add(1);
    if (name.empty()) {
        if (log_idx < 10) {
            log_msg("nf_getProcessNameFromKernel(pid=0x%lx) -> not found", processId);
        }
        return 0;
    }
    if (log_idx < 10) {
        char u8[512]{};
        int n8 = WideCharToMultiByte(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), u8,
                                     static_cast<int>(sizeof(u8) - 1), nullptr, nullptr);
        if (n8 > 0) u8[n8] = '\0';
        log_msg("nf_getProcessNameFromKernel(pid=0x%lx) -> %s", processId, u8);
    }
    std::size_t copy_n = name.size();
    if (copy_n >= static_cast<std::size_t>(len)) {
        copy_n = static_cast<std::size_t>(len) - 1;
    }
    std::memcpy(buf, name.data(), copy_n * sizeof(wchar_t));
    buf[copy_n] = L'\0';
    return 1;
}

int shim_nf_udpPostSend(std::uint64_t id, const unsigned char* remoteAddress, const char* buf,
                        int len, NF_UDP_OPTIONS* /*options*/) {
    if (len < 0) return kNfStatusFail;
    np::MsgUdpPacket hdr{};
    hdr.conn_id = id;
    if (!extract_win_sockaddr(remoteAddress, hdr.af, hdr.remote_ip, hdr.remote_port_be)) {
        return kNfStatusFail;
    }
    return send_frame(np::kMsgUdpPostSend, &hdr, sizeof(hdr), buf, static_cast<std::size_t>(len))
               ? kNfStatusSuccess
               : kNfStatusFail;
}

int shim_nf_udpPostReceive(std::uint64_t id, const unsigned char* remoteAddress, const char* buf,
                           int len, NF_UDP_OPTIONS* /*options*/) {
    if (len < 0) return kNfStatusFail;
    np::MsgUdpPacket hdr{};
    hdr.conn_id = id;
    if (!extract_win_sockaddr(remoteAddress, hdr.af, hdr.remote_ip, hdr.remote_port_be)) {
        return kNfStatusFail;
    }
    return send_frame(np::kMsgUdpPostRecv, &hdr, sizeof(hdr), buf, static_cast<std::size_t>(len))
               ? kNfStatusSuccess
               : kNfStatusFail;
}

int shim_nf_udpDisableFiltering(std::uint64_t id) {
    np::MsgUdpConnId msg{id};
    return send_frame(np::kMsgUdpDisableFilter, &msg, sizeof(msg)) ? kNfStatusSuccess
                                                                   : kNfStatusFail;
}

int shim_nf_udpEnableFiltering(std::uint64_t id) {
    np::MsgUdpConnId msg{id};
    return send_frame(np::kMsgUdpEnableFilter, &msg, sizeof(msg)) ? kNfStatusSuccess
                                                                  : kNfStatusFail;
}

int shim_nf_udpAddRemoteAddrRule(std::uint64_t /*id*/, void* /*pRule*/) {
    return kNfStatusSuccess;
}

int shim_nf_addFlowCtl(void* /*pData*/, std::uint32_t* pFcHandle) {
    if (pFcHandle) {
        *pFcHandle = g_next_fc_handle.fetch_add(1);
    }
    return kNfStatusSuccess;
}

int shim_nf_deleteFlowCtl(std::uint32_t /*fcHandle*/) { return kNfStatusSuccess; }

int shim_nf_setFlowCtlQueueParams(std::uint32_t /*fcHandle*/, void* /*pParams*/) {
    return kNfStatusSuccess;
}

int shim_nf_setTCPFlowCtl(std::uint64_t /*id*/, std::uint32_t /*fcHandle*/) {
    return kNfStatusSuccess;
}

int shim_nf_setUDPFlowCtl(std::uint64_t /*id*/, std::uint32_t /*fcHandle*/) {
    return kNfStatusSuccess;
}

int shim_nf_modifyFlowCtl(std::uint32_t /*fcHandle*/, void* /*pData*/) {
    return kNfStatusSuccess;
}

int shim_nf_getFlowCtlStat(std::uint32_t /*fcHandle*/, void* pStat) {
    if (pStat) {
        std::memset(pStat, 0, sizeof(NF_FLOWCTL_STAT));
    }
    return kNfStatusSuccess;
}

}  // extern "C"

// ---------------------------------------------------------------------------
// Wine compatibility hooks (IAT patching for ExitLag.exe and libexitlag.dll):
// 1. Auto-answer ExitLag's "WMI is not accessable! Try to repair WMI
//    automatically?" prompt with No (Wine lacks Win32_LogicalDiskRootDirectory).
// 2. Serialize/run async ICMP requests (Event/ApcRoutine != nullptr) onto
//    Wine's synchronous IcmpSendEcho2Ex / Icmp6SendEcho2 path inside a bounded
//    worker pool. Wine 11.22's async iphlpapi path allocates a 0x30-byte
//    async_icmp_data struct, frees it synchronously when NtDeviceIoControlFile
//    returns STATUS_SUCCESS (e.g. IPv6 no-route 11050), and then double-frees
//    the same 0x30-byte block from its IOCP callback, corrupting libexitlag's
//    0x30-byte std::unordered_map nodes.
// ---------------------------------------------------------------------------
namespace {

std::atomic<bool> g_process_detaching{false};

bool patch_module_iat(HMODULE mod, const char* dll_name, const char* func_name,
                      void* hook_fn, void** orig_out) {
    if (!mod || !dll_name || !func_name || !hook_fn) return false;
    auto* base = reinterpret_cast<unsigned char*>(mod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;

    for (auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
         imp->Name; ++imp) {
        if (_stricmp(reinterpret_cast<const char*>(base + imp->Name), dll_name) != 0) continue;
        if (!imp->OriginalFirstThunk || !imp->FirstThunk) continue;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->OriginalFirstThunk);
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
        for (; names->u1.AddressOfData; ++names, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), func_name) != 0) continue;
            if (iat->u1.Function == reinterpret_cast<ULONG_PTR>(hook_fn)) return true;
            DWORD old = 0;
            if (!VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                return false;
            }
            if (orig_out && !*orig_out) {
                *orig_out = reinterpret_cast<void*>(iat->u1.Function);
            }
            iat->u1.Function = reinterpret_cast<ULONG_PTR>(hook_fn);
            VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
            return true;
        }
    }
    return false;
}

using MessageBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t g_orig_MessageBoxA = nullptr;

int WINAPI hook_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    if (text && std::strstr(text, "WMI") && std::strstr(text, "repair")) {
        log_msg("auto-answered WMI repair prompt with No (Wine lacks "
                "Win32_LogicalDiskRootDirectory)");
        return IDNO;
    }
    return g_orig_MessageBoxA ? g_orig_MessageBoxA(hwnd, text, caption, type) : IDNO;
}

using IcmpCreateFile_t = HANDLE(WINAPI*)();
using Icmp6CreateFile_t = HANDLE(WINAPI*)();
using IcmpCloseHandle_t = BOOL(WINAPI*)(HANDLE);
using IcmpSendEcho2Ex_t = DWORD(WINAPI*)(HANDLE, HANDLE, PVOID, PVOID, IPAddr, IPAddr, LPVOID,
                                         WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
using Icmp6SendEcho2_t = DWORD(WINAPI*)(HANDLE, HANDLE, PVOID, PVOID, struct sockaddr_in6*,
                                        struct sockaddr_in6*, LPVOID, WORD,
                                        PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
using IcmpApcFn_t = VOID(WINAPI*)(PVOID ApcContext, PVOID IoStatusBlock, ULONG Reserved);

IcmpCreateFile_t g_orig_IcmpCreateFile = nullptr;
Icmp6CreateFile_t g_orig_Icmp6CreateFile = nullptr;
IcmpCloseHandle_t g_orig_IcmpCloseHandle = nullptr;
IcmpSendEcho2Ex_t g_orig_IcmpSendEcho2Ex = nullptr;
Icmp6SendEcho2_t g_orig_Icmp6SendEcho2 = nullptr;

struct ScopedWinHandle {
    HANDLE h = nullptr;
    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE v) : h(v) {}
    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    ScopedWinHandle(ScopedWinHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
    ScopedWinHandle& operator=(ScopedWinHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h = o.h;
            o.h = nullptr;
        }
        return *this;
    }
    ~ScopedWinHandle() { reset(); }
    void reset(HANDLE next = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE && !g_process_detaching.load(std::memory_order_acquire)) {
            CloseHandle(h);
        }
        h = next;
    }
    HANDLE get() const { return h; }
};

struct IcmpSlot {
    HANDLE real_handle = INVALID_HANDLE_VALUE;
    std::mutex mtx;
    bool closed = false;

    ~IcmpSlot() {
        if (real_handle != INVALID_HANDLE_VALUE &&
            !g_process_detaching.load(std::memory_order_acquire) && g_orig_IcmpCloseHandle) {
            g_orig_IcmpCloseHandle(real_handle);
        }
    }
};

struct IcmpJob {
    std::shared_ptr<IcmpSlot> slot;
    bool is_ipv6 = false;
    ScopedWinHandle dup_event;
    ScopedWinHandle dup_thread;
    PVOID apc_routine = nullptr;
    PVOID apc_context = nullptr;
    IPAddr src4 = 0;
    IPAddr dst4 = 0;
    sockaddr_in6 src6{};
    sockaddr_in6 dst6{};
    std::vector<std::uint8_t> request_data;
    WORD request_size = 0;
    bool has_options = false;
    IP_OPTION_INFORMATION options{};
    std::vector<std::uint8_t> options_data;
    LPVOID caller_reply_buf = nullptr;
    DWORD reply_size = 0;
    DWORD timeout = 0;
};

struct IcmpApcPayload {
    PVOID apc_routine = nullptr;
    PVOID apc_context = nullptr;
    std::uintptr_t iosb[2]{};
};

VOID CALLBACK icmp_apc_trampoline(ULONG_PTR dwParam) {
    auto* p = reinterpret_cast<IcmpApcPayload*>(dwParam);
    if (!p) return;
    auto fn = reinterpret_cast<IcmpApcFn_t>(p->apc_routine);
    PVOID ctx = p->apc_context;
    std::uintptr_t iosb_copy[2]{p->iosb[0], p->iosb[1]};
    delete p;
    if (fn) {
        fn(ctx, iosb_copy, 0);
    }
}

struct IcmpAsyncPool {
    static constexpr std::size_t kMaxWorkers = 64;
    std::mutex mtx;
    std::condition_variable cv;
    std::deque<IcmpJob> queue;
    std::size_t total_workers = 0;
    std::size_t idle_workers = 0;
};

IcmpAsyncPool* get_icmp_pool() {
    // Deliberately process-lifetime allocated so worker threads never race with
    // static destructors during DLL_PROCESS_DETACH loader lock.
    static auto* pool = new IcmpAsyncPool();
    return pool;
}

std::mutex g_icmp_slots_mtx;
std::unordered_map<HANDLE, std::shared_ptr<IcmpSlot>> g_icmp_slots;

std::shared_ptr<IcmpSlot> get_or_register_slot(HANDLE h) {
    std::lock_guard<std::mutex> lk(g_icmp_slots_mtx);
    auto it = g_icmp_slots.find(h);
    if (it != g_icmp_slots.end()) return it->second;
    auto slot = std::make_shared<IcmpSlot>();
    slot->real_handle = h;
    g_icmp_slots.emplace(h, slot);
    return slot;
}

void execute_icmp_job(IcmpJob job) {
    if (g_process_detaching.load(std::memory_order_acquire) || !job.slot) return;
    HANDLE raw_handle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> slk(job.slot->mtx);
        if (job.slot->closed || job.slot->real_handle == INVALID_HANDLE_VALUE) return;
        raw_handle = job.slot->real_handle;
    }

    IP_OPTION_INFORMATION local_opts{};
    PIP_OPTION_INFORMATION opts_ptr = nullptr;
    if (job.has_options) {
        local_opts = job.options;
        local_opts.OptionsData = job.options_data.empty() ? nullptr : job.options_data.data();
        opts_ptr = &local_opts;
    }

    std::vector<std::uint8_t> local_reply(job.reply_size, 0);
    LPVOID req_ptr = job.request_data.empty() ? nullptr : job.request_data.data();
    DWORD ret = 0;
    DWORD last_err = 0;

    if (job.is_ipv6) {
        if (!g_orig_Icmp6SendEcho2) return;
        ret = g_orig_Icmp6SendEcho2(raw_handle, nullptr, nullptr, nullptr, &job.src6, &job.dst6,
                                    req_ptr, job.request_size, opts_ptr, local_reply.data(),
                                    job.reply_size, job.timeout);
    } else {
        if (!g_orig_IcmpSendEcho2Ex) return;
        ret = g_orig_IcmpSendEcho2Ex(raw_handle, nullptr, nullptr, nullptr, job.src4, job.dst4,
                                     req_ptr, job.request_size, opts_ptr, local_reply.data(),
                                     job.reply_size, job.timeout);
    }
    if (ret == 0) {
        last_err = GetLastError();
    }

    if (!job.is_ipv6 && job.reply_size >= sizeof(ICMP_ECHO_REPLY)) {
        auto* replies = reinterpret_cast<ICMP_ECHO_REPLY*>(local_reply.data());
        const auto local_begin = reinterpret_cast<std::uintptr_t>(local_reply.data());
        const auto local_end = local_begin + job.reply_size;
        const auto caller_begin = reinterpret_cast<std::uintptr_t>(job.caller_reply_buf);
        const DWORD rebase_count = (ret > 0) ? ret : 1;
        for (DWORD i = 0; i < rebase_count; ++i) {
            if ((i + 1) * sizeof(ICMP_ECHO_REPLY) > job.reply_size) break;
            const auto dptr = reinterpret_cast<std::uintptr_t>(replies[i].Data);
            if (dptr >= local_begin && dptr < local_end) {
                replies[i].Data = reinterpret_cast<PVOID>(caller_begin + (dptr - local_begin));
            }
            const auto optr = reinterpret_cast<std::uintptr_t>(replies[i].Options.OptionsData);
            if (optr >= local_begin && optr < local_end) {
                replies[i].Options.OptionsData =
                    reinterpret_cast<PUCHAR>(caller_begin + (optr - local_begin));
            }
        }
        // Wine's synchronous IcmpSendEcho2Ex parses and clears Reserved (+0x0e).
        // Restore it so the caller's subsequent IcmpParseReplies() returns ret cleanly.
        if (ret > 0) {
            replies[0].Reserved = static_cast<USHORT>(ret > 0xFFFFu ? 0xFFFFu : ret);
        } else {
            replies[0].Reserved = 0;
            if (replies[0].Status == 0) {
                replies[0].Status = (last_err != 0) ? last_err : IP_GENERAL_FAILURE;
            }
        }
    } else if (job.is_ipv6 && job.reply_size >= sizeof(ICMPV6_ECHO_REPLY)) {
        auto* reply6 = reinterpret_cast<ICMPV6_ECHO_REPLY*>(local_reply.data());
        if (ret == 0 && reply6->Status == 0) {
            reply6->Status = (last_err != 0) ? last_err : IP_GENERAL_FAILURE;
        }
    }

    if (g_process_detaching.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> slk(job.slot->mtx);
    if (job.slot->closed || g_process_detaching.load(std::memory_order_acquire)) return;

    std::memcpy(job.caller_reply_buf, local_reply.data(), job.reply_size);
    if (job.dup_event.get()) {
        SetEvent(job.dup_event.get());
    } else if (job.dup_thread.get() && job.apc_routine) {
        auto* payload = new IcmpApcPayload{};
        payload->apc_routine = job.apc_routine;
        payload->apc_context = job.apc_context;
        payload->iosb[0] = (ret > 0 || last_err == 0) ? 0u : static_cast<std::uintptr_t>(0xC0000001u);
        payload->iosb[1] = static_cast<std::uintptr_t>(job.reply_size);
        if (QueueUserAPC(icmp_apc_trampoline, job.dup_thread.get(),
                         reinterpret_cast<ULONG_PTR>(payload)) == 0) {
            delete payload;
        }
    }
}

void icmp_worker_loop(IcmpAsyncPool* pool) {
    std::unique_lock<std::mutex> lk(pool->mtx);
    for (;;) {
        if (pool->queue.empty()) {
            if (g_process_detaching.load(std::memory_order_acquire)) break;
            ++pool->idle_workers;
            pool->cv.wait(lk, [&]() {
                return !pool->queue.empty() || g_process_detaching.load(std::memory_order_acquire);
            });
            --pool->idle_workers;
            if (pool->queue.empty()) break;
        }
        IcmpJob job = std::move(pool->queue.front());
        pool->queue.pop_front();
        lk.unlock();
        execute_icmp_job(std::move(job));
        lk.lock();
    }
    --pool->total_workers;
}

bool enqueue_icmp_job(IcmpJob job) {
    if (g_process_detaching.load(std::memory_order_acquire)) {
        SetLastError(ERROR_SHUTDOWN_IN_PROGRESS);
        return false;
    }
    IcmpAsyncPool* pool = get_icmp_pool();
    std::lock_guard<std::mutex> lk(pool->mtx);
    pool->queue.push_back(std::move(job));
    if (pool->idle_workers < pool->queue.size() && pool->total_workers < IcmpAsyncPool::kMaxWorkers) {
        ++pool->total_workers;
        try {
            std::thread(icmp_worker_loop, pool).detach();
        } catch (...) {
            --pool->total_workers;
            pool->queue.pop_back();
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }
    }
    pool->cv.notify_one();
    return true;
}

HANDLE WINAPI hook_IcmpCreateFile() {
    if (!g_orig_IcmpCreateFile) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE h = g_orig_IcmpCreateFile();
    if (h != INVALID_HANDLE_VALUE && h != nullptr) {
        get_or_register_slot(h);
    }
    return h;
}

HANDLE WINAPI hook_Icmp6CreateFile() {
    if (!g_orig_Icmp6CreateFile) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE h = g_orig_Icmp6CreateFile();
    if (h != INVALID_HANDLE_VALUE && h != nullptr) {
        get_or_register_slot(h);
    }
    return h;
}

BOOL WINAPI hook_IcmpCloseHandle(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    std::shared_ptr<IcmpSlot> slot;
    {
        std::lock_guard<std::mutex> lk(g_icmp_slots_mtx);
        auto it = g_icmp_slots.find(h);
        if (it != g_icmp_slots.end()) {
            slot = std::move(it->second);
            g_icmp_slots.erase(it);
        }
    }
    if (slot) {
        {
            std::lock_guard<std::mutex> slk(slot->mtx);
            slot->closed = true;
        }
        // ~IcmpSlot closes real_handle immediately if idle or when the last worker finishes.
        return TRUE;
    }
    return g_orig_IcmpCloseHandle ? g_orig_IcmpCloseHandle(h) : FALSE;
}

bool prepare_async_handles(HANDLE event, PVOID apc_routine, ScopedWinHandle& dup_event,
                           ScopedWinHandle& dup_thread) {
    HANDLE cur_proc = GetCurrentProcess();
    if (event != nullptr) {
        ResetEvent(event);
        HANDLE raw_dup = nullptr;
        if (!DuplicateHandle(cur_proc, event, cur_proc, &raw_dup, 0, FALSE,
                             DUPLICATE_SAME_ACCESS)) {
            return false;
        }
        dup_event.reset(raw_dup);
    } else if (apc_routine != nullptr) {
        HANDLE raw_thr = nullptr;
        if (!DuplicateHandle(cur_proc, GetCurrentThread(), cur_proc, &raw_thr, 0, FALSE,
                             DUPLICATE_SAME_ACCESS)) {
            return false;
        }
        dup_thread.reset(raw_thr);
    }
    return true;
}

void copy_request_payload(LPVOID request_data, WORD request_size, PIP_OPTION_INFORMATION options,
                          IcmpJob& job) {
    job.request_size = request_size;
    if (request_size > 0 && request_data) {
        const auto* b = static_cast<const std::uint8_t*>(request_data);
        job.request_data.assign(b, b + request_size);
    }
    if (options) {
        job.has_options = true;
        job.options = *options;
        if (options->OptionsData && options->OptionsSize > 0) {
            const auto* ob = static_cast<const std::uint8_t*>(options->OptionsData);
            job.options_data.assign(ob, ob + options->OptionsSize);
        } else {
            job.options.OptionsSize = 0;
            job.options.OptionsData = nullptr;
        }
    }
}

DWORD WINAPI hook_IcmpSendEcho2Ex(HANDLE IcmpHandle, HANDLE Event, PVOID ApcRoutine,
                                  PVOID ApcContext, IPAddr SourceAddress, IPAddr DestinationAddress,
                                  LPVOID RequestData, WORD RequestSize,
                                  PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer,
                                  DWORD ReplySize, DWORD Timeout) {
    if (!g_orig_IcmpSendEcho2Ex) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    if (!Event && !ApcRoutine) {
        return g_orig_IcmpSendEcho2Ex(IcmpHandle, nullptr, nullptr, nullptr, SourceAddress,
                                      DestinationAddress, RequestData, RequestSize, RequestOptions,
                                      ReplyBuffer, ReplySize, Timeout);
    }
    if (!IcmpHandle || IcmpHandle == INVALID_HANDLE_VALUE || !ReplyBuffer || ReplySize == 0 ||
        (RequestSize > 0 && !RequestData)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    ScopedWinHandle dup_event;
    ScopedWinHandle dup_thread;
    if (!prepare_async_handles(Event, ApcRoutine, dup_event, dup_thread)) {
        return 0;
    }

    IcmpJob job;
    job.slot = get_or_register_slot(IcmpHandle);
    job.is_ipv6 = false;
    job.dup_event = std::move(dup_event);
    job.dup_thread = std::move(dup_thread);
    job.apc_routine = ApcRoutine;
    job.apc_context = ApcContext;
    job.src4 = SourceAddress;
    job.dst4 = DestinationAddress;
    copy_request_payload(RequestData, RequestSize, RequestOptions, job);
    job.caller_reply_buf = ReplyBuffer;
    job.reply_size = ReplySize;
    job.timeout = Timeout;

    if (!enqueue_icmp_job(std::move(job))) return 0;
    SetLastError(ERROR_IO_PENDING);
    return 0;
}

DWORD WINAPI hook_Icmp6SendEcho2(HANDLE IcmpHandle, HANDLE Event, PVOID ApcRoutine,
                                 PVOID ApcContext, struct sockaddr_in6* SourceAddress,
                                 struct sockaddr_in6* DestinationAddress, LPVOID RequestData,
                                 WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions,
                                 LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) {
    if (!g_orig_Icmp6SendEcho2) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    if (!Event && !ApcRoutine) {
        return g_orig_Icmp6SendEcho2(IcmpHandle, nullptr, nullptr, nullptr, SourceAddress,
                                     DestinationAddress, RequestData, RequestSize, RequestOptions,
                                     ReplyBuffer, ReplySize, Timeout);
    }
    if (!IcmpHandle || IcmpHandle == INVALID_HANDLE_VALUE || !SourceAddress ||
        !DestinationAddress || !ReplyBuffer || ReplySize == 0 ||
        (RequestSize > 0 && !RequestData)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    ScopedWinHandle dup_event;
    ScopedWinHandle dup_thread;
    if (!prepare_async_handles(Event, ApcRoutine, dup_event, dup_thread)) {
        return 0;
    }

    IcmpJob job;
    job.slot = get_or_register_slot(IcmpHandle);
    job.is_ipv6 = true;
    job.dup_event = std::move(dup_event);
    job.dup_thread = std::move(dup_thread);
    job.apc_routine = ApcRoutine;
    job.apc_context = ApcContext;
    job.src6 = *SourceAddress;
    job.dst6 = *DestinationAddress;
    copy_request_payload(RequestData, RequestSize, RequestOptions, job);
    job.caller_reply_buf = ReplyBuffer;
    job.reply_size = ReplySize;
    job.timeout = Timeout;

    if (!enqueue_icmp_job(std::move(job))) return 0;
    SetLastError(ERROR_IO_PENDING);
    return 0;
}

using GetExtendedTcpTable_t = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
GetExtendedTcpTable_t g_orig_GetExtendedTcpTable = nullptr;

// Expose our synthetic Linux-bridged TCP connections to ExitLag's periodic
// zombie sweeper (ExitLag.exe calls GetExtendedTcpTable every ~5s and closes
// any BridgePool whose (dwOwningPid, dwLocalPort) is absent from the table).
DWORD WINAPI hook_GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf,
                                       TCP_TABLE_CLASS TableClass, ULONG Reserved) {
    if (!g_orig_GetExtendedTcpTable) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
    if (!pdwSize ||
        (TableClass != TCP_TABLE_OWNER_PID_CONNECTIONS &&
         TableClass != TCP_TABLE_OWNER_PID_ALL) ||
        (ulAf != AF_INET && ulAf != AF_INET6)) {
        return g_orig_GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved);
    }

    const std::uint8_t want_af = (ulAf == AF_INET) ? np::kAf4 : np::kAf6;
    std::vector<ActiveTcpEntry> extra;
    {
        std::lock_guard<std::mutex> lk(g_active_tcp_mtx);
        extra.reserve(g_active_tcp.size());
        for (const auto& [cid, e] : g_active_tcp) {
            if (e.af == want_af) extra.push_back(e);
        }
    }
    if (extra.empty()) {
        return g_orig_GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved);
    }

    std::vector<std::uint8_t> tmp(4096);
    DWORD orig_sz = 0;
    DWORD orig_rc = ERROR_SUCCESS;
    for (int attempt = 0; attempt < 3; ++attempt) {
        orig_sz = static_cast<DWORD>(tmp.size());
        orig_rc = g_orig_GetExtendedTcpTable(tmp.data(), &orig_sz, bOrder, ulAf, TableClass,
                                             Reserved);
        if (orig_rc != ERROR_INSUFFICIENT_BUFFER) break;
        if (orig_sz <= tmp.size()) orig_sz = static_cast<DWORD>(tmp.size()) * 2u;
        tmp.resize(orig_sz);
    }

    const std::size_t row_size =
        (ulAf == AF_INET) ? sizeof(MIB_TCPROW_OWNER_PID) : sizeof(MIB_TCP6ROW_OWNER_PID);
    constexpr std::size_t header_size = sizeof(DWORD);
    DWORD orig_count = 0;
    if (orig_rc == NO_ERROR && tmp.size() >= header_size) {
        std::memcpy(&orig_count, tmp.data(), sizeof(DWORD));
        const std::size_t max_rows = (tmp.size() - header_size) / row_size;
        if (orig_count > max_rows) orig_count = static_cast<DWORD>(max_rows);
    }

    const std::size_t total_count = static_cast<std::size_t>(orig_count) + extra.size();
    const std::size_t total_bytes = header_size + total_count * row_size;
    if (!pTcpTable || *pdwSize < total_bytes) {
        *pdwSize = static_cast<DWORD>(total_bytes);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    auto* out = static_cast<std::uint8_t*>(pTcpTable);
    const DWORD count32 = static_cast<DWORD>(total_count);
    std::memcpy(out, &count32, sizeof(DWORD));
    if (orig_count > 0) {
        std::memcpy(out + header_size, tmp.data() + header_size, orig_count * row_size);
    }

    std::size_t write_off = header_size + orig_count * row_size;
    for (const auto& e : extra) {
        if (ulAf == AF_INET) {
            MIB_TCPROW_OWNER_PID row{};
            row.dwState = MIB_TCP_STATE_ESTAB;
            std::memcpy(&row.dwLocalAddr, e.local_ip, 4);
            row.dwLocalPort = static_cast<DWORD>(e.local_port_be);
            std::memcpy(&row.dwRemoteAddr, e.remote_ip, 4);
            row.dwRemotePort = static_cast<DWORD>(e.remote_port_be);
            row.dwOwningPid = e.nf_pid;
            std::memcpy(out + write_off, &row, sizeof(row));
            write_off += sizeof(row);
        } else {
            MIB_TCP6ROW_OWNER_PID row6{};
            std::memcpy(row6.ucLocalAddr, e.local_ip, 16);
            row6.dwLocalScopeId = 0;
            row6.dwLocalPort = static_cast<DWORD>(e.local_port_be);
            std::memcpy(row6.ucRemoteAddr, e.remote_ip, 16);
            row6.dwRemoteScopeId = 0;
            row6.dwRemotePort = static_cast<DWORD>(e.remote_port_be);
            row6.dwState = MIB_TCP_STATE_ESTAB;
            row6.dwOwningPid = e.nf_pid;
            std::memcpy(out + write_off, &row6, sizeof(row6));
            write_off += sizeof(row6);
        }
    }
    *pdwSize = static_cast<DWORD>(total_bytes);
    return NO_ERROR;
}

std::once_flag g_compat_log_once;

void install_compat_hooks() {
    HMODULE exe = GetModuleHandleW(nullptr);
    HMODULE libexitlag = GetModuleHandleW(L"libexitlag.dll");

    patch_module_iat(exe, "USER32.dll", "MessageBoxA",
                     reinterpret_cast<void*>(&hook_MessageBoxA),
                     reinterpret_cast<void**>(&g_orig_MessageBoxA));

    int patched = 0;
    HMODULE targets[2] = {exe, libexitlag};
    for (HMODULE mod : targets) {
        if (!mod) continue;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "IcmpCreateFile",
                                    reinterpret_cast<void*>(&hook_IcmpCreateFile),
                                    reinterpret_cast<void**>(&g_orig_IcmpCreateFile))
                       ? 1
                       : 0;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "Icmp6CreateFile",
                                    reinterpret_cast<void*>(&hook_Icmp6CreateFile),
                                    reinterpret_cast<void**>(&g_orig_Icmp6CreateFile))
                       ? 1
                       : 0;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "IcmpCloseHandle",
                                    reinterpret_cast<void*>(&hook_IcmpCloseHandle),
                                    reinterpret_cast<void**>(&g_orig_IcmpCloseHandle))
                       ? 1
                       : 0;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "IcmpSendEcho2Ex",
                                    reinterpret_cast<void*>(&hook_IcmpSendEcho2Ex),
                                    reinterpret_cast<void**>(&g_orig_IcmpSendEcho2Ex))
                       ? 1
                       : 0;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "Icmp6SendEcho2",
                                    reinterpret_cast<void*>(&hook_Icmp6SendEcho2),
                                    reinterpret_cast<void**>(&g_orig_Icmp6SendEcho2))
                       ? 1
                       : 0;
        patched += patch_module_iat(mod, "IPHLPAPI.DLL", "GetExtendedTcpTable",
                                    reinterpret_cast<void*>(&hook_GetExtendedTcpTable),
                                    reinterpret_cast<void**>(&g_orig_GetExtendedTcpTable))
                       ? 1
                       : 0;
    }

    // Fallback: ensure originals resolve from iphlpapi.dll even if a target module
    // only imports a subset of the hooked functions.
    if (HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll")) {
        if (!g_orig_IcmpCreateFile) {
            g_orig_IcmpCreateFile =
                reinterpret_cast<IcmpCreateFile_t>(GetProcAddress(iphlp, "IcmpCreateFile"));
        }
        if (!g_orig_Icmp6CreateFile) {
            g_orig_Icmp6CreateFile =
                reinterpret_cast<Icmp6CreateFile_t>(GetProcAddress(iphlp, "Icmp6CreateFile"));
        }
        if (!g_orig_IcmpCloseHandle) {
            g_orig_IcmpCloseHandle =
                reinterpret_cast<IcmpCloseHandle_t>(GetProcAddress(iphlp, "IcmpCloseHandle"));
        }
        if (!g_orig_IcmpSendEcho2Ex) {
            g_orig_IcmpSendEcho2Ex =
                reinterpret_cast<IcmpSendEcho2Ex_t>(GetProcAddress(iphlp, "IcmpSendEcho2Ex"));
        }
        if (!g_orig_Icmp6SendEcho2) {
            g_orig_Icmp6SendEcho2 =
                reinterpret_cast<Icmp6SendEcho2_t>(GetProcAddress(iphlp, "Icmp6SendEcho2"));
        }
        if (!g_orig_GetExtendedTcpTable) {
            g_orig_GetExtendedTcpTable = reinterpret_cast<GetExtendedTcpTable_t>(
                GetProcAddress(iphlp, "GetExtendedTcpTable"));
        }
    }

    if (patched > 0) {
        std::call_once(g_compat_log_once, [patched]() {
            log_msg("installed IPHLPAPI compat hooks (patched=%d)", patched);
        });
    }
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        install_compat_hooks();
    } else if (reason == DLL_PROCESS_DETACH) {
        g_process_detaching.store(true, std::memory_order_release);
        g_running.store(false);
        if (IcmpAsyncPool* pool = get_icmp_pool()) {
            pool->cv.notify_all();
        }
    }
    return TRUE;
}
