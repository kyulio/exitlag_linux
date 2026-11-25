// Native Linux transparent TCP/UDP redirector (epoll + TPROXY + SO_MARK + proc lookup)
// bridging ExitLag.exe's drop-in nfapi.dll shim over loopback IPC (127.0.0.1:19850).
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet_diag.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unordered_set>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../src/nf_bridge_proto.hpp"

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

namespace np = shim::nf_proto;

namespace {

struct Config {
    std::string listen_tcp = "127.0.0.1:12345";
    std::string listen_udp = "127.0.0.1:12345";
    std::string listen_tcp6;
    std::string listen_udp6;
    std::string ipc = "127.0.0.1:19850";
    std::string proc_aliases_path;
    std::uint32_t mark = 0xff;
    int udp_idle_sec = 60;
    int nf_timeout_ms = 3000;
    bool verbose = false;
    // Native-direct fast path (see on_exitlag_decision): eBPF object + cgroup to attach to.
    std::string bpf_obj;
    std::string bpf_cgroup;
    // ExitLag client.log (decision lines) and bypass re-probe interval.
    std::string exitlag_log;
    int reprobe_sec = 15;
    // Native Linux process names that must never be bypassed.
    std::string native_tunnel_path;
};

struct AddrPort {
    std::uint8_t af = 0;  // np::kAf4 (4) or np::kAf6 (6)
    std::array<std::uint8_t, 16> ip{};
    std::uint16_t port_be = 0;
};

bool parse_ip_port(const std::string& spec, AddrPort& out) {
    if (spec.empty()) return false;
    std::string ip_str;
    std::string port_str;
    if (spec.front() == '[') {
        auto rb = spec.find("]:");
        if (rb == std::string::npos) return false;
        ip_str = spec.substr(1, rb - 1);
        port_str = spec.substr(rb + 2);
    } else {
        auto c = spec.rfind(':');
        if (c == std::string::npos || c == 0 || c + 1 >= spec.size()) return false;
        ip_str = spec.substr(0, c);
        port_str = spec.substr(c + 1);
    }
    char* end = nullptr;
    unsigned long p = std::strtoul(port_str.c_str(), &end, 10);
    if (!end || *end != '\0' || p == 0 || p > 65535) return false;
    out.ip.fill(0);
    out.port_be = htons(static_cast<std::uint16_t>(p));
    in_addr v4{};
    if (inet_pton(AF_INET, ip_str.c_str(), &v4) == 1) {
        out.af = np::kAf4;
        std::memcpy(out.ip.data(), &v4, 4);
        return true;
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, ip_str.c_str(), &v6) == 1) {
        out.af = np::kAf6;
        std::memcpy(out.ip.data(), &v6, 16);
        return true;
    }
    return false;
}

socklen_t to_sockaddr(const AddrPort& ap, sockaddr_storage& ss) {
    std::memset(&ss, 0, sizeof(ss));
    if (ap.af == np::kAf4) {
        auto* s4 = reinterpret_cast<sockaddr_in*>(&ss);
        s4->sin_family = AF_INET;
        s4->sin_port = ap.port_be;
        std::memcpy(&s4->sin_addr, ap.ip.data(), 4);
        return sizeof(sockaddr_in);
    }
    auto* s6 = reinterpret_cast<sockaddr_in6*>(&ss);
    s6->sin6_family = AF_INET6;
    s6->sin6_port = ap.port_be;
    std::memcpy(&s6->sin6_addr, ap.ip.data(), 16);
    return sizeof(sockaddr_in6);
}

bool from_sockaddr(const sockaddr_storage& ss, AddrPort& ap) {
    ap.ip.fill(0);
    if (ss.ss_family == AF_INET) {
        const auto* s4 = reinterpret_cast<const sockaddr_in*>(&ss);
        ap.af = np::kAf4;
        ap.port_be = s4->sin_port;
        std::memcpy(ap.ip.data(), &s4->sin_addr, 4);
        return true;
    }
    if (ss.ss_family == AF_INET6) {
        const auto* s6 = reinterpret_cast<const sockaddr_in6*>(&ss);
        ap.af = np::kAf6;
        ap.port_be = s6->sin6_port;
        std::memcpy(ap.ip.data(), &s6->sin6_addr, 16);
        return true;
    }
    return false;
}

std::string format_ap(const AddrPort& ap) {
    char buf[INET6_ADDRSTRLEN]{};
    if (ap.af == np::kAf4) {
        inet_ntop(AF_INET, ap.ip.data(), buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(ntohs(ap.port_be));
    }
    inet_ntop(AF_INET6, ap.ip.data(), buf, sizeof(buf));
    return "[" + std::string(buf) + "]:" + std::to_string(ntohs(ap.port_be));
}

bool same_ap(const AddrPort& a, const AddrPort& b) {
    if (a.af != b.af || a.port_be != b.port_be) return false;
    const std::size_t n = (a.af == np::kAf4) ? 4 : 16;
    return std::memcmp(a.ip.data(), b.ip.data(), n) == 0;
}

bool set_sockopt_int(int fd, int level, int optname, int val) {
    return setsockopt(fd, level, optname, &val, sizeof(val)) == 0;
}

void try_set_mark(int fd, std::uint32_t mark) {
    if (mark == 0) return;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::fprintf(stderr, "warn: setsockopt(SO_MARK=%u) failed: %s (continuing)\n",
                         mark, std::strerror(errno));
        }
    }
}

// ---------------------------------------------------------------------------
// Process lookup via NETLINK_SOCK_DIAG + /proc/<pid>/fd fallback to /proc/net
// ---------------------------------------------------------------------------
Config g_cfg;
int g_ep = -1;
bool g_running = true;
int g_nl_fd = -1;
std::uint32_t g_nl_seq = 1;
std::unordered_map<std::string, std::string> g_proc_aliases;

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string path_basename(const std::string& p) {
    auto pos = p.find_last_of("/\\");
    return (pos == std::string::npos) ? p : p.substr(pos + 1);
}

bool ends_with_ci(const std::string& s, const char* suffix) {
    const std::size_t slen = std::strlen(suffix);
    if (s.size() < slen) return false;
    return to_lower_ascii(s.substr(s.size() - slen)) == suffix;
}

void load_proc_aliases(const std::string& path) {
    if (path.empty()) return;
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "warn: cannot open --proc-aliases %s\n", path.c_str());
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = to_lower_ascii(line.substr(0, eq));
        std::string v = line.substr(eq + 1);
        auto trim = [](std::string& s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
        };
        trim(k);
        trim(v);
        if (!k.empty() && !v.empty()) {
            g_proc_aliases[k] = v;
        }
    }
}

bool is_zero_ip(const std::uint8_t ip[16], std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (ip[i] != 0) return false;
    }
    return true;
}

bool matches_diag_addr(int fam, const std::uint32_t diag_addr[4], const AddrPort& ap,
                       bool allow_wildcard) {
    const auto* b = reinterpret_cast<const std::uint8_t*>(diag_addr);
    if (fam == AF_INET) {
        if (ap.af == np::kAf4 && std::memcmp(b, ap.ip.data(), 4) == 0) return true;
        if (allow_wildcard && is_zero_ip(b, 4)) return true;
        return false;
    }
    if (fam == AF_INET6) {
        if (ap.af == np::kAf6 && std::memcmp(b, ap.ip.data(), 16) == 0) return true;
        if (ap.af == np::kAf4) {
            static const std::uint8_t kV4MappedPrefix[12] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
            if (std::memcmp(b, kV4MappedPrefix, 12) == 0 &&
                std::memcmp(b + 12, ap.ip.data(), 4) == 0) {
                return true;
            }
        }
        if (allow_wildcard && is_zero_ip(b, 16)) return true;
    }
    return false;
}

std::uint64_t query_diag_inode_family(int fam, int proto, const AddrPort& src) {
    if (g_nl_fd < 0) return 0;

    struct {
        nlmsghdr nlh;
        inet_diag_req_v2 req;
    } req{};

    const std::uint32_t seq = g_nl_seq++;
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = seq;
    req.req.sdiag_family = static_cast<std::uint8_t>(fam);
    req.req.sdiag_protocol = static_cast<std::uint8_t>(proto);
    req.req.idiag_states = (proto == IPPROTO_TCP) ? 0xFFF : ((1u << 1) | (1u << 7));
    req.req.id.idiag_sport = src.port_be;

    if (send(g_nl_fd, &req, sizeof(req), 0) < 0) {
        return 0;
    }

    std::uint8_t buf[16384];
    std::uint64_t exact_inode = 0;
    std::uint64_t wildcard_inode = 0;
    const bool allow_wildcard = (proto == IPPROTO_UDP);

    for (;;) {
        ssize_t n = recv(g_nl_fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;

        for (auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
             NLMSG_OK(nlh, static_cast<unsigned int>(n));
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != seq) continue;
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                return exact_inode ? exact_inode : wildcard_inode;
            }
            if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
                nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(inet_diag_msg))) {
                const auto* m = static_cast<const inet_diag_msg*>(NLMSG_DATA(nlh));
                if (m->id.idiag_sport != src.port_be || m->idiag_inode == 0) continue;
                if (matches_diag_addr(fam, m->id.idiag_src, src, false)) {
                    exact_inode = m->idiag_inode;
                } else if (allow_wildcard && wildcard_inode == 0 &&
                           matches_diag_addr(fam, m->id.idiag_src, src, true)) {
                    wildcard_inode = m->idiag_inode;
                }
            }
        }
    }
    return exact_inode ? exact_inode : wildcard_inode;
}

std::uint64_t find_inode_proc_net(const char* path, int fam, const AddrPort& src,
                                  bool allow_wildcard) {
    std::ifstream in(path);
    if (!in) return 0;
    std::string line;
    std::getline(in, line);  // header
    const std::uint16_t want_port = ntohs(src.port_be);
    std::uint64_t wildcard_inode = 0;

    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string sl, local, rem, st, txrx, trtm, retrnsmt, uid, timeout, inode_s;
        if (!(iss >> sl >> local >> rem >> st >> txrx >> trtm >> retrnsmt >> uid >> timeout >> inode_s)) {
            continue;
        }
        auto colon = local.find(':');
        if (colon == std::string::npos) continue;
        unsigned long lport = std::strtoul(local.c_str() + colon + 1, nullptr, 16);
        if (lport != want_port) continue;
        std::uint64_t ino = std::strtoull(inode_s.c_str(), nullptr, 10);
        if (ino == 0) continue;

        std::string hex_ip = local.substr(0, colon);
        std::uint32_t words[4]{};
        if (fam == AF_INET && hex_ip.size() == 8) {
            words[0] = static_cast<std::uint32_t>(std::strtoul(hex_ip.c_str(), nullptr, 16));
        } else if (fam == AF_INET6 && hex_ip.size() == 32) {
            for (int w = 0; w < 4; ++w) {
                words[w] = static_cast<std::uint32_t>(
                    std::strtoul(hex_ip.substr(static_cast<std::size_t>(w) * 8, 8).c_str(), nullptr, 16));
            }
        } else {
            continue;
        }
        if (matches_diag_addr(fam, words, src, false)) return ino;
        if (allow_wildcard && wildcard_inode == 0 && matches_diag_addr(fam, words, src, true)) {
            wildcard_inode = ino;
        }
    }
    return wildcard_inode;
}

std::uint64_t find_socket_inode(int proto, const AddrPort& src) {
    std::uint64_t ino = 0;
    if (src.af == np::kAf4) {
        ino = query_diag_inode_family(AF_INET, proto, src);
        if (ino != 0) return ino;
        ino = query_diag_inode_family(AF_INET6, proto, src);
        if (ino != 0) return ino;
        const bool wc = (proto == IPPROTO_UDP);
        ino = find_inode_proc_net(proto == IPPROTO_TCP ? "/proc/net/tcp" : "/proc/net/udp",
                                  AF_INET, src, wc);
        if (ino != 0) return ino;
        return find_inode_proc_net(proto == IPPROTO_TCP ? "/proc/net/tcp6" : "/proc/net/udp6",
                                   AF_INET6, src, wc);
    }
    ino = query_diag_inode_family(AF_INET6, proto, src);
    if (ino != 0) return ino;
    return find_inode_proc_net(proto == IPPROTO_TCP ? "/proc/net/tcp6" : "/proc/net/udp6",
                               AF_INET6, src, proto == IPPROTO_UDP);
}

std::vector<pid_t> find_pids_by_inode(std::uint64_t inode) {
    std::vector<pid_t> pids;
    if (inode == 0) return pids;
    char target[64];
    const int tlen = std::snprintf(target, sizeof(target), "socket:[%llu]",
                                   static_cast<unsigned long long>(inode));
    if (tlen <= 0) return pids;

    DIR* proc = opendir("/proc");
    if (!proc) return pids;
    const pid_t self_pid = getpid();

    while (dirent* de = readdir(proc)) {
        if (!std::isdigit(static_cast<unsigned char>(de->d_name[0]))) continue;
        char* end = nullptr;
        long pval = std::strtol(de->d_name, &end, 10);
        if (!end || *end != '\0' || pval <= 0 || pval == self_pid) continue;

        char fddir_path[64];
        std::snprintf(fddir_path, sizeof(fddir_path), "/proc/%ld/fd", pval);
        DIR* fdd = opendir(fddir_path);
        if (!fdd) continue;
        int dfd = dirfd(fdd);
        char linkbuf[128];
        bool matched = false;
        while (dirent* fe = readdir(fdd)) {
            if (fe->d_name[0] == '.') continue;
            ssize_t rl = readlinkat(dfd, fe->d_name, linkbuf, sizeof(linkbuf) - 1);
            if (rl == tlen && std::memcmp(linkbuf, target, static_cast<std::size_t>(tlen)) == 0) {
                matched = true;
                break;
            }
        }
        closedir(fdd);
        if (matched) pids.push_back(static_cast<pid_t>(pval));
    }
    closedir(proc);
    return pids;
}

// Wine/Proton runtime wrappers/servers must never be treated as native Linux apps
// or added to direct_pids (eBPF SO_MARK bypass): wineserver calls socket() and
// connect() on behalf of every Windows game process in its prefix.
bool is_wine_runtime_binary(const std::string& lower_base) {
    return lower_base == "wine" || lower_base == "wine64" ||
           lower_base == "wine-preloader" || lower_base == "wine64-preloader" ||
           lower_base == "wineserver" || lower_base == "wine-server" ||
           lower_base == "proton" || lower_base == "pressure-vessel" ||
           lower_base == "pv-adverb" || lower_base == "srt-bwrap" ||
           lower_base == "reaper";
}

bool is_wine_helper_exe(const std::string& lower_base) {
    return lower_base == "wine.exe" || lower_base == "wine64.exe" ||
           lower_base == "wineserver.exe" || lower_base == "start.exe" ||
           lower_base == "conhost.exe" || lower_base == "services.exe" ||
           lower_base == "svchost.exe" || lower_base == "explorer.exe" ||
           lower_base == "cmd.exe" || lower_base == "plugplay.exe" ||
           lower_base == "rpcss.exe";
}

bool is_wine_background_exe(const std::string& lower_base, const std::string& full_arg_lower) {
    if (is_wine_helper_exe(lower_base)) return true;
    if (lower_base == "winedevice.exe" || lower_base == "wineboot.exe" ||
        lower_base == "tabtip.exe" || lower_base == "winemenubuilder.exe" ||
        lower_base == "winebrowser.exe" || lower_base == "rundll32.exe" ||
        lower_base == "mscorsvw.exe" || lower_base == "msiexec.exe" ||
        lower_base == "csrss.exe" || lower_base == "schtasks.exe" ||
        lower_base == "taskhostw.exe" || lower_base == "dllhost.exe" ||
        lower_base == "spoolsv.exe") {
        return true;
    }
    if (lower_base == "steam.exe" &&
        (full_arg_lower.find("windows\\system32\\steam.exe") != std::string::npos ||
         full_arg_lower.find("windows/system32/steam.exe") != std::string::npos)) {
        return true;
    }
    return false;
}

bool looks_like_helper_app(const std::string& lower_base) {
    return lower_base.find("webview") != std::string::npos ||
           lower_base.find("crashpad") != std::string::npos ||
           lower_base.find("handler") != std::string::npos ||
           lower_base.find("helper") != std::string::npos ||
           lower_base.find("cef") != std::string::npos;
}

bool read_proc_exe_or_comm_lower(pid_t pid, std::string& out_lower) {
    out_lower.clear();
    if (pid <= 0) return false;
    char exe_path[64];
    std::snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    char linkbuf[1024]{};
    ssize_t n = readlink(exe_path, linkbuf, sizeof(linkbuf) - 1);
    if (n > 0) {
        out_lower = to_lower_ascii(path_basename(std::string(linkbuf, static_cast<std::size_t>(n))));
        return !out_lower.empty();
    }
    char comm_path[64];
    std::snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    std::ifstream in(comm_path);
    std::string line;
    if (in && std::getline(in, line) && !line.empty()) {
        out_lower = to_lower_ascii(line);
        return true;
    }
    return false;
}

bool is_wineserver_pid(pid_t pid) {
    std::string lb;
    if (!read_proc_exe_or_comm_lower(pid, lb)) return false;
    return lb == "wineserver" || lb == "wineserver.exe" || lb == "wine-server";
}

unsigned long long proc_starttime(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    std::ifstream in(path);
    std::string s;
    if (!in || !std::getline(in, s)) return 0;
    auto rp = s.rfind(')');
    if (rp == std::string::npos) return 0;
    std::istringstream rest(s.substr(rp + 2));
    std::string tok;
    // fields after "(comm)": state is field 3; starttime is field 22 -> 20th token here
    for (int i = 0; i < 20 && (rest >> tok); ++i) {}
    return std::strtoull(tok.c_str(), nullptr, 10);
}

bool read_proc_uid(pid_t pid, uid_t& out_uid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st{};
    if (stat(path, &st) != 0) return false;
    out_uid = st.st_uid;
    return true;
}

pid_t read_proc_ppid(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/status", pid);
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("PPid:", 0) == 0) {
            long v = std::strtol(line.c_str() + 5, nullptr, 10);
            return v > 0 ? static_cast<pid_t>(v) : 0;
        }
    }
    return 0;
}

std::string read_proc_cgroup(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) return line;
    }
    return {};
}

std::string normalize_dir_path(std::string p) {
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

struct ProcEnvInfo {
    std::string wineprefix;
    std::string compat_data;
};

ProcEnvInfo read_proc_env_info(pid_t pid) {
    ProcEnvInfo info;
    std::string home;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return info;

    std::string raw;
    char buf[8192];
    for (int rounds = 0; rounds < 16; ++rounds) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        raw.append(buf, static_cast<std::size_t>(n));
    }
    close(fd);

    std::size_t pos = 0;
    while (pos < raw.size()) {
        std::size_t nul = raw.find('\0', pos);
        std::size_t end = (nul == std::string::npos) ? raw.size() : nul;
        const std::size_t len = end - pos;
        if (len > 11 && raw.compare(pos, 11, "WINEPREFIX=") == 0) {
            info.wineprefix = normalize_dir_path(raw.substr(pos + 11, len - 11));
        } else if (len > 23 && raw.compare(pos, 23, "STEAM_COMPAT_DATA_PATH=") == 0) {
            info.compat_data = normalize_dir_path(raw.substr(pos + 23, len - 23));
        } else if (len > 5 && raw.compare(pos, 5, "HOME=") == 0) {
            home = normalize_dir_path(raw.substr(pos + 5, len - 5));
        }
        if (nul == std::string::npos) break;
        pos = nul + 1;
    }
    if (info.wineprefix.empty() && !home.empty()) {
        info.wineprefix = home + "/.wine";
    }
    return info;
}

bool parse_wineserver_cwd_dev_ino(pid_t pid, dev_t& out_dev, ino_t& out_ino) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    char linkbuf[1024]{};
    ssize_t n = readlink(path, linkbuf, sizeof(linkbuf) - 1);
    if (n <= 0) return false;
    std::string base = path_basename(std::string(linkbuf, static_cast<std::size_t>(n)));
    if (base.rfind("server-", 0) != 0) return false;
    auto dash = base.find('-', 7);
    if (dash == std::string::npos || dash == 7 || dash + 1 >= base.size()) return false;
    char* end1 = nullptr;
    unsigned long long dev_v = std::strtoull(base.c_str() + 7, &end1, 16);
    if (end1 != base.c_str() + dash) return false;
    char* end2 = nullptr;
    unsigned long long ino_v = std::strtoull(base.c_str() + dash + 1, &end2, 16);
    if (!end2 || *end2 != '\0') return false;
    out_dev = static_cast<dev_t>(dev_v);
    out_ino = static_cast<ino_t>(ino_v);
    return true;
}

bool extract_windows_exe_from_cmdline(pid_t pid, std::string& out_exe,
                                      std::string* out_fallback = nullptr) {
    out_exe.clear();
    if (out_fallback) out_fallback->clear();
    char cmd_path[64];
    std::snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);
    int fd = open(cmd_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return false;

    std::size_t pos = 0;
    while (pos < static_cast<std::size_t>(n)) {
        const char* s = buf + pos;
        std::size_t slen = strnlen(s, static_cast<std::size_t>(n) - pos);
        std::string arg(s, slen);
        pos += slen + 1;
        if (arg.empty() || arg.front() == '-') continue;
        if (arg.find('\n') != std::string::npos || arg.find('\r') != std::string::npos) continue;
        std::string base = path_basename(arg);
        if (ends_with_ci(base, ".exe")) {
            std::string lb = to_lower_ascii(base);
            if (!is_wine_background_exe(lb, to_lower_ascii(arg))) {
                out_exe = base;
                return true;
            }
            if (out_fallback && out_fallback->empty()) *out_fallback = base;
        }
    }
    return false;
}

// out_native: true when the process is a native Linux binary (no Windows .exe in its
// cmdline, not a wine/proton runtime) and no --proc-aliases entry mapped it to a game name.
std::string resolve_proc_name_for_pid(pid_t pid, bool* out_native = nullptr) {
    if (out_native) *out_native = false;
    if (pid <= 0) return "C:\\Linux\\unknown.exe";
    bool from_windows_exe = false;

    std::string candidate;
    std::string fallback_exe;

    // 1. Inspect /proc/<pid>/cmdline (pick real Windows .exe under Wine/Proton if present)
    if (extract_windows_exe_from_cmdline(pid, candidate, &fallback_exe)) {
        from_windows_exe = true;
    }

    // 2. Fall back to native Linux binary name via /proc/<pid>/exe or /proc/<pid>/comm
    if (candidate.empty()) {
        char exe_path[64];
        std::snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        char linkbuf[1024]{};
        ssize_t n = readlink(exe_path, linkbuf, sizeof(linkbuf) - 1);
        if (n > 0) {
            std::string base = path_basename(std::string(linkbuf, static_cast<std::size_t>(n)));
            std::string lb = to_lower_ascii(base);
            if (!is_wine_runtime_binary(lb)) {
                candidate = base;
            } else {
                from_windows_exe = true;  // Wine/Proton runtime: treat as Windows process
            }
        }
    }
    if (candidate.empty() && !fallback_exe.empty()) {
        candidate = fallback_exe;
        from_windows_exe = true;
    }
    if (candidate.empty()) {
        char comm_path[64];
        std::snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        std::ifstream in(comm_path);
        std::string line;
        if (in && std::getline(in, line) && !line.empty()) {
            std::string lb = to_lower_ascii(line);
            if (is_wine_runtime_binary(lb)) from_windows_exe = true;
            candidate = line;
        }
    }
    if (candidate.empty()) candidate = "unknown";

    // Apply alias table (check with and without .exe)
    std::string lc = to_lower_ascii(candidate);
    bool aliased = false;
    if (auto it = g_proc_aliases.find(lc); it != g_proc_aliases.end()) {
        candidate = it->second;
        aliased = true;
    } else if (ends_with_ci(lc, ".exe")) {
        std::string stem = lc.substr(0, lc.size() - 4);
        if (auto it2 = g_proc_aliases.find(stem); it2 != g_proc_aliases.end()) {
            candidate = it2->second;
            aliased = true;
        }
    }
    if (out_native) *out_native = !from_windows_exe && !aliased;

    // Native Linux binaries whose Windows .exe name differs, so ExitLag's app
    // matching (Chrome, Vivaldi, ...) recognizes them. Does not change "native".
    if (!aliased && !from_windows_exe) {
        static const std::unordered_map<std::string, std::string> kNativeRename = {
            {"chromium", "chrome.exe"},        {"chromium-browser", "chrome.exe"},
            {"google-chrome", "chrome.exe"},   {"google-chrome-stable", "chrome.exe"},
            {"firefox-bin", "firefox.exe"},    {"firefox-esr", "firefox.exe"},
            {"vivaldi-bin", "vivaldi.exe"},    {"brave-browser", "brave.exe"},
            {"microsoft-edge", "msedge.exe"},  {"steamwebhelper.sh", "steamwebhelper.exe"},
        };
        if (auto it = kNativeRename.find(to_lower_ascii(candidate)); it != kNativeRename.end()) {
            candidate = it->second;
        }
    }

    if (!ends_with_ci(candidate, ".exe")) {
        candidate += ".exe";
    }
    return "C:\\Linux\\" + candidate;
}

// ---------------------------------------------------------------------------
// Native-direct fast path (Windows-like per-app routing for native Linux apps)
//
// Every connection is first asked to ExitLag over IPC, exactly like NFSDK on
// Windows. ExitLag logs each decision to client.log as
//   [TCP] a -> b [firefox.exe (pid 1073745033) / <no-app>] -> pass
// with the app it matched (or <no-app>). We tail that log:
//  * native Linux process + "<no-app>" + pass  -> BYPASS: its PID goes into the
//    eBPF map, so its new sockets get the bypass mark and skip TPROXY in-kernel.
//  * any process matched to an app (Steam, YouTube, Discord...) -> PINNED: never
//    bypassed, ExitLag keeps deciding per connection.
//  * BYPASS entries are re-asked every --reprobe seconds, so enabling an app in
//    ExitLag takes effect within that time without restarting the app.
// Wine/Proton processes (games) are never bypassed.
// ---------------------------------------------------------------------------
std::unordered_set<std::string> g_native_tunnel;  // lowercase, no ".exe"
time_t g_native_tunnel_mtime = 0;
bpf_object* g_bpf_obj = nullptr;
bpf_link* g_bpf_link = nullptr;
int g_direct_map_fd = -1;

struct PidState {
    unsigned long long starttime = 0;
    bool bypass = false;    // false => pinned to ExitLag
    std::string key;        // normalize_proc_key(name)
    std::string proc_name;  // C:\Linux\...
    std::string app;        // last matched app (pinned)
    std::chrono::steady_clock::time_point since{};
};
std::unordered_map<pid_t, PidState> g_pid_state;

struct ProcCandidate {
    pid_t pid = 0;
    std::string name;
};

struct WineserverPref {
    unsigned long long ws_starttime = 0;
    pid_t cand_pid = 0;
    std::string proc_name;
    std::chrono::steady_clock::time_point since{};
};
std::unordered_map<pid_t, WineserverPref> g_wineserver_preferred;

// PIDs that just became BYPASS; on_timer_tick also switches their already-open
// UDP flows to direct (otherwise e.g. a Discord voice socket opened before the
// decision keeps round-tripping every packet through ExitLag).
std::vector<pid_t> g_new_bypass;

std::string normalize_proc_key(const std::string& name) {
    std::string s = name;
    if (auto p = s.find_last_of("\\/"); p != std::string::npos) s = s.substr(p + 1);
    s = to_lower_ascii(s);
    if (ends_with_ci(s, ".exe")) s.resize(s.size() - 4);
    return s;
}

void resolve_socket_candidates(int proto, const AddrPort& src,
                               std::vector<ProcCandidate>& out_cands,
                               pid_t& out_wineserver_pid) {
    out_cands.clear();
    out_wineserver_pid = 0;

    const std::uint64_t ino = find_socket_inode(proto, src);
    const std::vector<pid_t> pids = find_pids_by_inode(ino);

    std::vector<pid_t> non_ws_pids;
    std::vector<pid_t> ws_pids;
    for (pid_t p : pids) {
        if (is_wineserver_pid(p)) {
            ws_pids.push_back(p);
        } else {
            non_ws_pids.push_back(p);
        }
    }

    auto add_unique = [&](pid_t pid, const std::string& name, std::size_t cap) {
        if (out_cands.size() >= cap || name.empty()) return;
        std::string lk = to_lower_ascii(name);
        for (const auto& existing : out_cands) {
            if (to_lower_ascii(existing.name) == lk) return;
        }
        out_cands.push_back(ProcCandidate{pid, name});
    };

    // 1. Direct owner PID(s) present (native app, or Wine/Proton process already holding fd):
    // prefer any non-background Windows .exe PID first, then remaining owners.
    if (!non_ws_pids.empty()) {
        std::vector<ProcCandidate> deferred;
        for (pid_t p : non_ws_pids) {
            std::string dummy;
            std::string name = resolve_proc_name_for_pid(p);
            if (extract_windows_exe_from_cmdline(p, dummy)) {
                add_unique(p, name, 6);
            } else {
                deferred.push_back(ProcCandidate{p, std::move(name)});
            }
        }
        for (const auto& dc : deferred) {
            add_unique(dc.pid, dc.name, 6);
        }
        return;
    }

    if (ws_pids.empty()) {
        out_cands.push_back(ProcCandidate{0, "C:\\Linux\\unknown.exe"});
        return;
    }

    // 2. Socket is currently held only by wineserver: attribute it to the real
    // Windows game .exe(s) running inside the same Wine/Proton prefix.
    const pid_t ws_pid = ws_pids.front();
    out_wineserver_pid = ws_pid;

    uid_t ws_uid = 0;
    const bool has_ws_uid = read_proc_uid(ws_pid, ws_uid);
    const ProcEnvInfo ws_env = read_proc_env_info(ws_pid);
    dev_t ws_dev = 0;
    ino_t ws_ino = 0;
    const bool ws_has_dev_ino = parse_wineserver_cwd_dev_ino(ws_pid, ws_dev, ws_ino);
    const std::string ws_cgroup = read_proc_cgroup(ws_pid);
    const unsigned long long ws_st = proc_starttime(ws_pid);

    struct PrefixMatch {
        pid_t pid = 0;
        std::string name;
        int tier = 0;
        unsigned long long starttime = 0;
    };
    std::vector<PrefixMatch> prefix_matches;

    if (DIR* proc = opendir("/proc")) {
        const pid_t self_pid = getpid();
        while (dirent* de = readdir(proc)) {
            if (!std::isdigit(static_cast<unsigned char>(de->d_name[0]))) continue;
            char* end = nullptr;
            long pval = std::strtol(de->d_name, &end, 10);
            if (!end || *end != '\0' || pval <= 0 || pval == self_pid || pval == ws_pid) continue;
            const pid_t p = static_cast<pid_t>(pval);

            if (has_ws_uid) {
                uid_t p_uid = 0;
                if (!read_proc_uid(p, p_uid) || p_uid != ws_uid) continue;
            }

            std::string win_exe;
            if (!extract_windows_exe_from_cmdline(p, win_exe)) continue;

            const ProcEnvInfo p_env = read_proc_env_info(p);
            bool same_prefix = false;
            if (!ws_env.wineprefix.empty() && !p_env.wineprefix.empty() &&
                p_env.wineprefix == ws_env.wineprefix) {
                same_prefix = true;
            } else if (!ws_env.compat_data.empty() && !p_env.compat_data.empty() &&
                       p_env.compat_data == ws_env.compat_data) {
                same_prefix = true;
            } else if (ws_has_dev_ino) {
                if (!p_env.wineprefix.empty()) {
                    struct stat pst{};
                    if (stat(p_env.wineprefix.c_str(), &pst) == 0 &&
                        pst.st_dev == ws_dev && pst.st_ino == ws_ino) {
                        same_prefix = true;
                    }
                }
                if (!same_prefix && !p_env.compat_data.empty()) {
                    const std::string pfx = p_env.compat_data + "/pfx";
                    struct stat pst{};
                    if (stat(pfx.c_str(), &pst) == 0 &&
                        pst.st_dev == ws_dev && pst.st_ino == ws_ino) {
                        same_prefix = true;
                    }
                }
            }
            if (!same_prefix) continue;

            const std::string full_name = resolve_proc_name_for_pid(p);
            int tier = looks_like_helper_app(to_lower_ascii(win_exe)) ? 0 : 1;
            if (auto pit = g_pid_state.find(p); pit != g_pid_state.end() && !pit->second.bypass) {
                tier = 2;
            }
            prefix_matches.push_back(PrefixMatch{p, full_name, tier, proc_starttime(p)});
        }
        closedir(proc);
    }

    std::sort(prefix_matches.begin(), prefix_matches.end(),
              [](const PrefixMatch& a, const PrefixMatch& b) {
                  if (a.tier != b.tier) return a.tier > b.tier;
                  if (a.starttime != b.starttime) return a.starttime > b.starttime;
                  return a.pid > b.pid;
              });

    // Priority 1: cached REDIRECT preference for this live wineserver instance.
    const auto now = std::chrono::steady_clock::now();
    if (auto pref_it = g_wineserver_preferred.find(ws_pid);
        pref_it != g_wineserver_preferred.end() && ws_st != 0 &&
        pref_it->second.ws_starttime == ws_st) {
        const std::string pref_lower = to_lower_ascii(pref_it->second.proc_name);
        pid_t matched_pid = 0;
        for (const auto& pm : prefix_matches) {
            if (to_lower_ascii(pm.name) == pref_lower) {
                matched_pid = pm.pid;
                break;
            }
        }
        if (matched_pid > 0) {
            add_unique(matched_pid, pref_it->second.proc_name, 5);
        } else if (now - pref_it->second.since < std::chrono::seconds(g_cfg.reprobe_sec)) {
            add_unique(pref_it->second.cand_pid, pref_it->second.proc_name, 5);
        }
    }

    // Priority 2: live non-background Windows .exe processes in the same prefix.
    for (const auto& pm : prefix_matches) {
        add_unique(pm.pid, pm.name, 5);
    }

    // Priority 3: currently pinned ancestor (<=8 PPid hops) or same non-root cgroup.
    std::vector<pid_t> ancestors;
    {
        pid_t cur = ws_pid;
        for (int hop = 0; hop < 8 && cur > 1; ++hop) {
            pid_t parent = read_proc_ppid(cur);
            if (parent <= 1 || parent == cur) break;
            ancestors.push_back(parent);
            cur = parent;
        }
    }
    const bool has_nonroot_cg =
        !ws_cgroup.empty() && ws_cgroup != "/" && ws_cgroup != "0::/";
    for (const auto& [ppid, ps] : g_pid_state) {
        if (ps.bypass || ps.proc_name.empty()) continue;
        if (proc_starttime(ppid) != ps.starttime) continue;
        bool related =
            std::find(ancestors.begin(), ancestors.end(), ppid) != ancestors.end();
        if (!related && has_nonroot_cg && read_proc_cgroup(ppid) == ws_cgroup) {
            related = true;
        }
        if (related) {
            add_unique(ppid, ps.proc_name, 5);
        }
    }

    // Priority 4: wineserver.exe fallback (never added to eBPF direct_pids).
    add_unique(ws_pid, "C:\\Linux\\wineserver.exe", 6);
}

void resolve_process_for_sock(int proto, const AddrPort& src, pid_t& out_pid,
                              std::string& out_name) {
    std::vector<ProcCandidate> cands;
    pid_t ws_pid = 0;
    resolve_socket_candidates(proto, src, cands, ws_pid);
    if (!cands.empty()) {
        out_pid = cands.front().pid;
        out_name = cands.front().name;
    } else {
        out_pid = 0;
        out_name = "C:\\Linux\\unknown.exe";
    }
}

void unmark_pid(pid_t pid) {
    __u32 key = static_cast<__u32>(pid);
    if (g_direct_map_fd >= 0) bpf_map_delete_elem(g_direct_map_fd, &key);
}

void load_native_tunnel(bool force) {
    if (g_cfg.native_tunnel_path.empty()) return;
    struct stat st{};
    if (stat(g_cfg.native_tunnel_path.c_str(), &st) != 0) {
        g_native_tunnel.clear();
        g_native_tunnel_mtime = 0;
        return;
    }
    if (!force && st.st_mtime == g_native_tunnel_mtime) return;
    g_native_tunnel_mtime = st.st_mtime;
    g_native_tunnel.clear();
    std::ifstream in(g_cfg.native_tunnel_path);
    std::string line;
    while (std::getline(in, line)) {
        if (auto h = line.find('#'); h != std::string::npos) line.resize(h);
        line.erase(std::remove_if(line.begin(), line.end(),
                                  [](unsigned char ch) { return std::isspace(ch); }),
                   line.end());
        if (!line.empty()) g_native_tunnel.insert(normalize_proc_key(line));
    }
    std::printf("[nf-redir] always-via-ExitLag list: %zu name(s)\n", g_native_tunnel.size());
    for (auto& [pid, ps] : g_pid_state) {
        if (ps.bypass && g_native_tunnel.count(ps.key)) {
            unmark_pid(pid);
            ps.bypass = false;
            ps.app = "(list)";
        }
    }
}

void set_bypass(pid_t pid, const std::string& key, const std::string& proc_name) {
    if (g_direct_map_fd < 0) return;
    const unsigned long long st = proc_starttime(pid);
    if (st == 0) return;
    __u32 k = static_cast<__u32>(pid);
    __u8 v = 1;
    if (bpf_map_update_elem(g_direct_map_fd, &k, &v, BPF_ANY) != 0) return;
    g_pid_state[pid] = PidState{st, true, key, proc_name, {}, std::chrono::steady_clock::now()};
    g_new_bypass.push_back(pid);
    if (g_cfg.verbose) {
        std::printf("[nf-redir] bypass pid=%d (%s): not in an enabled ExitLag app\n",
                    static_cast<int>(pid), key.c_str());
    }
}

void set_pinned(pid_t pid, const std::string& key, const std::string& proc_name,
                const std::string& app) {
    auto it = g_pid_state.find(pid);
    const auto now = std::chrono::steady_clock::now();
    if (it != g_pid_state.end() && !it->second.bypass) {
        it->second.since = now;  // refresh pin
        it->second.app = app;
        if (!proc_name.empty()) it->second.proc_name = proc_name;
        return;
    }
    if (it != g_pid_state.end()) unmark_pid(pid);
    const unsigned long long st = proc_starttime(pid);
    if (st == 0) return;
    g_pid_state[pid] = PidState{st, false, key, proc_name, app, now};
    std::printf("[nf-redir] pin pid=%d (%s) -> ExitLag app '%s'\n", static_cast<int>(pid),
                key.c_str(), app.c_str());
}

// One ExitLag decision line from client.log.
void on_exitlag_decision(std::uint32_t nf_pid, const std::string& proc, const std::string& app,
                         const std::string& action) {
    if ((nf_pid & 0x40000000u) == 0) return;  // not a Linux process from our shim
    const pid_t pid = static_cast<pid_t>(nf_pid & 0x3FFFFFFFu);
    if (pid <= 0) return;
    const std::string key = normalize_proc_key(proc);
    if (is_wine_runtime_binary(key) || key == "unknown") return;
    const std::string full_proc = "C:\\Linux\\" + proc;
    if (app != "<no-app>") {
        set_pinned(pid, key, full_proc, app);
        return;
    }
    if (action != "pass") return;
    if (g_native_tunnel.count(key)) return;
    auto it = g_pid_state.find(pid);
    if (it != g_pid_state.end()) {
        if (it->second.bypass) return;
        // Pinned: keep it unless no app-matched decision was seen for 60s.
        if (std::chrono::steady_clock::now() - it->second.since < std::chrono::seconds(60)) return;
    }
    bool native = false;
    resolve_proc_name_for_pid(pid, &native);
    if (!native) return;  // Wine/Proton: always ask ExitLag (games)
    set_bypass(pid, key, full_proc);
}

// Tail ExitLag's client.log for decision lines.
struct LogTail {
    int fd = -1;
    ino_t ino = 0;
    off_t off = 0;
    std::string partial;
} g_logtail;

void parse_decision_line(const std::string& l) {
    // ... [TCP] a -> b [name (pid N) / APP] -> action
    auto t = l.find("[TCP] ");
    if (t == std::string::npos) t = l.find("[UDP] ");
    if (t == std::string::npos) return;
    auto p = l.find(" (pid ", t);
    if (p == std::string::npos) return;
    auto b = l.rfind('[', p);
    if (b == std::string::npos || b <= t) return;
    auto pe = l.find(") / ", p);
    if (pe == std::string::npos) return;
    auto ae = l.find("] -> ", pe);
    if (ae == std::string::npos) return;
    const std::string proc = l.substr(b + 1, p - b - 1);
    const std::uint32_t nf_pid =
        static_cast<std::uint32_t>(std::strtoul(l.c_str() + p + 6, nullptr, 10));
    const std::string app = l.substr(pe + 4, ae - pe - 4);
    std::string action = l.substr(ae + 5);
    while (!action.empty() && std::isspace(static_cast<unsigned char>(action.back()))) action.pop_back();
    if (auto sp = action.find(' '); sp != std::string::npos) action.resize(sp);
    on_exitlag_decision(nf_pid, proc, app, action);
}

void poll_exitlag_log(bool skip_existing) {
    if (g_cfg.exitlag_log.empty() || g_direct_map_fd < 0) return;
    struct stat st{};
    if (stat(g_cfg.exitlag_log.c_str(), &st) != 0) return;
    if (g_logtail.fd < 0 || st.st_ino != g_logtail.ino || st.st_size < g_logtail.off) {
        if (g_logtail.fd >= 0) close(g_logtail.fd);
        g_logtail.fd = open(g_cfg.exitlag_log.c_str(), O_RDONLY | O_CLOEXEC);
        if (g_logtail.fd < 0) return;
        g_logtail.ino = st.st_ino;
        // On daemon start skip the previous ExitLag run; after a rewrite read from 0.
        g_logtail.off = skip_existing ? st.st_size : 0;
        g_logtail.partial.clear();
    }
    char buf[65536];
    for (int rounds = 0; rounds < 64; ++rounds) {
        ssize_t n = pread(g_logtail.fd, buf, sizeof(buf), g_logtail.off);
        if (n <= 0) break;
        g_logtail.off += n;
        g_logtail.partial.append(buf, static_cast<std::size_t>(n));
        std::size_t pos = 0, nl;
        while ((nl = g_logtail.partial.find('\n', pos)) != std::string::npos) {
            parse_decision_line(g_logtail.partial.substr(pos, nl - pos));
            pos = nl + 1;
        }
        g_logtail.partial.erase(0, pos);
        if (g_logtail.partial.size() > 1 << 20) g_logtail.partial.clear();
    }
}

// Exited/reused PIDs out; BYPASS entries back to "ask ExitLag" after reprobe_sec.
void prune_pid_state() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = g_pid_state.begin(); it != g_pid_state.end();) {
        const bool dead = proc_starttime(it->first) != it->second.starttime;
        const bool reprobe = it->second.bypass &&
            now - it->second.since > std::chrono::seconds(g_cfg.reprobe_sec);
        if (dead || reprobe) {
            if (it->second.bypass) unmark_pid(it->first);
            it = g_pid_state.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = g_wineserver_preferred.begin(); it != g_wineserver_preferred.end();) {
        if (proc_starttime(it->first) != it->second.ws_starttime) {
            it = g_wineserver_preferred.erase(it);
        } else {
            ++it;
        }
    }
}

bool setup_bpf_direct() {
    if (g_cfg.bpf_obj.empty() || g_cfg.bpf_cgroup.empty()) return false;
    libbpf_set_print(nullptr);
    g_bpf_obj = bpf_object__open_file(g_cfg.bpf_obj.c_str(), nullptr);
    if (!g_bpf_obj) {
        std::printf("[nf-redir] WARN bpf open %s failed: %s\n", g_cfg.bpf_obj.c_str(),
                    std::strerror(errno));
        return false;
    }
    if (bpf_object__load(g_bpf_obj) != 0) {
        std::printf("[nf-redir] WARN bpf load failed: %s\n", std::strerror(errno));
        return false;
    }
    bpf_program* prog = bpf_object__find_program_by_name(g_bpf_obj, "mark_direct");
    bpf_map* map = bpf_object__find_map_by_name(g_bpf_obj, "direct_pids");
    if (!prog || !map) {
        std::printf("[nf-redir] WARN bpf program/map not found\n");
        return false;
    }
    int cg_fd = open(g_cfg.bpf_cgroup.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cg_fd < 0) {
        std::printf("[nf-redir] WARN open cgroup %s: %s\n", g_cfg.bpf_cgroup.c_str(),
                    std::strerror(errno));
        return false;
    }
    // Link-based attach: detached automatically when this process exits.
    g_bpf_link = bpf_program__attach_cgroup(prog, cg_fd);
    close(cg_fd);
    if (!g_bpf_link) {
        std::printf("[nf-redir] WARN bpf attach to %s failed: %s\n", g_cfg.bpf_cgroup.c_str(),
                    std::strerror(errno));
        return false;
    }
    g_direct_map_fd = bpf_map__fd(map);
    std::printf("[nf-redir] eBPF native-direct attached to %s\n", g_cfg.bpf_cgroup.c_str());
    return true;
}

// ---------------------------------------------------------------------------
// Epoll & IPC State
// ---------------------------------------------------------------------------
struct EpollTag {
    enum Kind {
        kTcpListen,
        kUdpListen,
        kIpcListen,
        kIpcClient,
        kTcpClient,
        kTcpTarget,
        kUdpDirect,
        kTimer,
        kSignal
    };
    Kind kind;
    void* ptr;
};

int g_ipc_listen_fd = -1;
int g_ipc_client_fd = -1;
EpollTag g_ipc_listen_tag{EpollTag::kIpcListen, nullptr};
EpollTag g_ipc_client_tag{EpollTag::kIpcClient, nullptr};
std::deque<std::vector<std::uint8_t>> g_ipc_out;
std::size_t g_ipc_out_off = 0;
std::vector<std::uint8_t> g_ipc_in;

bool epoll_ctrl_fd(int op, int fd, std::uint32_t events, EpollTag* tag) {
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = tag;
    return epoll_ctl(g_ep, op, fd, &ev) == 0;
}

void update_ipc_epoll() {
    if (g_ipc_client_fd < 0) return;
    std::uint32_t ev = EPOLLIN | EPOLLRDHUP;
    if (!g_ipc_out.empty()) ev |= EPOLLOUT;
    epoll_ctrl_fd(EPOLL_CTL_MOD, g_ipc_client_fd, ev, &g_ipc_client_tag);
}

void queue_ipc_frame(np::MsgType type, const void* hdr, std::size_t hdr_len,
                     const void* extra = nullptr, std::size_t extra_len = 0) {
    if (g_ipc_client_fd < 0) return;
    std::vector<std::uint8_t> frame;
    np::append_frame(frame, type, hdr, hdr_len, extra, extra_len);
    g_ipc_out.push_back(std::move(frame));
    update_ipc_epoll();
}

// ---------------------------------------------------------------------------
// TCP Transparent Proxy Relay
// ---------------------------------------------------------------------------
struct TcpConn : std::enable_shared_from_this<TcpConn> {
    enum State { kWaitNfDecision, kConnectingTarget, kRelaying, kClosed };

    std::uint64_t conn_id = 0;
    pid_t linux_pid = 0;
    pid_t wineserver_pid = 0;
    std::string proc_name;
    std::deque<ProcCandidate> fallback_cands;
    bool nf_notified = false;
    State state = kConnectingTarget;
    std::chrono::steady_clock::time_point wait_started{};

    int client_fd = -1;
    int target_fd = -1;
    EpollTag client_tag{EpollTag::kTcpClient, this};
    EpollTag target_tag{EpollTag::kTcpTarget, this};

    AddrPort orig_dst{};
    AddrPort local_ap{};

    std::deque<std::string> to_target;
    std::size_t to_target_off = 0;
    std::deque<std::string> to_client;
    std::size_t to_client_off = 0;

    bool client_eof = false;
    bool target_eof = false;
    bool client_shut_wr = false;
    bool target_shut_wr = false;
};

std::uint64_t g_next_conn_id = 1;
std::unordered_map<TcpConn*, std::shared_ptr<TcpConn>> g_tcp_conns;
std::unordered_map<std::uint64_t, std::shared_ptr<TcpConn>> g_tcp_by_id;

void send_tcp_closed(const TcpConn* c) {
    np::MsgTcpClosed msg{};
    msg.conn_id = c->conn_id;
    msg.linux_pid = static_cast<std::uint32_t>(c->linux_pid);
    msg.af = c->local_ap.af ? c->local_ap.af : c->orig_dst.af;
    std::memcpy(msg.local_ip, c->local_ap.ip.data(), 16);
    msg.local_port_be = c->local_ap.port_be;
    msg.remote_port_be = c->orig_dst.port_be;
    std::memcpy(msg.remote_ip, c->orig_dst.ip.data(), 16);
    queue_ipc_frame(np::kMsgTcpClosed, &msg, sizeof(msg));
}

void send_tcp_connect_req(const TcpConn* c) {
    np::MsgTcpConnectReq req{};
    req.conn_id = c->conn_id;
    req.linux_pid = static_cast<std::uint32_t>(c->linux_pid);
    req.af = c->orig_dst.af;
    req.proc_name_len = static_cast<std::uint16_t>(
        std::min<std::size_t>(c->proc_name.size(), 512));
    std::memcpy(req.local_ip, c->local_ap.ip.data(), 16);
    req.local_port_be = c->local_ap.port_be;
    req.remote_port_be = c->orig_dst.port_be;
    std::memcpy(req.remote_ip, c->orig_dst.ip.data(), 16);
    queue_ipc_frame(np::kMsgTcpConnectReq, &req, sizeof(req),
                    c->proc_name.data(), req.proc_name_len);
}

void close_tcp_conn(TcpConn* c) {
    if (c->state == TcpConn::kClosed) return;
    c->state = TcpConn::kClosed;
    if (c->nf_notified && g_ipc_client_fd >= 0) {
        send_tcp_closed(c);
    }
    if (c->client_fd >= 0) {
        epoll_ctl(g_ep, EPOLL_CTL_DEL, c->client_fd, nullptr);
        close(c->client_fd);
        c->client_fd = -1;
    }
    if (c->target_fd >= 0) {
        epoll_ctl(g_ep, EPOLL_CTL_DEL, c->target_fd, nullptr);
        close(c->target_fd);
        c->target_fd = -1;
    }
    g_tcp_by_id.erase(c->conn_id);
    g_tcp_conns.erase(c);
}

void update_tcp_epoll(TcpConn* c) {
    if (c->state == TcpConn::kClosed) return;
    if (c->target_fd >= 0 && c->state != TcpConn::kWaitNfDecision) {
        std::uint32_t ev = EPOLLIN | EPOLLRDHUP;
        if (c->state == TcpConn::kConnectingTarget || !c->to_target.empty()) {
            ev |= EPOLLOUT;
        }
        epoll_ctrl_fd(EPOLL_CTL_MOD, c->target_fd, ev, &c->target_tag);
    }
    if (c->client_fd >= 0) {
        std::uint32_t ev = EPOLLRDHUP;
        if (c->state == TcpConn::kRelaying) {
            ev |= EPOLLIN;
            if (!c->to_client.empty()) ev |= EPOLLOUT;
        }
        epoll_ctrl_fd(EPOLL_CTL_MOD, c->client_fd, ev, &c->client_tag);
    }
}

bool flush_queue(int fd, std::deque<std::string>& q, std::size_t& off, bool& eof_peer,
                 bool& shut_wr, bool& fatal) {
    while (!q.empty()) {
        const std::string& front = q.front();
        ssize_t n = send(fd, front.data() + off, front.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
            fatal = true;
            return false;
        }
        off += static_cast<std::size_t>(n);
        if (off == front.size()) {
            q.pop_front();
            off = 0;
        }
    }
    if (q.empty() && eof_peer && !shut_wr) {
        shutdown(fd, SHUT_WR);
        shut_wr = true;
    }
    return true;
}

bool read_into_queue(int fd, std::deque<std::string>& q, bool& eof, bool& fatal) {
    char buf[16384];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            q.emplace_back(buf, static_cast<std::size_t>(n));
            if (q.size() > 64) break;
        } else if (n == 0) {
            eof = true;
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            fatal = true;
            return false;
        }
    }
    return true;
}

bool start_tcp_connect(TcpConn* c, const AddrPort& dst, bool keep_bound_loopback) {
    if (!keep_bound_loopback || c->target_fd < 0 || dst.af != c->local_ap.af) {
        if (c->target_fd >= 0) {
            epoll_ctl(g_ep, EPOLL_CTL_DEL, c->target_fd, nullptr);
            close(c->target_fd);
            c->target_fd = -1;
        }
        const int domain = (dst.af == np::kAf4) ? AF_INET : AF_INET6;
        int tfd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (tfd < 0) return false;
        set_sockopt_int(tfd, IPPROTO_TCP, TCP_NODELAY, 1);
        try_set_mark(tfd, g_cfg.mark);
        c->target_fd = tfd;
    }
    sockaddr_storage dss{};
    socklen_t dlen = to_sockaddr(dst, dss);
    int rc = connect(c->target_fd, reinterpret_cast<sockaddr*>(&dss), dlen);
    if (rc < 0 && errno != EINPROGRESS) {
        if (g_cfg.verbose) {
            std::printf("[nf-redir tcp] id=%llu connect(%s) failed: %s\n",
                        static_cast<unsigned long long>(c->conn_id), format_ap(dst).c_str(),
                        std::strerror(errno));
        }
        return false;
    }
    c->state = (rc == 0) ? TcpConn::kRelaying : TcpConn::kConnectingTarget;
    std::uint32_t ev = EPOLLIN | EPOLLRDHUP;
    if (c->state == TcpConn::kConnectingTarget) ev |= EPOLLOUT;
    epoll_ctrl_fd(EPOLL_CTL_ADD, c->target_fd, ev, &c->target_tag);
    update_tcp_epoll(c);
    return true;
}

void on_tcp_accept(int listen_fd, const AddrPort& listen_ap) {
    for (;;) {
        sockaddr_storage src_ss{};
        socklen_t src_len = sizeof(src_ss);
        int cfd = accept4(listen_fd, reinterpret_cast<sockaddr*>(&src_ss), &src_len,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
            return;
        }

        AddrPort src{};
        AddrPort dst{};
        sockaddr_storage dst_ss{};
        socklen_t dst_len = sizeof(dst_ss);
        if (!from_sockaddr(src_ss, src) ||
            getsockname(cfd, reinterpret_cast<sockaddr*>(&dst_ss), &dst_len) != 0 ||
            !from_sockaddr(dst_ss, dst)) {
            close(cfd);
            continue;
        }
        if (same_ap(dst, listen_ap)) {
            socklen_t olen = sizeof(dst_ss);
            const int level = (dst.af == np::kAf4) ? SOL_IP : SOL_IPV6;
            const int opt = (dst.af == np::kAf4) ? SO_ORIGINAL_DST : IP6T_SO_ORIGINAL_DST;
            if (getsockopt(cfd, level, opt, &dst_ss, &olen) != 0 || !from_sockaddr(dst_ss, dst)) {
                close(cfd);
                continue;
            }
        }

        set_sockopt_int(cfd, IPPROTO_TCP, TCP_NODELAY, 1);

        auto c = std::make_shared<TcpConn>();
        c->conn_id = g_next_conn_id++;
        c->client_fd = cfd;
        c->orig_dst = dst;

        TcpConn* raw = c.get();
        g_tcp_conns[raw] = c;
        g_tcp_by_id[c->conn_id] = c;
        epoll_ctrl_fd(EPOLL_CTL_ADD, cfd, EPOLLRDHUP, &raw->client_tag);

        if (g_ipc_client_fd < 0) {
            if (!start_tcp_connect(raw, dst, false)) {
                close_tcp_conn(raw);
            } else if (g_cfg.verbose) {
                std::printf("[nf-redir tcp] direct (no ipc) %s -> %s\n",
                            format_ap(src).c_str(), format_ap(dst).c_str());
            }
            continue;
        }

        std::vector<ProcCandidate> cands;
        pid_t ws_pid = 0;
        resolve_socket_candidates(IPPROTO_TCP, src, cands, ws_pid);
        const ProcCandidate first =
            !cands.empty() ? cands.front() : ProcCandidate{0, "C:\\Linux\\unknown.exe"};
        pid_t pid = first.pid;
        std::string proc_name = first.name;
        c->linux_pid = pid;
        c->wineserver_pid = ws_pid;
        c->proc_name = proc_name;
        for (std::size_t i = 1; i < cands.size(); ++i) {
            c->fallback_cands.push_back(std::move(cands[i]));
        }

        // Bind a loopback socket so ExitLag.exe's accept() server (1414546e0) can
        // match peer_port == req.local_port when redirecting TCP!
        const int domain = (dst.af == np::kAf4) ? AF_INET : AF_INET6;
        int pfd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (pfd < 0) {
            if (!start_tcp_connect(raw, dst, false)) close_tcp_conn(raw);
            continue;
        }
        set_sockopt_int(pfd, IPPROTO_TCP, TCP_NODELAY, 1);
        try_set_mark(pfd, g_cfg.mark);

        AddrPort bind_ap{};
        bind_ap.af = dst.af;
        bind_ap.port_be = 0;
        if (dst.af == np::kAf4) {
            std::uint32_t lo = htonl(INADDR_LOOPBACK);
            std::memcpy(bind_ap.ip.data(), &lo, 4);
        } else {
            bind_ap.ip[15] = 1;
        }
        sockaddr_storage bss{};
        socklen_t blen = to_sockaddr(bind_ap, bss);
        sockaddr_storage bound_ss{};
        socklen_t bound_len = sizeof(bound_ss);
        if (bind(pfd, reinterpret_cast<sockaddr*>(&bss), blen) != 0 ||
            getsockname(pfd, reinterpret_cast<sockaddr*>(&bound_ss), &bound_len) != 0 ||
            !from_sockaddr(bound_ss, c->local_ap)) {
            close(pfd);
            if (!start_tcp_connect(raw, dst, false)) close_tcp_conn(raw);
            continue;
        }
        c->target_fd = pfd;
        c->state = TcpConn::kWaitNfDecision;
        c->wait_started = std::chrono::steady_clock::now();
        c->nf_notified = true;

        send_tcp_connect_req(raw);

        if (g_cfg.verbose) {
            std::printf("[nf-redir tcp] id=%llu pid=%d proc=%s %s -> %s (lb=%u)\n",
                        static_cast<unsigned long long>(c->conn_id), static_cast<int>(pid),
                        proc_name.c_str(), format_ap(src).c_str(), format_ap(dst).c_str(),
                        ntohs(c->local_ap.port_be));
        }
    }
}

void handle_tcp_event(TcpConn* c, bool is_target, std::uint32_t events) {
    if (c->state == TcpConn::kClosed) return;
    if (events & EPOLLERR) {
        close_tcp_conn(c);
        return;
    }

    if (!is_target && c->state != TcpConn::kRelaying) {
        // Only abort on full hangup while waiting for NF decision or target connect;
        // EPOLLRDHUP is peer SHUT_WR and will be drained once relaying begins.
        if (events & EPOLLHUP) {
            close_tcp_conn(c);
        }
        return;
    }

    if (is_target && c->state == TcpConn::kConnectingTarget) {
        if (!(events & EPOLLOUT)) return;
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(c->target_fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            if (g_cfg.verbose) {
                std::printf("[nf-redir tcp] id=%llu target SO_ERROR=%d (%s)\n",
                            static_cast<unsigned long long>(c->conn_id), err, std::strerror(err));
            }
            close_tcp_conn(c);
            return;
        }
        c->state = TcpConn::kRelaying;
        update_tcp_epoll(c);
    }

    if (c->state == TcpConn::kRelaying) {
        bool fatal = false;
        if (!is_target) {
            if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) {
                if (!read_into_queue(c->client_fd, c->to_target, c->client_eof, fatal) && fatal) {
                    close_tcp_conn(c);
                    return;
                }
            }
        } else {
            if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) {
                if (!read_into_queue(c->target_fd, c->to_client, c->target_eof, fatal) && fatal) {
                    close_tcp_conn(c);
                    return;
                }
            }
        }
        if (!flush_queue(c->target_fd, c->to_target, c->to_target_off, c->client_eof,
                         c->target_shut_wr, fatal) ||
            !flush_queue(c->client_fd, c->to_client, c->to_client_off, c->target_eof,
                         c->client_shut_wr, fatal)) {
            close_tcp_conn(c);
            return;
        }
        if (c->client_shut_wr && c->target_shut_wr) {
            close_tcp_conn(c);
            return;
        }
        update_tcp_epoll(c);
    }
}

// ---------------------------------------------------------------------------
// UDP Transparent Proxy Relay
// ---------------------------------------------------------------------------
struct AddrPortKeyHash {
    std::size_t operator()(const AddrPort& a) const noexcept {
        std::uint64_t h = 14695981039346656037ull;
        auto mix = [&](const void* p, std::size_t n) {
            const auto* b = static_cast<const std::uint8_t*>(p);
            for (std::size_t i = 0; i < n; ++i) {
                h ^= b[i];
                h *= 1099511628211ull;
            }
        };
        mix(&a.af, 1);
        mix(&a.port_be, 2);
        mix(a.ip.data(), a.af == np::kAf4 ? 4 : 16);
        return static_cast<std::size_t>(h);
    }
};

struct AddrPortKeyEq {
    bool operator()(const AddrPort& a, const AddrPort& b) const noexcept {
        return same_ap(a, b);
    }
};

struct ReplySockEntry {
    int fd = -1;
    std::chrono::steady_clock::time_point last_used{};
};

struct UdpFlow {
    std::uint64_t conn_id = 0;
    pid_t linux_pid = 0;
    AddrPort src{};
    int direct_fd = -1;
    EpollTag direct_tag{EpollTag::kUdpDirect, nullptr};
    bool direct = false;
    bool nf_notified = false;
    std::chrono::steady_clock::time_point last_active{};
};

std::unordered_map<AddrPort, std::uint64_t, AddrPortKeyHash, AddrPortKeyEq> g_udp_by_src;
std::unordered_map<std::uint64_t, std::unique_ptr<UdpFlow>> g_udp_by_id;
std::unordered_map<AddrPort, ReplySockEntry, AddrPortKeyHash, AddrPortKeyEq> g_reply_socks;

int acquire_reply_socket(const AddrPort& spoof_src) {
    auto it = g_reply_socks.find(spoof_src);
    if (it != g_reply_socks.end()) {
        it->second.last_used = std::chrono::steady_clock::now();
        return it->second.fd;
    }

    const int domain = (spoof_src.af == np::kAf4) ? AF_INET : AF_INET6;
    int fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    set_sockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    set_sockopt_int(fd, SOL_SOCKET, SO_REUSEPORT, 1);
    if (spoof_src.af == np::kAf4) {
        if (!set_sockopt_int(fd, SOL_IP, IP_TRANSPARENT, 1)) {
            std::fprintf(stderr, "error: setsockopt(IP_TRANSPARENT) reply failed: %s\n",
                         std::strerror(errno));
            close(fd);
            return -1;
        }
        set_sockopt_int(fd, SOL_IP, IP_FREEBIND, 1);
    } else {
        if (!set_sockopt_int(fd, SOL_IPV6, IPV6_TRANSPARENT, 1)) {
            std::fprintf(stderr, "error: setsockopt(IPV6_TRANSPARENT) reply failed: %s\n",
                         std::strerror(errno));
            close(fd);
            return -1;
        }
        set_sockopt_int(fd, SOL_IPV6, IPV6_FREEBIND, 1);
    }
    try_set_mark(fd, g_cfg.mark);

    sockaddr_storage bss{};
    socklen_t blen = to_sockaddr(spoof_src, bss);
    if (bind(fd, reinterpret_cast<sockaddr*>(&bss), blen) != 0) {
        std::fprintf(stderr, "error: bind transparent reply socket %s failed: %s\n",
                     format_ap(spoof_src).c_str(), std::strerror(errno));
        close(fd);
        return -1;
    }
    g_reply_socks[spoof_src] = ReplySockEntry{fd, std::chrono::steady_clock::now()};
    return fd;
}

void inject_udp_reply(const AddrPort& client_dst, const AddrPort& spoof_remote,
                      const void* data, std::size_t len) {
    int rfd = acquire_reply_socket(spoof_remote);
    if (rfd < 0) return;
    sockaddr_storage dst_ss{};
    socklen_t dlen = to_sockaddr(client_dst, dst_ss);
    sendto(rfd, data, len, MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&dst_ss), dlen);
}

void destroy_udp_flow(std::uint64_t conn_id, bool send_close) {
    auto it = g_udp_by_id.find(conn_id);
    if (it == g_udp_by_id.end()) return;
    UdpFlow* f = it->second.get();
    if (send_close && f->nf_notified && g_ipc_client_fd >= 0) {
        np::MsgUdpClosed msg{};
        msg.conn_id = f->conn_id;
        msg.linux_pid = static_cast<std::uint32_t>(f->linux_pid);
        msg.af = f->src.af;
        std::memcpy(msg.local_ip, f->src.ip.data(), 16);
        msg.local_port_be = f->src.port_be;
        queue_ipc_frame(np::kMsgUdpClosed, &msg, sizeof(msg));
    }
    if (f->direct_fd >= 0) {
        epoll_ctl(g_ep, EPOLL_CTL_DEL, f->direct_fd, nullptr);
        close(f->direct_fd);
        f->direct_fd = -1;
    }
    g_udp_by_src.erase(f->src);
    g_udp_by_id.erase(it);
}

void on_udp_tproxy_readable(int listen_fd) {
    std::array<char, 65536> buf{};
    std::uint8_t cbuf[256]{};
    for (;;) {
        sockaddr_storage src_ss{};
        iovec iov{buf.data(), buf.size()};
        msghdr msg{};
        msg.msg_name = &src_ss;
        msg.msg_namelen = sizeof(src_ss);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        ssize_t n = recvmsg(listen_fd, &msg, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            return;
        }
        AddrPort src{};
        if (!from_sockaddr(src_ss, src)) continue;

        AddrPort dst{};
        bool found_dst = false;
        for (cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
            if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_ORIGDSTADDR &&
                cm->cmsg_len >= CMSG_LEN(sizeof(sockaddr_in))) {
                sockaddr_storage ds{};
                std::memcpy(&ds, CMSG_DATA(cm), sizeof(sockaddr_in));
                found_dst = from_sockaddr(ds, dst);
                break;
            }
            if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_ORIGDSTADDR &&
                cm->cmsg_len >= CMSG_LEN(sizeof(sockaddr_in6))) {
                sockaddr_storage ds{};
                std::memcpy(&ds, CMSG_DATA(cm), sizeof(sockaddr_in6));
                found_dst = from_sockaddr(ds, dst);
                break;
            }
        }
        if (!found_dst) continue;

        UdpFlow* flow = nullptr;
        auto it = g_udp_by_src.find(src);
        if (it != g_udp_by_src.end()) {
            flow = g_udp_by_id[it->second].get();
            flow->last_active = std::chrono::steady_clock::now();
        } else {
            auto nf = std::make_unique<UdpFlow>();
            nf->conn_id = g_next_conn_id++;
            nf->src = src;
            nf->last_active = std::chrono::steady_clock::now();

            const int domain = (src.af == np::kAf4) ? AF_INET : AF_INET6;
            nf->direct_fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (nf->direct_fd < 0) continue;
            try_set_mark(nf->direct_fd, g_cfg.mark);
            nf->direct_tag = EpollTag{EpollTag::kUdpDirect, nf.get()};
            epoll_ctrl_fd(EPOLL_CTL_ADD, nf->direct_fd, EPOLLIN, &nf->direct_tag);

            if (g_ipc_client_fd >= 0) {
                std::string proc_name;
                resolve_process_for_sock(IPPROTO_UDP, src, nf->linux_pid, proc_name);
                nf->direct = false;
                nf->nf_notified = true;

                np::MsgUdpCreated cmsg{};
                cmsg.conn_id = nf->conn_id;
                cmsg.linux_pid = static_cast<std::uint32_t>(nf->linux_pid);
                cmsg.af = src.af;
                cmsg.proc_name_len = static_cast<std::uint16_t>(
                    std::min<std::size_t>(proc_name.size(), 512));
                std::memcpy(cmsg.local_ip, src.ip.data(), 16);
                cmsg.local_port_be = src.port_be;
                queue_ipc_frame(np::kMsgUdpCreated, &cmsg, sizeof(cmsg),
                                proc_name.data(), cmsg.proc_name_len);
                if (g_cfg.verbose) {
                    std::printf("[nf-redir udp] id=%llu pid=%d proc=%s src=%s -> %s\n",
                                static_cast<unsigned long long>(nf->conn_id),
                                static_cast<int>(nf->linux_pid), proc_name.c_str(),
                                format_ap(src).c_str(), format_ap(dst).c_str());
                }
            } else {
                nf->direct = true;
                nf->nf_notified = false;
                if (g_cfg.verbose) {
                    std::printf("[nf-redir udp] id=%llu direct (no ipc) src=%s -> %s\n",
                                static_cast<unsigned long long>(nf->conn_id),
                                format_ap(src).c_str(), format_ap(dst).c_str());
                }
            }

            flow = nf.get();
            g_udp_by_src[src] = nf->conn_id;
            g_udp_by_id[nf->conn_id] = std::move(nf);
        }

        if (flow->direct || g_ipc_client_fd < 0) {
            sockaddr_storage dss{};
            socklen_t dlen = to_sockaddr(dst, dss);
            sendto(flow->direct_fd, buf.data(), static_cast<std::size_t>(n), MSG_DONTWAIT,
                   reinterpret_cast<sockaddr*>(&dss), dlen);
        } else {
            np::MsgUdpPacket uhdr{};
            uhdr.conn_id = flow->conn_id;
            uhdr.af = dst.af;
            uhdr.remote_port_be = dst.port_be;
            std::memcpy(uhdr.remote_ip, dst.ip.data(), 16);
            queue_ipc_frame(np::kMsgUdpSend, &uhdr, sizeof(uhdr),
                            buf.data(), static_cast<std::size_t>(n));
        }
    }
}

void on_udp_direct_readable(UdpFlow* flow) {
    std::array<char, 65536> buf{};
    for (;;) {
        sockaddr_storage from_ss{};
        socklen_t flen = sizeof(from_ss);
        ssize_t n = recvfrom(flow->direct_fd, buf.data(), buf.size(), 0,
                             reinterpret_cast<sockaddr*>(&from_ss), &flen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            return;
        }
        AddrPort from_ap{};
        if (!from_sockaddr(from_ss, from_ap)) continue;
        flow->last_active = std::chrono::steady_clock::now();
        inject_udp_reply(flow->src, from_ap, buf.data(), static_cast<std::size_t>(n));
    }
}

// ---------------------------------------------------------------------------
// IPC Dispatch & Maintenance
// ---------------------------------------------------------------------------
void close_ipc_client() {
    if (g_ipc_client_fd >= 0) {
        epoll_ctl(g_ep, EPOLL_CTL_DEL, g_ipc_client_fd, nullptr);
        close(g_ipc_client_fd);
        g_ipc_client_fd = -1;
    }
    g_ipc_out.clear();
    g_ipc_out_off = 0;
    g_ipc_in.clear();

    // Fail-open any pending TCP decisions or filtered UDP flows
    std::vector<TcpConn*> pending;
    for (auto& [raw, sp] : g_tcp_conns) {
        if (sp->state == TcpConn::kWaitNfDecision) pending.push_back(raw);
    }
    for (TcpConn* c : pending) {
        c->nf_notified = false;
        if (!start_tcp_connect(c, c->orig_dst, false)) close_tcp_conn(c);
    }
    for (auto& [cid, f] : g_udp_by_id) {
        f->direct = true;
        f->nf_notified = false;
    }
    if (g_cfg.verbose) {
        std::printf("[nf-redir ipc] client disconnected (fail-open active flows)\n");
    }
}

void handle_ipc_frame(np::MsgType type, const std::uint8_t* data, std::size_t len) {
    switch (type) {
        case np::kMsgHello: {
            if (len >= sizeof(np::MsgHello)) {
                np::MsgHello h{};
                std::memcpy(&h, data, sizeof(h));
                std::printf("NF IPC CONNECTED exitlag_pid=%u proto=%u\n",
                            h.exitlag_pid, h.proto_version);
            }
            break;
        }
        case np::kMsgTcpConnectResp: {
            if (len < sizeof(np::MsgTcpConnectResp)) break;
            np::MsgTcpConnectResp resp{};
            std::memcpy(&resp, data, sizeof(resp));
            auto it = g_tcp_by_id.find(resp.conn_id);
            if (it == g_tcp_by_id.end()) break;
            auto sp = it->second;
            TcpConn* c = sp.get();
            if (c->state != TcpConn::kWaitNfDecision) break;

            if (resp.action == np::kTcpBlock) {
                if (g_cfg.verbose) {
                    std::printf("[nf-redir tcp] id=%llu BLOCK\n",
                                static_cast<unsigned long long>(resp.conn_id));
                }
                close_tcp_conn(c);
            } else if (resp.action == np::kTcpRedirect) {
                if (c->wineserver_pid > 0 && !c->proc_name.empty()) {
                    const unsigned long long ws_st = proc_starttime(c->wineserver_pid);
                    if (ws_st != 0) {
                        g_wineserver_preferred[c->wineserver_pid] = WineserverPref{
                            ws_st, c->linux_pid, c->proc_name, std::chrono::steady_clock::now()};
                    }
                }
                AddrPort redir{};
                redir.af = resp.af;
                redir.port_be = resp.new_remote_port_be;
                std::memcpy(redir.ip.data(), resp.new_remote_ip, 16);
                if (g_cfg.verbose) {
                    std::printf("[nf-redir tcp] id=%llu REDIRECT -> %s\n",
                                static_cast<unsigned long long>(resp.conn_id),
                                format_ap(redir).c_str());
                }
                if (!start_tcp_connect(c, redir, true)) close_tcp_conn(c);
            } else if (!c->fallback_cands.empty() && g_ipc_client_fd >= 0) {
                // Wineserver attribution fallback: close rejected synthetic attempt and
                // re-ask ExitLag under the next candidate .exe before allowing direct.
                send_tcp_closed(c);

                const std::uint64_t prev_id = c->conn_id;
                g_tcp_by_id.erase(it);
                ProcCandidate next = std::move(c->fallback_cands.front());
                c->fallback_cands.pop_front();
                c->conn_id = g_next_conn_id++;
                c->linux_pid = next.pid;
                c->proc_name = next.name;
                c->wait_started = std::chrono::steady_clock::now();
                g_tcp_by_id[c->conn_id] = sp;

                send_tcp_connect_req(c);

                if (g_cfg.verbose) {
                    std::printf("[nf-redir tcp] id=%llu retry (prev=%llu) ws=%d pid=%d proc=%s\n",
                                static_cast<unsigned long long>(c->conn_id),
                                static_cast<unsigned long long>(prev_id),
                                static_cast<int>(c->wineserver_pid),
                                static_cast<int>(c->linux_pid), c->proc_name.c_str());
                }
            } else {
                if (g_cfg.verbose) {
                    std::printf("[nf-redir tcp] id=%llu ALLOW_DIRECT\n",
                                static_cast<unsigned long long>(resp.conn_id));
                }
                if (!start_tcp_connect(c, c->orig_dst, false)) close_tcp_conn(c);
            }
            break;
        }
        case np::kMsgUdpPostSend: {
            if (len < sizeof(np::MsgUdpPacket)) break;
            np::MsgUdpPacket hdr{};
            std::memcpy(&hdr, data, sizeof(hdr));
            auto it = g_udp_by_id.find(hdr.conn_id);
            if (it == g_udp_by_id.end()) break;
            UdpFlow* f = it->second.get();
            f->last_active = std::chrono::steady_clock::now();
            AddrPort remote{};
            remote.af = hdr.af;
            remote.port_be = hdr.remote_port_be;
            std::memcpy(remote.ip.data(), hdr.remote_ip, 16);
            sockaddr_storage rss{};
            socklen_t rlen = to_sockaddr(remote, rss);
            sendto(f->direct_fd, data + sizeof(hdr), len - sizeof(hdr), MSG_DONTWAIT,
                   reinterpret_cast<sockaddr*>(&rss), rlen);
            break;
        }
        case np::kMsgUdpPostRecv: {
            if (len < sizeof(np::MsgUdpPacket)) break;
            np::MsgUdpPacket hdr{};
            std::memcpy(&hdr, data, sizeof(hdr));
            auto it = g_udp_by_id.find(hdr.conn_id);
            if (it == g_udp_by_id.end()) break;
            UdpFlow* f = it->second.get();
            f->last_active = std::chrono::steady_clock::now();
            AddrPort remote{};
            remote.af = hdr.af;
            remote.port_be = hdr.remote_port_be;
            std::memcpy(remote.ip.data(), hdr.remote_ip, 16);
            inject_udp_reply(f->src, remote, data + sizeof(hdr), len - sizeof(hdr));
            break;
        }
        case np::kMsgUdpDisableFilter: {
            if (len < sizeof(np::MsgUdpConnId)) break;
            np::MsgUdpConnId msg{};
            std::memcpy(&msg, data, sizeof(msg));
            if (auto it = g_udp_by_id.find(msg.conn_id); it != g_udp_by_id.end()) {
                it->second->direct = true;
                if (g_cfg.verbose) {
                    std::printf("[nf-redir udp] id=%llu -> direct (filter disabled)\n",
                                static_cast<unsigned long long>(msg.conn_id));
                }
            }
            break;
        }
        case np::kMsgUdpEnableFilter: {
            if (len < sizeof(np::MsgUdpConnId)) break;
            np::MsgUdpConnId msg{};
            std::memcpy(&msg, data, sizeof(msg));
            if (auto it = g_udp_by_id.find(msg.conn_id); it != g_udp_by_id.end()) {
                it->second->direct = false;
            }
            break;
        }
        default:
            break;
    }
}

void on_ipc_listen_readable() {
    for (;;) {
        sockaddr_storage ss{};
        socklen_t sl = sizeof(ss);
        int cfd = accept4(g_ipc_listen_fd, reinterpret_cast<sockaddr*>(&ss), &sl,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
            return;
        }
        set_sockopt_int(cfd, IPPROTO_TCP, TCP_NODELAY, 1);
        if (g_ipc_client_fd >= 0) {
            close_ipc_client();
        }
        g_ipc_client_fd = cfd;
        epoll_ctrl_fd(EPOLL_CTL_ADD, cfd, EPOLLIN | EPOLLRDHUP, &g_ipc_client_tag);
    }
}

void on_ipc_client_events(std::uint32_t events) {
    if (g_ipc_client_fd < 0) return;
    if (events & (EPOLLERR | EPOLLHUP)) {
        close_ipc_client();
        return;
    }
    if (events & EPOLLOUT) {
        while (!g_ipc_out.empty()) {
            const auto& front = g_ipc_out.front();
            ssize_t n = send(g_ipc_client_fd, front.data() + g_ipc_out_off,
                             front.size() - g_ipc_out_off, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                close_ipc_client();
                return;
            }
            g_ipc_out_off += static_cast<std::size_t>(n);
            if (g_ipc_out_off == front.size()) {
                g_ipc_out.pop_front();
                g_ipc_out_off = 0;
            }
        }
        update_ipc_epoll();
    }
    if (events & (EPOLLIN | EPOLLRDHUP)) {
        std::uint8_t tmp[32768];
        for (;;) {
            ssize_t n = recv(g_ipc_client_fd, tmp, sizeof(tmp), 0);
            if (n > 0) {
                g_ipc_in.insert(g_ipc_in.end(), tmp, tmp + n);
            } else if (n == 0) {
                close_ipc_client();
                return;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                close_ipc_client();
                return;
            }
        }

        std::size_t off = 0;
        while (g_ipc_in.size() - off >= sizeof(np::MsgHeader)) {
            np::MsgHeader mh{};
            std::memcpy(&mh, g_ipc_in.data() + off, sizeof(mh));
            if (mh.length > np::kMaxFrameBytes) {
                close_ipc_client();
                return;
            }
            if (g_ipc_in.size() - off < sizeof(np::MsgHeader) + mh.length) break;
            const std::uint8_t* pdata = g_ipc_in.data() + off + sizeof(np::MsgHeader);
            handle_ipc_frame(static_cast<np::MsgType>(mh.type), pdata, mh.length);
            if (g_ipc_client_fd < 0) return;
            off += sizeof(np::MsgHeader) + mh.length;
        }
        if (off > 0) {
            g_ipc_in.erase(g_ipc_in.begin(), g_ipc_in.begin() + static_cast<std::ptrdiff_t>(off));
        }
    }
}

void on_timer_tick() {
    const auto now = std::chrono::steady_clock::now();

    // 1s tick: read new ExitLag decisions, expire/re-probe bypassed PIDs, list edits.
    poll_exitlag_log(false);
    if (!g_new_bypass.empty()) {
        for (auto& [fid, f] : g_udp_by_id) {
            if (f->direct || f->linux_pid <= 0) continue;
            if (std::find(g_new_bypass.begin(), g_new_bypass.end(), f->linux_pid) ==
                g_new_bypass.end()) continue;
            f->direct = true;
            if (g_cfg.verbose) {
                std::printf("[nf-redir udp] id=%llu pid=%d -> direct (process bypassed)\n",
                            static_cast<unsigned long long>(fid), static_cast<int>(f->linux_pid));
            }
        }
        g_new_bypass.clear();
    }
    if (g_direct_map_fd >= 0) prune_pid_state();
    load_native_tunnel(false);

    std::vector<TcpConn*> timed_out_tcp;
    for (auto& [raw, sp] : g_tcp_conns) {
        if (sp->state == TcpConn::kWaitNfDecision &&
            now - sp->wait_started > std::chrono::milliseconds(g_cfg.nf_timeout_ms)) {
            timed_out_tcp.push_back(raw);
        }
    }
    for (TcpConn* c : timed_out_tcp) {
        if (g_cfg.verbose) {
            std::printf("[nf-redir tcp] id=%llu NF timeout -> direct %s\n",
                        static_cast<unsigned long long>(c->conn_id),
                        format_ap(c->orig_dst).c_str());
        }
        c->nf_notified = false;
        if (!start_tcp_connect(c, c->orig_dst, false)) close_tcp_conn(c);
    }

    std::vector<std::uint64_t> expired_udp;
    for (const auto& [fid, f] : g_udp_by_id) {
        if (now - f->last_active > std::chrono::seconds(g_cfg.udp_idle_sec)) {
            expired_udp.push_back(fid);
        }
    }
    for (std::uint64_t fid : expired_udp) destroy_udp_flow(fid, true);

    for (auto it = g_reply_socks.begin(); it != g_reply_socks.end();) {
        if (now - it->second.last_used > std::chrono::seconds(g_cfg.udp_idle_sec)) {
            close(it->second.fd);
            it = g_reply_socks.erase(it);
        } else {
            ++it;
        }
    }
}

int make_tproxy_tcp_listener(const AddrPort& ap, const char* label) {
    const int domain = (ap.af == np::kAf4) ? AF_INET : AF_INET6;
    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::fprintf(stderr, "error: socket(%s): %s\n", label, std::strerror(errno));
        return -1;
    }
    set_sockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    if (ap.af == np::kAf6) {
        set_sockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        if (!set_sockopt_int(fd, SOL_IPV6, IPV6_TRANSPARENT, 1)) {
            std::fprintf(stderr, "error: IPV6_TRANSPARENT(%s): %s\n", label, std::strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        if (!set_sockopt_int(fd, SOL_IP, IP_TRANSPARENT, 1)) {
            std::fprintf(stderr, "error: IP_TRANSPARENT(%s): %s\n", label, std::strerror(errno));
            close(fd);
            return -1;
        }
    }
    sockaddr_storage ss{};
    socklen_t slen = to_sockaddr(ap, ss);
    if (bind(fd, reinterpret_cast<sockaddr*>(&ss), slen) != 0 || listen(fd, 128) != 0) {
        std::fprintf(stderr, "error: bind/listen(%s): %s\n", label, std::strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int make_tproxy_udp_listener(const AddrPort& ap, const char* label) {
    const int domain = (ap.af == np::kAf4) ? AF_INET : AF_INET6;
    int fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::fprintf(stderr, "error: socket(%s): %s\n", label, std::strerror(errno));
        return -1;
    }
    set_sockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    if (ap.af == np::kAf6) {
        set_sockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        if (!set_sockopt_int(fd, SOL_IPV6, IPV6_TRANSPARENT, 1) ||
            !set_sockopt_int(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)) {
            std::fprintf(stderr, "error: IPV6_TRANSPARENT/RECVORIGDSTADDR(%s): %s\n", label,
                         std::strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        if (!set_sockopt_int(fd, SOL_IP, IP_TRANSPARENT, 1) ||
            !set_sockopt_int(fd, SOL_IP, IP_RECVORIGDSTADDR, 1)) {
            std::fprintf(stderr, "error: IP_TRANSPARENT/RECVORIGDSTADDR(%s): %s\n", label,
                         std::strerror(errno));
            close(fd);
            return -1;
        }
    }
    sockaddr_storage ss{};
    socklen_t slen = to_sockaddr(ap, ss);
    if (bind(fd, reinterpret_cast<sockaddr*>(&ss), slen) != 0) {
        std::fprintf(stderr, "error: bind(%s): %s\n", label, std::strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int make_ipc_listener(const AddrPort& ap) {
    const int domain = (ap.af == np::kAf4) ? AF_INET : AF_INET6;
    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    set_sockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    sockaddr_storage ss{};
    socklen_t slen = to_sockaddr(ap, ss);
    if (bind(fd, reinterpret_cast<sockaddr*>(&ss), slen) != 0 || listen(fd, 8) != 0) {
        std::fprintf(stderr, "error: bind/listen IPC %s failed: %s\n",
                     format_ap(ap).c_str(), std::strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

struct ListenerFd {
    int fd = -1;
    AddrPort ap{};
    EpollTag tag{};
};

void print_usage(const char* argv0) {
    std::fprintf(
        stderr,
        "usage: %s [options]\n"
        "  --listen-tcp <ip:port>   IPv4 TPROXY TCP listener (default 127.0.0.1:12345)\n"
        "  --listen-udp <ip:port>   IPv4 TPROXY UDP listener (default 127.0.0.1:12345)\n"
        "  --listen-tcp6 <ip:port>  Optional IPv6 TPROXY TCP listener (e.g. [::1]:12345)\n"
        "  --listen-udp6 <ip:port>  Optional IPv6 TPROXY UDP listener (e.g. [::1]:12345)\n"
        "  --ipc <ip:port>          NFSDK bridge IPC listen address (default 127.0.0.1:19850)\n"
        "  --proc-aliases <path>    Optional linux_name=win_name.exe map\n"
        "  --mark <val>             SO_MARK on outbound/reply sockets (default 0xff)\n"
        "  --udp-idle <sec>         UDP flow idle timeout seconds (default 60)\n"
        "  --nf-timeout <ms>        NFSDK TCP decision fail-open timeout (default 3000)\n"
        "  --bpf-obj <path>         eBPF object (exitlag_direct.bpf.o) for native-direct bypass\n"
        "  --bpf-cgroup <path>      cgroupv2 dir to attach it to (e.g. /sys/fs/cgroup/user.slice/user-1000.slice)\n"
        "  --exitlag-log <path>     ExitLag client.log (per-connection app decisions)\n"
        "  --reprobe <sec>          Re-ask ExitLag for bypassed processes every N s (default 15)\n"
        "  --native-tunnel <path>   Native Linux process names never to bypass\n"
        "  --verbose                Log each new TCP/UDP flow\n",
        argv0);
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* f) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", f);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--listen-tcp") g_cfg.listen_tcp = need("--listen-tcp");
        else if (a == "--listen-udp") g_cfg.listen_udp = need("--listen-udp");
        else if (a == "--listen-tcp6") g_cfg.listen_tcp6 = need("--listen-tcp6");
        else if (a == "--listen-udp6") g_cfg.listen_udp6 = need("--listen-udp6");
        else if (a == "--ipc") g_cfg.ipc = need("--ipc");
        else if (a == "--proc-aliases") g_cfg.proc_aliases_path = need("--proc-aliases");
        else if (a == "--mark") g_cfg.mark = std::strtoul(need("--mark").c_str(), nullptr, 0);
        else if (a == "--udp-idle") g_cfg.udp_idle_sec = std::atoi(need("--udp-idle").c_str());
        else if (a == "--nf-timeout") g_cfg.nf_timeout_ms = std::atoi(need("--nf-timeout").c_str());
        else if (a == "--bpf-obj") g_cfg.bpf_obj = need("--bpf-obj");
        else if (a == "--bpf-cgroup") g_cfg.bpf_cgroup = need("--bpf-cgroup");
        else if (a == "--native-tunnel") g_cfg.native_tunnel_path = need("--native-tunnel");
        else if (a == "--exitlag-log") g_cfg.exitlag_log = need("--exitlag-log");
        else if (a == "--reprobe") g_cfg.reprobe_sec = std::atoi(need("--reprobe").c_str());
        else if (a == "--verbose") g_cfg.verbose = true;
        else if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "unknown option: %s\n", a.c_str());
            return 2;
        }
    }

    load_proc_aliases(g_cfg.proc_aliases_path);
    load_native_tunnel(true);
    if (!g_cfg.bpf_obj.empty() && !setup_bpf_direct()) {
        std::printf("[nf-redir] WARN no kernel bypass: all traffic is relayed and "
                    "decided by ExitLag\n");
    }
    poll_exitlag_log(true);

    AddrPort tcp4_ap{}, udp4_ap{}, tcp6_ap{}, udp6_ap{}, ipc_ap{};
    if (!parse_ip_port(g_cfg.listen_tcp, tcp4_ap) ||
        !parse_ip_port(g_cfg.listen_udp, udp4_ap) ||
        !parse_ip_port(g_cfg.ipc, ipc_ap)) {
        std::fprintf(stderr, "invalid --listen-tcp, --listen-udp, or --ipc address\n");
        return 2;
    }
    if (!g_cfg.listen_tcp6.empty() && !parse_ip_port(g_cfg.listen_tcp6, tcp6_ap)) {
        std::fprintf(stderr, "invalid --listen-tcp6\n");
        return 2;
    }
    if (!g_cfg.listen_udp6.empty() && !parse_ip_port(g_cfg.listen_udp6, udp6_ap)) {
        std::fprintf(stderr, "invalid --listen-udp6\n");
        return 2;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask, nullptr);
    int sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    g_nl_fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (g_nl_fd >= 0) {
        timeval tv{0, 200000};
        setsockopt(g_nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    g_ep = epoll_create1(EPOLL_CLOEXEC);
    if (g_ep < 0) {
        std::perror("epoll_create1");
        return 1;
    }

    std::vector<std::unique_ptr<ListenerFd>> listeners;
    auto add_tcp = [&](const AddrPort& ap, const char* lbl) -> bool {
        int fd = make_tproxy_tcp_listener(ap, lbl);
        if (fd < 0) return false;
        auto l = std::make_unique<ListenerFd>();
        l->fd = fd;
        l->ap = ap;
        l->tag = EpollTag{EpollTag::kTcpListen, l.get()};
        epoll_ctrl_fd(EPOLL_CTL_ADD, fd, EPOLLIN, &l->tag);
        listeners.push_back(std::move(l));
        return true;
    };
    auto add_udp = [&](const AddrPort& ap, const char* lbl) -> bool {
        int fd = make_tproxy_udp_listener(ap, lbl);
        if (fd < 0) return false;
        auto l = std::make_unique<ListenerFd>();
        l->fd = fd;
        l->ap = ap;
        l->tag = EpollTag{EpollTag::kUdpListen, l.get()};
        epoll_ctrl_fd(EPOLL_CTL_ADD, fd, EPOLLIN, &l->tag);
        listeners.push_back(std::move(l));
        return true;
    };

    if (!add_tcp(tcp4_ap, "tcp4") || !add_udp(udp4_ap, "udp4")) return 1;
    if (!g_cfg.listen_tcp6.empty() && !add_tcp(tcp6_ap, "tcp6")) return 1;
    if (!g_cfg.listen_udp6.empty() && !add_udp(udp6_ap, "udp6")) return 1;

    g_ipc_listen_fd = make_ipc_listener(ipc_ap);
    if (g_ipc_listen_fd < 0) return 1;
    epoll_ctrl_fd(EPOLL_CTL_ADD, g_ipc_listen_fd, EPOLLIN, &g_ipc_listen_tag);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    itimerspec its{};
    its.it_interval.tv_sec = 1;
    its.it_value.tv_sec = 1;
    timerfd_settime(tfd, 0, &its, nullptr);
    EpollTag timer_tag{EpollTag::kTimer, nullptr};
    epoll_ctrl_fd(EPOLL_CTL_ADD, tfd, EPOLLIN, &timer_tag);

    EpollTag sig_tag{EpollTag::kSignal, nullptr};
    epoll_ctrl_fd(EPOLL_CTL_ADD, sig_fd, EPOLLIN, &sig_tag);

    std::printf("NF REDIR READY tcp=%s udp=%s ipc=%s\n", g_cfg.listen_tcp.c_str(),
                g_cfg.listen_udp.c_str(), g_cfg.ipc.c_str());

    std::array<epoll_event, 64> evs{};
    while (g_running) {
        int nfds = epoll_wait(g_ep, evs.data(), static_cast<int>(evs.size()), -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < nfds; ++i) {
            auto* tag = static_cast<EpollTag*>(evs[i].data.ptr);
            if (!tag) continue;
            switch (tag->kind) {
                case EpollTag::kTcpListen: {
                    auto* l = static_cast<ListenerFd*>(tag->ptr);
                    on_tcp_accept(l->fd, l->ap);
                    break;
                }
                case EpollTag::kUdpListen: {
                    auto* l = static_cast<ListenerFd*>(tag->ptr);
                    on_udp_tproxy_readable(l->fd);
                    break;
                }
                case EpollTag::kIpcListen:
                    on_ipc_listen_readable();
                    break;
                case EpollTag::kIpcClient:
                    on_ipc_client_events(evs[i].events);
                    break;
                case EpollTag::kTcpClient: {
                    auto* c = static_cast<TcpConn*>(tag->ptr);
                    if (g_tcp_conns.count(c)) handle_tcp_event(c, false, evs[i].events);
                    break;
                }
                case EpollTag::kTcpTarget: {
                    auto* c = static_cast<TcpConn*>(tag->ptr);
                    if (g_tcp_conns.count(c)) handle_tcp_event(c, true, evs[i].events);
                    break;
                }
                case EpollTag::kUdpDirect: {
                    auto* f = static_cast<UdpFlow*>(tag->ptr);
                    on_udp_direct_readable(f);
                    break;
                }
                case EpollTag::kTimer: {
                    std::uint64_t ticks = 0;
                    ssize_t r = read(tfd, &ticks, sizeof(ticks));
                    (void)r;
                    on_timer_tick();
                    break;
                }
                case EpollTag::kSignal: {
                    signalfd_siginfo ssi{};
                    ssize_t r = read(sig_fd, &ssi, sizeof(ssi));
                    (void)r;
                    g_running = false;
                    break;
                }
            }
        }
    }

    auto tcp_copy = g_tcp_conns;
    for (auto& [raw, sp] : tcp_copy) close_tcp_conn(raw);
    std::vector<std::uint64_t> fids;
    for (const auto& [fid, _] : g_udp_by_id) fids.push_back(fid);
    for (std::uint64_t fid : fids) destroy_udp_flow(fid, true);
    for (auto& [_, rs] : g_reply_socks) close(rs.fd);
    close_ipc_client();
    close(g_ipc_listen_fd);
    for (auto& l : listeners) close(l->fd);
    if (g_nl_fd >= 0) close(g_nl_fd);
    close(tfd);
    close(sig_fd);
    close(g_ep);
    return 0;
}
