#include "ipc.h"
namespace ownvpn {
static bool WriteAll(HANDLE h, const void* data, DWORD n) {
    auto p = static_cast<const char*>(data);
    while (n) {
        DWORD wrote = 0;
        if (!::WriteFile(h, p, n, &wrote, nullptr) || !wrote) {
            return false;
        }
        p += wrote;
        n -= wrote;
    }
    return true;
}
static bool ReadAll(HANDLE h, void* data, DWORD n) {
    auto p = static_cast<char*>(data);
    while (n) {
        DWORD got = 0;
        if (!::ReadFile(h, p, n, &got, nullptr) || !got) {
            return false;
        }
        p += got;
        n -= got;
    }
    return true;
}
bool SendPacket(HANDLE pipe, uint32_t type, const std::vector<std::string>& fields) {
    std::string data;
    auto append = [&](uint32_t v) { data.append(reinterpret_cast<const char*>(&v), 4); };
    append(type);
    append(static_cast<uint32_t>(fields.size()));
    for (const auto& field : fields) {
        append(static_cast<uint32_t>(field.size()));
        data += field;
    }
    uint32_t size = static_cast<uint32_t>(data.size());
    bool ok = size <= 65536 && WriteAll(pipe, &size, 4) && WriteAll(pipe, data.data(), size);
    Wipe(data);
    return ok;
}
bool ReceivePacket(HANDLE pipe, uint32_t& type, std::vector<std::string>& fields) {
    uint32_t size = 0;
    fields.clear();
    if (!ReadAll(pipe, &size, 4) || size < 8 || size > 65536) {
        return false;
    }
    std::string data(size, '\0');
    if (!ReadAll(pipe, data.data(), size)) {
        Wipe(data);
        return false;
    }
    size_t pos = 0;
    auto next = [&](uint32_t& v) {
        if (pos + 4 > data.size()) {
            return false;
        }
        memcpy(&v, data.data() + pos, 4);
        pos += 4;
        return true;
    };
    uint32_t count = 0;
    bool ok = next(type) && next(count) && count <= 16;
    for (uint32_t i = 0; ok && i < count; ++i) {
        uint32_t n = 0;
        ok = next(n) && n <= data.size() - pos;
        if (ok) {
            fields.emplace_back(data.substr(pos, n));
            pos += n;
        }
    }
    ok = ok && pos == data.size();
    Wipe(data);
    if (!ok) {
        for (auto& f : fields) {
            Wipe(f);
        }
        fields.clear();
    }
    return ok;
}
bool PipeReady(HANDLE pipe) {
    DWORD n = 0;
    return PeekNamedPipe(pipe, nullptr, 0, nullptr, &n, nullptr) && n >= 4;
}
} // namespace ownvpn
