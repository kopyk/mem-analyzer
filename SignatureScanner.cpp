#include <vector>
#include <string>
#include <sstream>
#include <optional>
#include <cctype>
#include <windows.h>
#include <Psapi.h>
#include "SignatureScanner.h"

using std::string;

namespace sa_utils_ex {
    std::vector<std::string> splitString(std::string str, char delim) {
        std::vector<std::string> retVal;
        std::istringstream split(str);
        for (std::string each; std::getline(split, each, delim);) retVal.push_back(each);
        return retVal;
    }
}

namespace {
    struct ParsedSig {
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;
        std::vector<size_t> fixedIdx;
        size_t sigSize{};
        std::optional<size_t> anchorIdx;
        uint8_t anchorByte{};
    };

    inline bool isWildcardToken(const std::string& s) {
        return (s == "?" || s == "??");
    }

    ParsedSig parsePattern(const std::string& pattern) {
        auto parts = sa_utils_ex::splitString(pattern, ' ');
        ParsedSig ps;
        ps.bytes.resize(parts.size());
        ps.mask.resize(parts.size());
        ps.sigSize = parts.size();

        for (size_t i = 0; i < parts.size(); ++i) {
            const auto& tok = parts[i];
            if (isWildcardToken(tok)) {
                ps.bytes[i] = 0;
                ps.mask[i] = 0;
            }
            else {
                ps.bytes[i] = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                ps.mask[i] = 1;
                ps.fixedIdx.push_back(i);
            }
        }
        if (!ps.fixedIdx.empty()) {
            ps.anchorIdx = ps.fixedIdx.back();
            ps.anchorByte = ps.bytes[*ps.anchorIdx];
        }
        else {
            ps.anchorIdx.reset();
        }
        return ps;
    }

    inline bool matchAt(const uint8_t* ptr, const ParsedSig& ps) {
        for (size_t idx : ps.fixedIdx) {
            if (ptr[idx] != ps.bytes[idx]) return false;
        }
        return true;
    }

    inline const uint8_t* findAnchor(const uint8_t* cur, const uint8_t* end, uint8_t anchor) {
        return static_cast<const uint8_t*>(std::memchr(cur, anchor, static_cast<size_t>(end - cur)));
    }

    struct Region { uintptr_t start; uintptr_t end; };
    std::vector<Region> queryReadableRegions(uintptr_t begin, uintptr_t end) {
        std::vector<Region> regions;
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = begin;
        while (addr < end && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            uintptr_t rStart = std::max<uintptr_t>(addr, reinterpret_cast<uintptr_t>(mbi.BaseAddress));
            uintptr_t rEnd = rStart + mbi.RegionSize;
            if (rEnd > end) rEnd = end;

            bool readable =
                (mbi.State == MEM_COMMIT) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                !(mbi.Protect & PAGE_GUARD);

            if (readable && rEnd > rStart) {
                regions.push_back({ rStart, rEnd });
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return regions;
    }

    std::vector<Region> queryReadableRegionsEx(HANDLE hProcess, uintptr_t begin, uintptr_t end) {
        std::vector<Region> regions;
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = begin;
        while (addr < end && VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            uintptr_t rStart = std::max<uintptr_t>(addr, reinterpret_cast<uintptr_t>(mbi.BaseAddress));
            uintptr_t rEnd = rStart + mbi.RegionSize;
            if (rEnd > end) rEnd = end;

            bool readable =
                (mbi.State == MEM_COMMIT) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                !(mbi.Protect & PAGE_GUARD);

            if (readable && rEnd > rStart) {
                regions.push_back({ rStart, rEnd });
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return regions;
    }
}

SignatureScanner::SignatureScanner(uintptr_t start, uintptr_t end) {
    this->startAddress = start;
    this->endAddress = end;
}

SignatureScanner::SignatureScanner(HANDLE hProcess, uintptr_t start, uintptr_t end) {
    this->startAddress = start;
    this->endAddress = end;
    this->hProcess = hProcess;
}

uintptr_t SignatureScanner::scan(std::string pattern, int skips) {
    const ParsedSig ps = parsePattern(pattern);
    if (ps.sigSize == 0) return 0;

    if (!ps.anchorIdx.has_value()) {
        auto regions = queryReadableRegions(this->startAddress, this->endAddress);
        for (const auto& r : regions) {
            if (r.end - r.start >= ps.sigSize) {
                if (skips-- == 0) return r.start;
            }
        }
        return 0;
    }

    const auto regions = queryReadableRegions(this->startAddress, this->endAddress);
    const size_t sigSize = ps.sigSize;
    const size_t anchor = *ps.anchorIdx;

    for (const auto& reg : regions) {
        if (reg.end - reg.start < sigSize) continue;
        const uint8_t* base = reinterpret_cast<const uint8_t*>(reg.start);
        const uint8_t* last = reinterpret_cast<const uint8_t*>(reg.end - sigSize + 1);

        const uint8_t* p = base;
        while (p <= last) {
            const uint8_t* hit = findAnchor(p + anchor, last + anchor, ps.anchorByte);
            if (!hit) break;
            const uint8_t* cand = hit - anchor;
            if (matchAt(cand, ps)) {
                if (skips-- == 0) {
                    return reinterpret_cast<uintptr_t>(cand);
                }
            }
            p = cand + 1;
        }
    }
    return 0;
}

uintptr_t SignatureScanner::scanEx(std::string pattern, int skips) {
    const ParsedSig ps = parsePattern(pattern);
    if (ps.sigSize == 0 || !this->hProcess) return 0;

    const auto regions = queryReadableRegionsEx(this->hProcess, this->startAddress, this->endAddress);
    const size_t sigSize = ps.sigSize;
    constexpr size_t CHUNK = 1 << 20;

    std::vector<uint8_t> buf;
    buf.resize(CHUNK + sigSize - 1);

    for (const auto& reg : regions) {
        uintptr_t cur = reg.start;
        const uintptr_t end = reg.end;

        if (end - cur < sigSize) continue;

        while (cur < end) {
            size_t toRead = std::min<size_t>(CHUNK + sigSize - 1, static_cast<size_t>(end - cur));
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(this->hProcess, reinterpret_cast<LPCVOID>(cur), buf.data(), toRead, &bytesRead) || bytesRead < sigSize) {
                SYSTEM_INFO si{};
                GetSystemInfo(&si);
                cur = (cur + si.dwPageSize) & ~(uintptr_t(si.dwPageSize) - 1);
                continue;
            }

            const uint8_t* base = buf.data();
            const uint8_t* last = base + bytesRead - sigSize + 1;

            if (!ps.anchorIdx.has_value()) {
                for (const uint8_t* cand = base; cand <= last; ++cand) {
                    if (skips-- == 0) return cur + static_cast<uintptr_t>(cand - base);
                }
            }
            else {
                const size_t anchor = *ps.anchorIdx;
                const uint8_t* p = base;
                while (p <= last) {
                    const uint8_t* hit = findAnchor(p + anchor, last + anchor, ps.anchorByte);
                    if (!hit) break;
                    const uint8_t* cand = hit - anchor;
                    if (matchAt(cand, ps)) {
                        if (skips-- == 0) {
                            return cur + static_cast<uintptr_t>(cand - base);
                        }
                    }
                    p = cand + 1;
                }
            }

            if (bytesRead > sigSize - 1) {
                cur += (bytesRead - (sigSize - 1));
            }
            else {
                cur += bytesRead;
            }
        }
    }
    return 0;
}