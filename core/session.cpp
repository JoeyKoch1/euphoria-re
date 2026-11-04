#include <algorithm>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <vector>

#include "db.h"
#include "euphoria.h"
#include "scan.h"

struct EuSession {
    std::unique_ptr<EuDb, decltype(&eu_db_destroy)> db{eu_db_create(), &eu_db_destroy};
};

namespace {

constexpr uint8_t kX64Prologue[] = {0x55, 0x48, 0x89, 0xE5};
constexpr uint8_t kX86Prologue[] = {0x55, 0x8B, 0xEC};
constexpr uint8_t kX86PrologueAlt[] = {0x55, 0x89, 0xE5};

std::span<const EuSection> sections_of(const EuImage& image) {
    return {image.sections, image.section_count};
}

std::span<const uint8_t> bytes_of(const EuImage& image, const EuSection& section) {
    if (section.offset >= image.data_len) {
        return {};
    }
    const auto available = image.data_len - section.offset;
    return {image.data + section.offset, std::min<uint64_t>(section.size, available)};
}

const EuSection* executable_section_at(const EuImage& image, uint64_t va) {
    for (const auto& section : sections_of(image)) {
        if (section.executable && va >= section.va && va - section.va < section.size) {
            return &section;
        }
    }
    return nullptr;
}

void scan_prologues(const EuImage& image,
                    const EuSection& section,
                    std::span<const uint8_t> pattern,
                    std::vector<uint64_t>& found) {
    const auto bytes = bytes_of(image, section);
    size_t at = 0;
    while (at < bytes.size()) {
        const auto rest = bytes.subspan(at);
        const auto hit = eu_scan_pattern(rest.data(), rest.size(), pattern.data(), pattern.size());
        if (hit == rest.size()) {
            return;
        }
        found.push_back(section.va + at + hit);
        at += hit + pattern.size();
    }
}

std::vector<uint64_t> discover(const EuImage& image) {
    std::vector<uint64_t> found(image.seeds, image.seeds + image.seed_count);
    found.push_back(image.entry);

    for (const auto& section : sections_of(image)) {
        if (!section.executable) {
            continue;
        }
        if (image.arch == EU_ARCH_X86_64) {
            scan_prologues(image, section, kX64Prologue, found);
        } else if (image.arch == EU_ARCH_X86) {
            scan_prologues(image, section, kX86Prologue, found);
            scan_prologues(image, section, kX86PrologueAlt, found);
        }
    }

    std::erase_if(found, [&](uint64_t va) { return !executable_section_at(image, va); });
    std::ranges::sort(found);
    found.erase(std::unique(found.begin(), found.end()), found.end());
    return found;
}

EuStatus store(EuDb* db, const EuImage& image, const std::vector<uint64_t>& starts) {
    for (size_t i = 0; i < starts.size(); i++) {
        const auto va = starts[i];
        const auto* section = executable_section_at(image, va);
        auto size = section->size - (va - section->va);
        if (i + 1 < starts.size()) {
            size = std::min(size, starts[i + 1] - va);
        }
        if (const auto status = eu_db_add_function(db, {va, size}); status != EU_STATUS_OK) {
            return status;
        }
    }
    return EU_STATUS_OK;
}

}

EuStatus eu_session_analyze(const EuImage* image, EuSession** out) {
    if (!image || !out) {
        return EU_STATUS_INVALID_ARGUMENT;
    }

    try {
        auto session = std::make_unique<EuSession>();
        if (!session->db) {
            return EU_STATUS_OUT_OF_MEMORY;
        }
        if (const auto status = store(session->db.get(), *image, discover(*image)); status != EU_STATUS_OK) {
            return status;
        }
        *out = session.release();
        return EU_STATUS_OK;
    } catch (const std::bad_alloc&) {
        return EU_STATUS_OUT_OF_MEMORY;
    } catch (...) {
        return EU_STATUS_INTERNAL;
    }
}

const EuFunction* eu_session_functions(const EuSession* session, size_t* count) {
    return eu_db_functions(session->db.get(), count);
}

EuStatus eu_session_save(const EuSession* session, const char* path) {
    if (!session || !path) {
        return EU_STATUS_INVALID_ARGUMENT;
    }
    return eu_db_save(session->db.get(), path);
}

void eu_session_free(EuSession* session) {
    delete session;
}
