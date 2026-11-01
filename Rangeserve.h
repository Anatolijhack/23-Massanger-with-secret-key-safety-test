#pragma once
#include <algorithm>
#include <cstddef>
#include <fstream>
#include <optional>
#include <string>

// Не отдаём за один ответ больше этого объёма. Браузер сам запросит следующие куски.
inline constexpr size_t kMaxRangeChunk = 4u * 1024 * 1024;

struct ByteRange
{
    size_t start = 0;
    size_t end = 0;       // включительно
};

enum class RangeResult
{
    None,             // заголовка нет или он непонятный: отдаём файл целиком (200)
    Ok,               // диапазон разобран: отдаём кусок (206)
    Unsatisfiable     // начало за пределами файла: 416
};

inline bool parse_u64(const std::string& s, unsigned long long& out)
{
    if (s.empty() || s.size() > 18) return false;

    unsigned long long v = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (unsigned long long)(c - '0');
    }
    out = v;
    return true;
}

// Поддерживаются формы: bytes=0-499, bytes=500-, bytes=-500.
// Несколько диапазонов через запятую не поддерживаются: по стандарту такой заголовок можно игнорировать.
inline RangeResult parse_range(const std::string& header, size_t size, ByteRange& out)
{
    if (size == 0) return RangeResult::None;

    std::string h;
    for (char c : header)
        if (c != ' ' && c != '\t') h += c;

    if (h.compare(0, 6, "bytes=") != 0) return RangeResult::None;

    const std::string spec = h.substr(6);
    if (spec.find(',') != std::string::npos) return RangeResult::None;

    const size_t dash = spec.find('-');
    if (dash == std::string::npos) return RangeResult::None;

    const std::string a = spec.substr(0, dash);
    const std::string b = spec.substr(dash + 1);

    unsigned long long first = 0, last = 0;

    if (a.empty())
    {
        // bytes=-500: последние 500 байт
        if (!parse_u64(b, last)) return RangeResult::None;
        if (last == 0) return RangeResult::Unsatisfiable;

        out.start = (last >= size) ? 0 : size - (size_t)last;
        out.end = size - 1;
        return RangeResult::Ok;
    }

    if (!parse_u64(a, first)) return RangeResult::None;
    if (first >= size) return RangeResult::Unsatisfiable;

    if (b.empty())
    {
        last = size - 1;
    }
    else
    {
        if (!parse_u64(b, last)) return RangeResult::None;
        if (last < first) return RangeResult::None;      // некорректный диапазон игнорируем
        if (last >= size) last = size - 1;
    }

    out.start = (size_t)first;
    out.end = (size_t)last;
    return RangeResult::Ok;
}

inline std::optional<std::string> read_file_range(const std::string& path, size_t start, size_t len)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;

    in.seekg((std::streamoff)start);

    std::string data(len, '\0');
    in.read(&data[0], (std::streamsize)len);
    data.resize((size_t)in.gcount());

    if (data.empty()) return std::nullopt;
    return data;
}