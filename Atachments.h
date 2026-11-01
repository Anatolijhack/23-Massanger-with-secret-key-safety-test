#pragma once
#include <cstddef>
#include <cstring>
#include <string>
#include <nlohmann/json.hpp>

// ќдин список разрешЄнных типов вложений. „тобы добавить формат, допишите строку.
struct FileType
{
    const char* mime;
    const char* ext;        // у каждого формата своЄ расширение: по нему сервер выбирает тип при отдаче
    const char* kind;       // image, audio, video, file (клиент по нему выбирает, как показывать)
    size_t max_size;
    bool inline_ok;         // true: отдаЄтс€ со своим типом (картинки, аудио, видео), false: только скачивание
};

inline const FileType kFileTypes[] = {
    // картинки
    { "image/jpeg",      ".jpg",  "image", 10u * 1024 * 1024, true },
    { "image/png",       ".png",  "image", 10u * 1024 * 1024, true },
    { "image/webp",      ".webp", "image", 10u * 1024 * 1024, true },

    // голосовые сообщени€ (MediaRecorder: Chrome и Firefox дают webm или ogg, Safari mp4)
    { "audio/webm",      ".weba", "audio", 10u * 1024 * 1024, true },
    { "audio/ogg",       ".ogg",  "audio", 10u * 1024 * 1024, true },
    { "audio/mp4",       ".m4a",  "audio", 10u * 1024 * 1024, true },
    { "audio/mpeg",      ".mp3",  "audio", 10u * 1024 * 1024, true },

    // видео и видеосообщени€
    { "video/webm",      ".webm", "video", 30u * 1024 * 1024, true },
    { "video/mp4",       ".mp4",  "video", 30u * 1024 * 1024, true },

    // документы: только скачивание, браузер их не открывает
    { "application/pdf", ".pdf",  "file",  20u * 1024 * 1024, false },
    { "text/plain",      ".txt",  "file",   5u * 1024 * 1024, false },
    { "application/zip", ".zip",  "file",  20u * 1024 * 1024, false },
};

inline const FileType* find_type_by_mime(const std::string& mime)
{
    for (const auto& t : kFileTypes)
        if (mime == t.mime) return &t;
    return nullptr;
}

inline const FileType* find_type_by_ext(const std::string& ext)
{
    for (const auto& t : kFileTypes)
        if (ext == t.ext) return &t;
    return nullptr;
}

// —амый большой лимит из таблицы: дл€ ранней проверки размера всего тела запроса
inline size_t max_upload_size()
{
    size_t m = 0;
    for (const auto& t : kFileTypes)
        if (t.max_size > m) m = t.max_size;
    return m;
}

// јдрес вложени€: /uploads/chat/<16 hex в нижнем регистре><расширение из таблицы>
inline bool is_valid_attachment_url(const std::string& url)
{
    static const std::string prefix = "/uploads/chat/";
    if (url.compare(0, prefix.size(), prefix) != 0) return false;

    const std::string name = url.substr(prefix.size());
    if (name.size() <= 16) return false;

    for (size_t i = 0; i < 16; ++i)
    {
        const char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }

    return find_type_by_ext(name.substr(16)) != nullptr;
}

// “ип приходит от клиента, поэтому провер€ем и начало самого файла
inline bool matches_signature(const std::string& mime, const char* d, size_t n)
{
    const unsigned char* u = reinterpret_cast<const unsigned char*>(d);

    if (mime == "image/jpeg")
        return n >= 3 && u[0] == 0xFF && u[1] == 0xD8 && u[2] == 0xFF;

    if (mime == "image/png")
        return n >= 8 && std::memcmp(d, "\x89PNG\r\n\x1A\n", 8) == 0;

    if (mime == "image/webp")
        return n >= 12 && std::memcmp(d, "RIFF", 4) == 0 && std::memcmp(d + 8, "WEBP", 4) == 0;

    // webm (и аудио, и видео) начинаетс€ с заголовка EBML
    if (mime == "audio/webm" || mime == "video/webm")
        return n >= 4 && u[0] == 0x1A && u[1] == 0x45 && u[2] == 0xDF && u[3] == 0xA3;

    if (mime == "audio/ogg")
        return n >= 4 && std::memcmp(d, "OggS", 4) == 0;

    // mp4 и m4a: после 4 байт длины идЄт "ftyp"
    if (mime == "audio/mp4" || mime == "video/mp4")
        return n >= 12 && std::memcmp(d + 4, "ftyp", 4) == 0;

    // mp3: либо тег ID3, либо синхронизаци€ кадра (11 единичных бит)
    if (mime == "audio/mpeg")
        return n >= 3 && (std::memcmp(d, "ID3", 3) == 0 || (u[0] == 0xFF && (u[1] & 0xE0) == 0xE0));

    if (mime == "application/pdf")
        return n >= 5 && std::memcmp(d, "%PDF-", 5) == 0;

    if (mime == "application/zip")
        return n >= 4 && std::memcmp(d, "PK\x03\x04", 4) == 0;

    // у текста сигнатуры нет: провер€ем, что нет нулевых байтов
    if (mime == "text/plain")
        return std::memchr(d, 0, n) == nullptr;

    return false;
}
inline const char* kind_for_url(const std::string& url)
{
    const size_t dot = url.find_last_of('.');
    if (dot == std::string::npos) return nullptr;

    const FileType* t = find_type_by_ext(url.substr(dot));
    return t ? t->kind : nullptr;
}
inline void add_attachment_meta(nlohmann::json& item, const std::string& url, long duration_ms)
{
    if (const char* kind = kind_for_url(url)) item["attachment_kind"] = kind;
    if (duration_ms > 0) item["attachment_duration"] = duration_ms;
}