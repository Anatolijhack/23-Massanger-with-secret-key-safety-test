#pragma once
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>

#include "Atachments.h"
#include "BlockCrypto.h"
#include "Сrypto.h"

// Зашифрованные файлы лежат в отдельной папке под теми же именами, что и обычные.
// Старые незашифрованные остаются в uploads/chat, пока не будут перенесены.
//
// Форматы зашифрованных файлов (определяются по первому байту):
//   1: файл целиком одной записью Crypto (старый вариант, расшифровывается весь целиком)
//   2: блочный формат BlockCrypto (новые файлы, расшифровываются только нужные блоки)
inline const std::string kPlainDir = "uploads/chat";
inline const std::string kEncDir = "uploads_enc/chat";

inline std::optional<std::string> read_all(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;

    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) return std::nullopt;
    return data;
}

// Пишет во временный файл и переименовывает: при сбое не остаётся наполовину записанный файл
inline bool write_all(const std::string& path, const std::string& data)
{
    namespace fs = std::filesystem;
    const std::string tmp = path + ".tmp";

    {
        std::ofstream out(tmp, std::ios::binary);
        if (!out) return false;
        out.write(data.data(), (std::streamsize)data.size());
        out.close();
        if (!out) { std::error_code rm; fs::remove(tmp, rm); return false; }
    }

    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) { std::error_code rm; fs::remove(tmp, rm); return false; }
    return true;
}

inline std::string enc_path_for(const std::string& stored_name) { return kEncDir + "/" + stored_name; }
inline std::string plain_path_for(const std::string& stored_name) { return kPlainDir + "/" + stored_name; }

inline bool encrypted_upload_exists(const std::string& stored_name)
{
    std::error_code ec;
    return std::filesystem::exists(enc_path_for(stored_name), ec);
}

// Первый байт файла: 1 (старый формат), 2 (блочный) или 0 (файл не читается или формат неизвестен)
inline int encrypted_format(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return 0;

    char c = 0;
    in.read(&c, 1);
    if (in.gcount() != 1) return 0;

    const unsigned char b = (unsigned char)c;
    return (b == Crypto::kVersion || b == blockfile::kVersion) ? (int)b : 0;
}

// Источник содержимого зашифрованного файла. Размер известен без расшифровки,
// байты отдаются по запросу: у блочного формата читаются только нужные блоки.
class UploadSource
{
public:
    // nullopt: файла нет, формат неизвестен, файл повреждён или подменён
    static std::optional<UploadSource> open_encrypted(const std::string& stored_name)
    {
        const std::string path = enc_path_for(stored_name);
        const int fmt = encrypted_format(path);

        UploadSource s;
        s.name = stored_name;
        s.path = path;

        if (fmt == blockfile::kVersion)
        {
            auto h = blockfile::read_header(path);
            if (!h) return std::nullopt;

            s.block = true;
            s.header = std::move(*h);
            s.total = (size_t)s.header.plain_len;
            return s;
        }

        if (fmt == Crypto::kVersion)
        {
            // старый формат: расшифровываем целиком, дальше режем из памяти
            auto blob = read_all(path);
            if (!blob) return std::nullopt;

            auto plain = crypto().decrypt(*blob, aad_file(stored_name));
            if (!plain || plain->empty()) return std::nullopt;

            s.whole = std::move(*plain);
            s.total = s.whole.size();
            return s;
        }

        return std::nullopt;
    }

    size_t size() const { return total; }

    // байты [start, start + len); nullopt: диапазон вне файла или блок не прошёл проверку
    std::optional<std::string> read(size_t start, size_t len) const
    {
        if (len == 0 || start >= total || len > total - start) return std::nullopt;
        if (block) return blockfile::decrypt_range(path, name, header, start, len);
        return whole.substr(start, len);
    }

private:
    bool block = false;
    blockfile::Header header;
    std::string name;
    std::string path;
    std::string whole;
    size_t total = 0;
};

// Содержимое зашифрованного файла целиком в открытом виде
inline std::optional<std::string> read_encrypted_upload(const std::string& stored_name)
{
    auto src = UploadSource::open_encrypted(stored_name);
    if (!src) return std::nullopt;
    return src->read(0, src->size());
}

// Сохраняет новый файл зашифрованным в блочном формате. false: шифрование или запись не удались.
inline bool save_encrypted_upload(const std::string& stored_name, const char* data, size_t size)
{
    std::error_code ec;
    std::filesystem::create_directories(kEncDir, ec);
    if (ec) return false;

    auto blob = blockfile::encrypt_file(stored_name, data, size);
    if (!blob) return false;

    return write_all(enc_path_for(stored_name), *blob);
}

// Переносит старые открытые файлы в зашифрованную папку (сразу в блочном формате).
// Исходный файл удаляется только после успешной записи.
inline int migrate_legacy_files()
{
    namespace fs = std::filesystem;
    if (!crypto().enabled()) return 0;

    std::error_code ec;
    fs::create_directories(kEncDir, ec);

    int done = 0;

    for (fs::directory_iterator it(kPlainDir, ec), end; !ec && it != end; it.increment(ec))
    {
        if (!it->is_regular_file(ec)) continue;

        const std::string name = it->path().filename().string();
        if (!is_valid_attachment_url("/uploads/chat/" + name)) continue;     // чужие файлы не трогаем

        auto data = read_all(it->path().string());
        if (!data || data->empty()) continue;

        auto blob = blockfile::encrypt_file(name, data->data(), data->size());
        if (!blob) continue;

        if (!write_all(enc_path_for(name), *blob)) continue;

        std::error_code rm;
        fs::remove(it->path(), rm);
        ++done;
    }

    return done;
}

// Переводит уже зашифрованные файлы старого формата (1) в блочный (2).
// Перезапись идёт через временный файл, при сбое остаётся прежний файл.
inline int upgrade_encrypted_files()
{
    namespace fs = std::filesystem;
    if (!crypto().enabled()) return 0;

    std::error_code ec;
    int done = 0;

    for (fs::directory_iterator it(kEncDir, ec), end; !ec && it != end; it.increment(ec))
    {
        if (!it->is_regular_file(ec)) continue;

        const std::string name = it->path().filename().string();
        if (!is_valid_attachment_url("/uploads/chat/" + name)) continue;
        if (encrypted_format(it->path().string()) != Crypto::kVersion) continue;

        auto plain = read_encrypted_upload(name);
        if (!plain || plain->empty()) continue;

        auto blob = blockfile::encrypt_file(name, plain->data(), plain->size());
        if (!blob) continue;

        if (write_all(it->path().string(), *blob)) ++done;
    }

    return done;
}