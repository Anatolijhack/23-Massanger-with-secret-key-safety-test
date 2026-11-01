#pragma once
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "Сrypto.h"

// Блочный формат зашифрованного файла (версия 2). Каждый блок шифруется отдельно,
// поэтому для диапазона байт расшифровываются только нужные блоки.
//
//   [1 байт версия = 2][1 байт id ключа][4 байта размер блока][8 байт длина исходного файла][16 байт соль]
//   затем блоки: [шифротекст блока][16 байт тег]. Все блоки, кроме последнего, одной длины.
//
// Что защищает от подмены:
//   - ключ файла получается из мастер-ключа и случайной соли, у каждого файла он свой;
//   - nonce блока = его номер, повторов с одним ключом нет;
//   - в проверяемые данные (AAD) каждого блока входят весь заголовок, имя файла, номер блока
//     и признак «последний блок»: блоки нельзя переставить, дублировать, перенести в другой
//     файл или обрезать конец;
//   - размер файла на диске должен точно совпадать с рассчитанным по заголовку.
namespace blockfile
{
    inline constexpr uint8_t kVersion = 2;
    inline constexpr size_t kChunkSize = 64 * 1024;
    inline constexpr size_t kTag = 16;
    inline constexpr size_t kSalt = 16;
    inline constexpr size_t kHeaderLen = 2 + 4 + 8 + kSalt;                 // 30
    inline constexpr uint64_t kMaxPlain = 256ull * 1024 * 1024;             // страховка от подменённого заголовка

    struct Header
    {
        int key_id = 0;
        uint32_t chunk_size = 0;
        uint64_t plain_len = 0;
        std::string salt;
        std::string raw;                // заголовок как на диске (входит в AAD)

        uint64_t chunks() const { return plain_len == 0 ? 0 : (plain_len + chunk_size - 1) / chunk_size; }
        uint64_t file_size() const { return kHeaderLen + plain_len + chunks() * kTag; }
    };

    struct CtxDeleter { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
    using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

    inline void put_be32(std::string& s, size_t pos, uint32_t v)
    {
        for (int i = 0; i < 4; ++i) s[pos + i] = (char)((v >> (24 - 8 * i)) & 0xFF);
    }

    inline void put_be64(std::string& s, size_t pos, uint64_t v)
    {
        for (int i = 0; i < 8; ++i) s[pos + i] = (char)((v >> (56 - 8 * i)) & 0xFF);
    }

    inline uint32_t get_be32(const std::string& s, size_t pos)
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | (unsigned char)s[pos + i];
        return v;
    }

    inline uint64_t get_be64(const std::string& s, size_t pos)
    {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | (unsigned char)s[pos + i];
        return v;
    }

    // nonce блока: 4 нулевых байта и номер блока
    inline void chunk_nonce(uint64_t index, unsigned char nonce[12])
    {
        std::memset(nonce, 0, 12);
        for (int i = 0; i < 8; ++i) nonce[4 + i] = (unsigned char)((index >> (56 - 8 * i)) & 0xFF);
    }

    inline std::string chunk_aad(const std::string& header_raw, const std::string& stored_name,
        uint64_t index, bool last)
    {
        std::string a = header_raw + stored_name;
        const size_t pos = a.size();
        a.resize(pos + 9);
        put_be64(a, pos, index);
        a[pos + 8] = last ? 1 : 0;
        return a;
    }

    inline bool gcm_seal(const std::string& key, const unsigned char* nonce, const std::string& aad,
        const unsigned char* in, size_t n, unsigned char* out, unsigned char* tag)
    {
        CtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return false;

        int len = 0;
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return false;
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), nonce) != 1) return false;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len,
            reinterpret_cast<const unsigned char*>(aad.data()), (int)aad.size()) != 1) return false;
        if (n > 0 && EVP_EncryptUpdate(ctx.get(), out, &len, in, (int)n) != 1) return false;

        int fin = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), out + n, &fin) != 1) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)kTag, tag) != 1) return false;
        return true;
    }

    inline bool gcm_open(const std::string& key, const unsigned char* nonce, const std::string& aad,
        const unsigned char* in, size_t n, const unsigned char* tag, unsigned char* out)
    {
        CtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return false;

        int len = 0;
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return false;
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), nonce) != 1) return false;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len,
            reinterpret_cast<const unsigned char*>(aad.data()), (int)aad.size()) != 1) return false;
        if (n > 0 && EVP_DecryptUpdate(ctx.get(), out, &len, in, (int)n) != 1) return false;

        unsigned char t[kTag];
        std::memcpy(t, tag, kTag);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)kTag, t) != 1) return false;

        int fin = 0;
        return EVP_DecryptFinal_ex(ctx.get(), out + n, &fin) > 0;      // здесь проверяется тег блока
    }

    // Весь зашифрованный файл одной строкой, готовой к записи на диск
    inline std::optional<std::string> encrypt_file(const std::string& stored_name, const char* data, size_t size)
    {
        if (!crypto().enabled() || size == 0 || size > (size_t)kMaxPlain) return std::nullopt;

        Header h;
        h.key_id = crypto().active_key_id();
        h.chunk_size = (uint32_t)kChunkSize;
        h.plain_len = size;

        unsigned char salt[kSalt];
        if (RAND_bytes(salt, (int)kSalt) != 1) return std::nullopt;
        h.salt.assign(reinterpret_cast<const char*>(salt), kSalt);

        h.raw.assign(kHeaderLen, '\0');
        h.raw[0] = (char)kVersion;
        h.raw[1] = (char)(unsigned char)h.key_id;
        put_be32(h.raw, 2, h.chunk_size);
        put_be64(h.raw, 6, h.plain_len);
        std::memcpy(&h.raw[14], salt, kSalt);

        std::string key;
        if (!crypto().derive_file_key(h.key_id, h.salt, key)) return std::nullopt;

        std::string out;
        out.resize((size_t)h.file_size());
        std::memcpy(&out[0], h.raw.data(), kHeaderLen);

        const uint64_t n = h.chunks();
        size_t off = kHeaderLen;

        for (uint64_t i = 0; i < n; ++i)
        {
            const size_t pos = (size_t)(i * h.chunk_size);
            const size_t len = (std::min)((size_t)h.chunk_size, size - pos);
            const bool last = (i + 1 == n);

            unsigned char nonce[12];
            chunk_nonce(i, nonce);

            unsigned char tag[kTag];
            if (!gcm_seal(key, nonce, chunk_aad(h.raw, stored_name, i, last),
                reinterpret_cast<const unsigned char*>(data) + pos, len,
                reinterpret_cast<unsigned char*>(&out[off]), tag)) return std::nullopt;

            std::memcpy(&out[off + len], tag, kTag);
            off += len + kTag;
        }

        return out;
    }

    // Читает и проверяет заголовок. nullopt: файла нет, это не блочный формат,
    // заголовок неверный или размер файла не совпадает с ожидаемым (обрезан, дописан).
    inline std::optional<Header> read_header(const std::string& path)
    {
        std::error_code ec;
        const uintmax_t size = std::filesystem::file_size(path, ec);
        if (ec || size < kHeaderLen) return std::nullopt;

        std::ifstream in(path, std::ios::binary);
        if (!in) return std::nullopt;

        std::string raw(kHeaderLen, '\0');
        in.read(&raw[0], (std::streamsize)kHeaderLen);
        if ((size_t)in.gcount() != kHeaderLen) return std::nullopt;

        if ((unsigned char)raw[0] != kVersion) return std::nullopt;

        Header h;
        h.raw = raw;
        h.key_id = (unsigned char)raw[1];
        h.chunk_size = get_be32(raw, 2);
        h.plain_len = get_be64(raw, 6);
        h.salt = raw.substr(14, kSalt);

        // подменённый заголовок не должен заставить нас выделять огромные буферы
        if (h.chunk_size < 4096 || h.chunk_size > 1024 * 1024) return std::nullopt;
        if (h.plain_len == 0 || h.plain_len > kMaxPlain) return std::nullopt;
        if (h.file_size() != (uint64_t)size) return std::nullopt;

        return h;
    }

    // Расшифровывает байты [start, start + len) исходного файла, читая с диска только нужные блоки.
    // nullopt: диапазон вне файла, нет ключа, блок повреждён или подменён.
    inline std::optional<std::string> decrypt_range(const std::string& path, const std::string& stored_name,
        const Header& h, size_t start, size_t len)
    {
        if (len == 0 || start >= h.plain_len || len > h.plain_len - start) return std::nullopt;

        std::string key;
        if (!crypto().derive_file_key(h.key_id, h.salt, key)) return std::nullopt;

        const uint64_t n_chunks = h.chunks();
        const uint64_t first = start / h.chunk_size;
        const uint64_t last_idx = (start + len - 1) / h.chunk_size;
        const uint64_t block = (uint64_t)h.chunk_size + kTag;

        // сколько байт на диске занимают нужные блоки
        const uint64_t disk_start = kHeaderLen + first * block;
        const uint64_t disk_end = (last_idx + 1 == n_chunks) ? h.file_size() : kHeaderLen + (last_idx + 1) * block;

        std::string disk((size_t)(disk_end - disk_start), '\0');
        {
            std::ifstream in(path, std::ios::binary);
            if (!in) return std::nullopt;
            in.seekg((std::streamoff)disk_start);
            in.read(&disk[0], (std::streamsize)disk.size());
            if ((size_t)in.gcount() != disk.size()) return std::nullopt;
        }

        std::string plain;
        plain.reserve((size_t)((last_idx - first + 1) * h.chunk_size));

        size_t pos = 0;
        for (uint64_t i = first; i <= last_idx; ++i)
        {
            const bool last = (i + 1 == n_chunks);
            const size_t ct_len = last ? (size_t)(h.plain_len - i * h.chunk_size) : (size_t)h.chunk_size;

            if (pos + ct_len + kTag > disk.size()) return std::nullopt;

            unsigned char nonce[12];
            chunk_nonce(i, nonce);

            const unsigned char* ct = reinterpret_cast<const unsigned char*>(disk.data()) + pos;
            const unsigned char* tag = ct + ct_len;

            const size_t at = plain.size();
            plain.resize(at + ct_len);

            if (!gcm_open(key, nonce, chunk_aad(h.raw, stored_name, i, last), ct, ct_len, tag,
                reinterpret_cast<unsigned char*>(&plain[at]))) return std::nullopt;

            pos += ct_len + kTag;
        }

        const size_t skip = (size_t)(start - first * h.chunk_size);
        return plain.substr(skip, len);
    }
}