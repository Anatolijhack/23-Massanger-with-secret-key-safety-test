#pragma once
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

// Шифрование данных «в покое» на стороне сервера (AES-256-GCM).
//
// Формат зашифрованной записи (бинарная строка):
//   [1 байт версия формата][1 байт id ключа][12 байт nonce][шифротекст][16 байт тег]
//
// Версия и id ключа лежат в каждой записи, поэтому ключи можно менять без остановки:
// новые данные шифруются активным ключом, старые читаются тем ключом, которым были записаны.
//
// aad (контекст) не хранится, а проверяется при расшифровке: зашифрованное тело
// нельзя незаметно перенести в другую строку или чат.
//
// Ключи берутся из переменных окружения, в коде и в базе их нет:
//   CHAT_KEYS        = "1:<64 hex>,2:<64 hex>"   (id от 1 до 255, ключ 32 байта в hex)
//   CHAT_KEY_ACTIVE  = "2"                        (каким ключом шифровать новое)
class Crypto
{
public:
    static constexpr uint8_t kVersion = 1;
    static constexpr size_t kNonceLen = 12;
    static constexpr size_t kTagLen = 16;
    static constexpr size_t kKeyLen = 32;
    static constexpr size_t kHeaderLen = 2 + kNonceLen;

    ~Crypto()
    {
        for (auto& kv : keys)
            if (!kv.second.empty()) OPENSSL_cleanse(&kv.second[0], kv.second.size());
    }

    // Ключи из переменных окружения CHAT_KEYS и CHAT_KEY_ACTIVE
    bool init_from_env(std::string& error)
    {
        return init_from_strings(env_get("CHAT_KEYS"), env_get("CHAT_KEY_ACTIVE"), error);
    }

    // keys_env: "1:<64 hex>,2:<64 hex>", active_env: "2". Строки может отдать любое хранилище
    // секретов (файл ключей, менеджер секретов), поэтому модуль не привязан к окружению.
    // false: ключей нет или они заданы неверно (причина в error). Шифрование при этом выключено.
    bool init_from_strings(const std::string& keys_env, const std::string& active_env, std::string& error)
    {
        keys.clear();
        active_id = 0;

        if (keys_env.empty()) { error = "ключи не заданы"; return false; }

        size_t pos = 0;
        while (pos <= keys_env.size())
        {
            size_t comma = keys_env.find(',', pos);
            if (comma == std::string::npos) comma = keys_env.size();

            const std::string item = trim(keys_env.substr(pos, comma - pos));
            pos = comma + 1;
            if (item.empty()) continue;

            const size_t colon = item.find(':');
            if (colon == std::string::npos) { error = "ожидался формат id:hex"; keys.clear(); return false; }

            const int id = parse_id(item.substr(0, colon));
            std::string raw;
            if (id < 1 || id > 255) { error = "id ключа должен быть от 1 до 255"; keys.clear(); return false; }
            if (keys.count(id)) { error = "id ключа повторяется"; keys.clear(); return false; }
            if (!from_hex(item.substr(colon + 1), raw) || raw.size() != kKeyLen)
            {
                error = "ключ должен быть 64 символа hex (32 байта)";
                keys.clear();
                return false;
            }
            keys[id] = std::move(raw);
        }

        if (keys.empty()) { error = "в CHAT_KEYS нет ключей"; return false; }

        const int active = parse_id(trim(active_env));
        if (active < 1 || !keys.count(active))
        {
            error = "CHAT_KEY_ACTIVE не задан или указывает на несуществующий ключ";
            keys.clear();
            return false;
        }

        active_id = active;

        if (!self_test())
        {
            error = "самопроверка шифрования не прошла (проверьте OpenSSL)";
            keys.clear();
            active_id = 0;
            return false;
        }
        return true;
    }

    bool enabled() const { return active_id != 0; }
    int active_key_id() const { return active_id; }

    // nullopt означает ошибку: вызывающий НЕ должен записывать открытый текст вместо шифротекста
    std::optional<std::string> encrypt(const std::string& plain, const std::string& aad) const
    {
        if (!enabled()) return std::nullopt;
        if (plain.size() > (size_t)INT_MAX / 2 || aad.size() > (size_t)INT_MAX / 2) return std::nullopt;

        const std::string& key = keys.at(active_id);

        unsigned char nonce[kNonceLen];
        if (RAND_bytes(nonce, (int)kNonceLen) != 1) return std::nullopt;

        CtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return std::nullopt;

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return std::nullopt;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) != 1) return std::nullopt;
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), nonce) != 1) return std::nullopt;

        int len = 0;
        if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len,
            reinterpret_cast<const unsigned char*>(aad.data()), (int)aad.size()) != 1) return std::nullopt;

        std::string out;
        out.resize(kHeaderLen + plain.size());
        out[0] = (char)kVersion;
        out[1] = (char)(unsigned char)active_id;
        std::memcpy(&out[2], nonce, kNonceLen);

        unsigned char* dst = reinterpret_cast<unsigned char*>(&out[kHeaderLen]);
        int total = 0;

        if (!plain.empty())
        {
            if (EVP_EncryptUpdate(ctx.get(), dst, &len,
                reinterpret_cast<const unsigned char*>(plain.data()), (int)plain.size()) != 1) return std::nullopt;
            total = len;
        }

        if (EVP_EncryptFinal_ex(ctx.get(), dst + total, &len) != 1) return std::nullopt;
        total += len;
        if ((size_t)total != plain.size()) return std::nullopt;

        unsigned char tag[kTagLen];
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)kTagLen, tag) != 1) return std::nullopt;

        out.append(reinterpret_cast<const char*>(tag), kTagLen);
        return out;
    }

    // nullopt: запись повреждена или подменена, неверный контекст, неизвестный ключ
    std::optional<std::string> decrypt(const std::string& blob, const std::string& aad) const
    {
        if (blob.size() < kHeaderLen + kTagLen) return std::nullopt;
        if (blob.size() > (size_t)INT_MAX / 2 || aad.size() > (size_t)INT_MAX / 2) return std::nullopt;
        if ((unsigned char)blob[0] != kVersion) return std::nullopt;

        auto it = keys.find((unsigned char)blob[1]);
        if (it == keys.end()) return std::nullopt;
        const std::string& key = it->second;

        const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob.data()) + 2;
        const unsigned char* ct = reinterpret_cast<const unsigned char*>(blob.data()) + kHeaderLen;
        const size_t ct_len = blob.size() - kHeaderLen - kTagLen;

        unsigned char tag[kTagLen];
        std::memcpy(tag, blob.data() + kHeaderLen + ct_len, kTagLen);

        CtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return std::nullopt;

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return std::nullopt;
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) != 1) return std::nullopt;
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), nonce) != 1) return std::nullopt;

        int len = 0;
        if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len,
            reinterpret_cast<const unsigned char*>(aad.data()), (int)aad.size()) != 1) return std::nullopt;

        std::string plain(ct_len, '\0');
        unsigned char* dst = reinterpret_cast<unsigned char*>(&plain[0]);
        int total = 0;

        if (ct_len > 0)
        {
            if (EVP_DecryptUpdate(ctx.get(), dst, &len, ct, (int)ct_len) != 1) return std::nullopt;
            total = len;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)kTagLen, tag) != 1) return std::nullopt;

        // здесь проверяется тег: при подмене данных или неверном контексте возвращается ошибка
        if (EVP_DecryptFinal_ex(ctx.get(), dst + total, &len) <= 0) return std::nullopt;

        return plain;
    }

    // Получение отдельного ключа файла через HKDF-SHA256.
    // key_id: ID мастер-ключа из CHAT_KEYS, salt: уникальная случайная соль файла,
    // out_key: производный ключ AES-256 (32 байта).
    // У каждого файла своя соль, поэтому и ключ свой: номера блоков можно использовать
    // как nonce, повторов с одним ключом не будет. Мастер-ключи остаются закрытыми.
    // Строка info менять нельзя: от неё зависит результат, и файлы, уже записанные с ней,
    // перестанут расшифровываться.
    bool derive_file_key(int key_id, const std::string& salt, std::string& out_key) const
    {
        out_key.clear();

        auto it = keys.find(key_id);
        if (it == keys.end())
            return false;

        if (salt.size() < 16 || salt.size() > 64)
            return false;

        const std::string& master_key = it->second;

        EVP_PKEY_CTX* raw_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!raw_ctx)
            return false;

        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw_ctx, EVP_PKEY_CTX_free);

        if (EVP_PKEY_derive_init(ctx.get()) <= 0)
            return false;

        if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0)
            return false;

        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
            reinterpret_cast<const unsigned char*>(salt.data()), (int)salt.size()) <= 0)
            return false;

        if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(),
            reinterpret_cast<const unsigned char*>(master_key.data()), (int)master_key.size()) <= 0)
            return false;

        // разделение назначения ключей (domain separation)
        static const unsigned char info[] = "chat-file-encryption-v1";

        if (EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info, sizeof(info) - 1) <= 0)
            return false;

        out_key.resize(kKeyLen);
        size_t out_len = kKeyLen;

        if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(&out_key[0]), &out_len) <= 0
            || out_len != kKeyLen)
        {
            OPENSSL_cleanse(&out_key[0], out_key.size());
            out_key.clear();
            return false;
        }

        return true;
    }

    // Новый случайный ключ в hex: вывести один раз и положить в CHAT_KEYS
    static std::string generate_key_hex()
    {
        unsigned char k[kKeyLen];
        if (RAND_bytes(k, (int)kKeyLen) != 1) return {};
        return to_hex(k, kKeyLen);
    }

private:
    struct CtxDeleter { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
    using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

    bool self_test() const
    {
        const std::string text = "self-test";

        auto blob = encrypt(text, "ctx");
        if (!blob) return false;

        auto ok = decrypt(*blob, "ctx");
        if (!ok || *ok != text) return false;

        if (decrypt(*blob, "other")) return false;            // другой контекст должен отвергаться

        std::string bad = *blob;
        bad[kHeaderLen] ^= 0x01;                              // испорченные данные должны отвергаться
        if (decrypt(bad, "ctx")) return false;

        return true;
    }

    static std::string env_get(const char* name)
    {
#ifdef _WIN32
        char* buf = nullptr;
        size_t len = 0;
        if (_dupenv_s(&buf, &len, name) != 0 || !buf) return {};
        std::string v(buf);
        free(buf);
        return v;
#else
        const char* v = std::getenv(name);
        return v ? std::string(v) : std::string();
#endif
    }

    static std::string trim(const std::string& s)
    {
        const size_t b = s.find_first_not_of(" \t\r\n");
        const size_t e = s.find_last_not_of(" \t\r\n");
        return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
    }

    static int parse_id(const std::string& s)
    {
        if (s.empty() || s.size() > 3) return 0;
        int v = 0;
        for (char c : s)
        {
            if (c < '0' || c > '9') return 0;
            v = v * 10 + (c - '0');
        }
        return v;
    }

    static int hex_val(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static bool from_hex(const std::string& hex, std::string& out)
    {
        if (hex.size() % 2 != 0) return false;
        out.clear();
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            const int hi = hex_val(hex[i]), lo = hex_val(hex[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out.push_back((char)(hi * 16 + lo));
        }
        return true;
    }

    static std::string to_hex(const unsigned char* d, size_t n)
    {
        static const char* h = "0123456789abcdef";
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i)
        {
            s += h[d[i] >> 4];
            s += h[d[i] & 15];
        }
        return s;
    }

    std::map<int, std::string> keys;     // id -> 32 байта ключа
    int active_id = 0;
};

// Один объект на весь процесс; после init_from_env только читается, поэтому безопасен для потоков
inline Crypto& crypto()
{
    static Crypto c;
    return c;
}

// Контекст (AAD) для разных видов данных. Должен совпадать при записи и при чтении.
inline std::string aad_direct(int sender_id, int recipient_id)
{
    return "dm:" + std::to_string(sender_id) + ":" + std::to_string(recipient_id);
}

inline std::string aad_group(int group_id, int sender_id)
{
    return "gm:" + std::to_string(group_id) + ":" + std::to_string(sender_id);
}

inline std::string aad_file(const std::string& stored_name)
{
    return "file:" + stored_name;
}

inline std::string aad_upload_name(const std::string& stored_name)
{
    return "fname:" + stored_name;
}