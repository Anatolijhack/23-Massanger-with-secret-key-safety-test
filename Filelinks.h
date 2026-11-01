#pragma once
#include <cstdint>
#include <ctime>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// Подписанная ссылка на файл вида  /uploads/chat/<имя>?exp=<unix>&u=<id>&sig=<hex>
//
// Браузер не умеет добавлять заголовок Authorization к <img>, <audio> и <video>,
// поэтому клиент сначала просит сервер выдать ссылки (с проверкой прав), а потом
// подставляет их в страницу. Подпись привязана к имени файла, времени жизни и пользователю.
class FileLinks
{
public:
    static constexpr int kDefaultTtlSec = 600;

    enum class Verdict { Ok, Expired, Invalid };

    // Секрет из переменной FILE_LINK_SECRET (от 16 символов). Если не задан, на время работы
    // процесса создаётся случайный: после перезапуска старые ссылки перестанут работать,
    // клиент просто запросит новые. Для нескольких экземпляров сервера секрет задавать нужно.
    void init(const std::string& secret_from_env)
    {
        if (secret_from_env.size() >= 16)
        {
            secret = secret_from_env;
            return;
        }

        unsigned char r[32];
        if (RAND_bytes(r, (int)sizeof(r)) != 1)
        {
            secret.clear();
            return;
        }
        secret.assign(reinterpret_cast<const char*>(r), sizeof(r));
    }

    bool ready() const { return !secret.empty(); }

    // "exp=...&u=...&sig=..." для добавления к адресу файла
    std::string sign_query(const std::string& stored_name, int user_id, int ttl_sec = kDefaultTtlSec) const
    {
        const long long exp = (long long)std::time(nullptr) + ttl_sec;
        return "exp=" + std::to_string(exp) + "&u=" + std::to_string(user_id) +
            "&sig=" + mac_hex(stored_name, exp, user_id);
    }

    Verdict verify(const std::string& stored_name, long long exp, int user_id, const std::string& sig) const
    {
        if (!ready()) return Verdict::Invalid;

        const std::string expect = mac_hex(stored_name, exp, user_id);

        // сравнение за постоянное время, чтобы подпись нельзя было подобрать по скорости ответа
        if (sig.size() != expect.size() || CRYPTO_memcmp(sig.data(), expect.data(), sig.size()) != 0)
            return Verdict::Invalid;

        if (exp < (long long)std::time(nullptr)) return Verdict::Expired;
        return Verdict::Ok;
    }

private:
    std::string mac_hex(const std::string& name, long long exp, int user_id) const
    {
        const std::string data = "file|" + name + "|" + std::to_string(exp) + "|" + std::to_string(user_id);

        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        HMAC(EVP_sha256(), secret.data(), (int)secret.size(),
            reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac, &len);

        static const char* h = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (unsigned int i = 0; i < len; ++i)
        {
            out += h[mac[i] >> 4];
            out += h[mac[i] & 15];
        }
        return out;
    }

    std::string secret;
};

inline FileLinks& file_links()
{
    static FileLinks f;
    return f;
}

// Только цифры, не больше 12 знаков. Для разбора exp и u из строки запроса.
inline bool parse_nonneg(const std::string& s, long long& out)
{
    if (s.empty() || s.size() > 12) return false;

    long long v = 0;
    for (char c : s)
    {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}