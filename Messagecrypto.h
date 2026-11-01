#pragma once
#include <algorithm>
#include <iostream>
#include <optional>
#include <string>


#include "Сrypto.h"

// Что записать в БД вместо текста сообщения.
// Шифрование включено: text пустой, enc содержит зашифрованную запись (колонка body_enc).
// Шифрование выключено: text содержит исходный текст, enc пустой (как раньше).
struct SealedBody
{
    std::string text;
    std::string enc;
};

// nullopt значит ошибку шифрования: сообщение нельзя сохранять, а тем более открытым текстом
inline std::optional<SealedBody> seal_body(const std::string& plain, const std::string& aad)
{
    SealedBody out;

    if (!crypto().enabled())
    {
        out.text = plain;
        return out;
    }

    auto blob = crypto().encrypt(plain, aad);
    if (!blob) return std::nullopt;

    out.enc = std::move(*blob);
    return out;
}

inline std::optional<SealedBody> seal_direct(int sender_id, int recipient_id, const std::string& text)
{
    return seal_body(text, aad_direct(sender_id, recipient_id));
}

inline std::optional<SealedBody> seal_group(int group_id, int sender_id, const std::string& text)
{
    return seal_body(text, aad_group(group_id, sender_id));
}

// Текст для клиента. Запись без body_enc это старое незашифрованное сообщение.
inline std::string open_body(const std::string& legacy_text, const std::string& enc, const std::string& aad)
{
    if (enc.empty()) return legacy_text;

    auto plain = crypto().decrypt(enc, aad);
    if (!plain)
    {
        std::cerr << "Crypto: не удалось расшифровать сообщение (подмена, неверный ключ или контекст)" << std::endl;
        return "[не удалось расшифровать]";
    }
    return *plain;
}

inline std::string open_direct(const std::string& legacy_text, const std::string& enc,
    int sender_id, int recipient_id)
{
    return open_body(legacy_text, enc, aad_direct(sender_id, recipient_id));
}

inline std::string open_group(const std::string& legacy_text, const std::string& enc,
    int group_id, int sender_id)
{
    return open_body(legacy_text, enc, aad_group(group_id, sender_id));
}

// Двоичная колонка из буфера, к которому привязан SQLBindCol (ind = длина или NULL_DATA)
inline std::string bincol(const unsigned char* buf, size_t cap, long long ind)
{
    if (ind <= 0) return {};
    return std::string(reinterpret_cast<const char*>(buf), (std::min)((size_t)ind, cap));
}

// Первые max_chars символов UTF-8 строки: для превью в списке диалогов
inline std::string utf8_preview(const std::string& s, size_t max_chars)
{
    size_t chars = 0, i = 0;

    while (i < s.size() && chars < max_chars)
    {
        const unsigned char c = (unsigned char)s[i];
        const size_t step = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 1;
        i += step;
        ++chars;
    }

    return s.substr(0, (std::min)(i, s.size()));
}