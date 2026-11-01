#pragma once
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#pragma comment(lib, "Crypt32.lib")
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "BlockCrypto.h"
#include "Сrypto.h"
#include "FileCrypto.h"

// Хранилище ключей шифрования.
//
// Откуда сервер берёт ключи (по порядку):
//   1. Файл ключей (по умолчанию keys/chat.keystore, путь можно задать в CHAT_KEYSTORE).
//      Он зашифрован Windows DPAPI: расшифровать его может только та же учётная запись Windows
//      (или любой процесс на этом компьютере, если CHAT_KEYSTORE_SCOPE=machine).
//      Украденный файл на другом компьютере или под другим пользователем бесполезен.
//   2. Переменные окружения CHAT_KEYS и CHAT_KEY_ACTIVE (как раньше).
//
// Если файл ключей есть, но не расшифровывается, сервер не запускается: молча переходить
// на другой источник нельзя.
//
// DPAPI не защищает от кода, который работает под той же учётной записью. Для более строгой защиты
// ключи берут из облачного хранилища секретов (Azure Key Vault, HashiCorp Vault) или аппаратного
// модуля: достаточно заменить load_key_material, остальной код получает ключи как строки.
//
// Необязательные переменные:
//   CHAT_KEYSTORE            путь к файлу ключей
//   CHAT_KEYSTORE_SCOPE      machine: файл читает любой процесс на этом компьютере (для служб)
//   CHAT_KEYSTORE_ENTROPY    дополнительный секрет: без него файл не расшифровать

struct KeyMaterial
{
    std::string keys_spec;      // "1:<64 hex>,2:<64 hex>"
    int active = 0;             // id ключа для новых записей

    void wipe()
    {
        if (!keys_spec.empty()) OPENSSL_cleanse(&keys_spec[0], keys_spec.size());
        keys_spec.clear();
        active = 0;
    }

    ~KeyMaterial() { wipe(); }
};

inline void secret_wipe(std::string& s)
{
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

inline std::string secret_env(const char* name)
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

inline int parse_small_int(const std::string& s)
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

inline std::string keystore_path()
{
    const std::string p = secret_env("CHAT_KEYSTORE");
    return p.empty() ? std::string("keys/chat.keystore") : p;
}

inline bool keystore_exists()
{
    std::error_code ec;
    return std::filesystem::exists(keystore_path(), ec);
}

// Идентификаторы ключей из строки "1:...,2:..."
inline std::vector<int> key_ids(const std::string& spec)
{
    std::vector<int> ids;
    size_t pos = 0;

    while (pos <= spec.size())
    {
        size_t comma = spec.find(',', pos);
        if (comma == std::string::npos) comma = spec.size();

        std::string item = spec.substr(pos, comma - pos);
        pos = comma + 1;

        const size_t b = item.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        item = item.substr(b);

        const size_t colon = item.find(':');
        if (colon == std::string::npos) continue;

        const int id = parse_small_int(item.substr(0, colon));
        if (id > 0) ids.push_back(id);
    }
    return ids;
}

// ---------- защита файла ключей (Windows DPAPI) ----------

#ifdef _WIN32

inline bool dpapi_protect(const std::string& plain, std::string& out, std::string& error)
{
    const std::string entropy = secret_env("CHAT_KEYSTORE_ENTROPY");
    const bool machine = (secret_env("CHAT_KEYSTORE_SCOPE") == "machine");

    DATA_BLOB in;
    in.cbData = (DWORD)plain.size();
    in.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(plain.data()));

    DATA_BLOB ent;
    ent.cbData = (DWORD)entropy.size();
    ent.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(entropy.data()));

    DATA_BLOB res = {};
    const DWORD flags = CRYPTPROTECT_UI_FORBIDDEN | (machine ? CRYPTPROTECT_LOCAL_MACHINE : 0);

    if (!CryptProtectData(&in, L"chat-keystore", entropy.empty() ? nullptr : &ent,
        nullptr, nullptr, flags, &res))
    {
        error = "CryptProtectData не удалась, код " + std::to_string(GetLastError());
        return false;
    }

    out.assign(reinterpret_cast<const char*>(res.pbData), res.cbData);
    LocalFree(res.pbData);
    return true;
}

inline bool dpapi_unprotect(const std::string& blob, std::string& out, std::string& error)
{
    const std::string entropy = secret_env("CHAT_KEYSTORE_ENTROPY");

    DATA_BLOB in;
    in.cbData = (DWORD)blob.size();
    in.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(blob.data()));

    DATA_BLOB ent;
    ent.cbData = (DWORD)entropy.size();
    ent.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(entropy.data()));

    DATA_BLOB res = {};

    if (!CryptUnprotectData(&in, nullptr, entropy.empty() ? nullptr : &ent,
        nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &res))
    {
        error = "не удалось расшифровать файл ключей (другая учётная запись или компьютер, "
            "неверный CHAT_KEYSTORE_ENTROPY, файл повреждён), код " + std::to_string(GetLastError());
        return false;
    }

    out.assign(reinterpret_cast<const char*>(res.pbData), res.cbData);
    SecureZeroMemory(res.pbData, res.cbData);
    LocalFree(res.pbData);
    return true;
}

#else

inline bool dpapi_protect(const std::string&, std::string&, std::string& error)
{
    error = "DPAPI доступен только в Windows";
    return false;
}

inline bool dpapi_unprotect(const std::string&, std::string&, std::string& error)
{
    error = "DPAPI доступен только в Windows";
    return false;
}

#endif

// ---------- сериализация ----------

// "CK1\n<id активного ключа>\n<строка ключей>"
inline std::string serialize_key_material(const KeyMaterial& km)
{
    return "CK1\n" + std::to_string(km.active) + "\n" + km.keys_spec;
}

inline bool parse_key_material(const std::string& plain, KeyMaterial& km)
{
    if (plain.compare(0, 4, "CK1\n") != 0) return false;

    const size_t nl = plain.find('\n', 4);
    if (nl == std::string::npos) return false;

    km.active = parse_small_int(plain.substr(4, nl - 4));
    km.keys_spec = plain.substr(nl + 1);
    return km.active > 0 && !km.keys_spec.empty();
}

// Проверка, что ключи годятся: формат, активный ключ существует, шифрование работает
inline bool validate_key_material(const KeyMaterial& km, std::string& error)
{
    Crypto probe;
    return probe.init_from_strings(km.keys_spec, std::to_string(km.active), error);
}

// ---------- файл ключей ----------

inline bool keystore_save(const KeyMaterial& km, std::string& error)
{
    std::string verr;
    if (!validate_key_material(km, verr))
    {
        error = "ключи неверны: " + verr;
        return false;
    }

    std::string plain = serialize_key_material(km);
    std::string blob;
    const bool ok = dpapi_protect(plain, blob, error);
    secret_wipe(plain);
    if (!ok) return false;

    const std::filesystem::path path = keystore_path();
    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);

    if (!write_all(path.string(), blob))
    {
        error = "не удалось записать файл ключей " + path.string();
        return false;
    }
    return true;
}

inline bool keystore_load(KeyMaterial& km, std::string& error)
{
    auto blob = read_all(keystore_path());
    if (!blob || blob->empty())
    {
        error = "не удалось прочитать файл ключей " + keystore_path();
        return false;
    }

    std::string plain;
    if (!dpapi_unprotect(*blob, plain, error)) return false;

    const bool parsed = parse_key_material(plain, km);
    secret_wipe(plain);

    if (!parsed)
    {
        km.wipe();
        error = "файл ключей имеет неизвестный формат";
        return false;
    }
    return true;
}

// Единственное место, где сервер получает ключи. Сюда подключается любой другой источник секретов.
// source: откуда загружено, для строки в журнале.
inline bool load_key_material(KeyMaterial& km, std::string& source, std::string& error)
{
    if (keystore_exists())
    {
        source = "файл ключей " + keystore_path();
        return keystore_load(km, error);
    }

    source = "переменные окружения";

    km.keys_spec = secret_env("CHAT_KEYS");
    km.active = parse_small_int(secret_env("CHAT_KEY_ACTIVE"));

    if (km.keys_spec.empty())
    {
        error = "ключи не заданы: нет файла ключей " + keystore_path() + " и переменной CHAT_KEYS";
        return false;
    }
    if (km.active <= 0)
    {
        km.wipe();
        error = "CHAT_KEY_ACTIVE не задан";
        return false;
    }
    return true;
}

// Добавляет новый случайный ключ и делает его активным. Старые ключи остаются:
// по ним читаются уже записанные данные.
inline bool keys_rotate(KeyMaterial& km, int& new_id, std::string& error)
{
    int max_id = 0;
    for (int id : key_ids(km.keys_spec)) max_id = (std::max)(max_id, id);

    if (max_id <= 0) { error = "в хранилище нет ключей"; return false; }
    if (max_id >= 255) { error = "достигнут предел числа ключей (255)"; return false; }

    std::string hex = Crypto::generate_key_hex();
    if (hex.empty()) { error = "не удалось получить случайные данные"; return false; }

    new_id = max_id + 1;
    km.keys_spec += "," + std::to_string(new_id) + ":" + hex;
    km.active = new_id;

    secret_wipe(hex);
    return true;
}

// ---------- резервная копия под парольной фразой ----------
//
// Файл можно хранить где угодно отдельно от сервера и базы и восстановить на другом компьютере
// (файл DPAPI на другой компьютер перенести нельзя).
// Формат: "CKB1" | 16 байт соли | 4 байта число итераций | 12 байт nonce | шифротекст | 16 байт тег.
// Ключ из парольной фразы: PBKDF2-HMAC-SHA256, шифрование AES-256-GCM.

inline constexpr uint32_t kBackupIterations = 600000;
inline constexpr size_t kBackupHeader = 4 + 16 + 4 + 12;

inline bool backup_derive_key(const std::string& pass, const unsigned char* salt, uint32_t iter, std::string& key)
{
    key.assign(32, '\0');
    return PKCS5_PBKDF2_HMAC(pass.data(), (int)pass.size(), salt, 16, (int)iter, EVP_sha256(),
        32, reinterpret_cast<unsigned char*>(&key[0])) == 1;
}

inline bool keys_backup_write(const KeyMaterial& km, const std::string& path, const std::string& pass,
    std::string& error)
{
    if (pass.size() < 12) { error = "парольная фраза должна быть не короче 12 символов"; return false; }

    std::string verr;
    if (!validate_key_material(km, verr)) { error = "ключи неверны: " + verr; return false; }

    unsigned char salt[16], nonce[12];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1)
    {
        error = "не удалось получить случайные данные";
        return false;
    }

    std::string key;
    if (!backup_derive_key(pass, salt, kBackupIterations, key)) { error = "не удалось вывести ключ"; return false; }

    std::string header(kBackupHeader, '\0');
    std::memcpy(&header[0], "CKB1", 4);
    std::memcpy(&header[4], salt, 16);
    blockfile::put_be32(header, 20, kBackupIterations);
    std::memcpy(&header[24], nonce, 12);

    std::string plain = serialize_key_material(km);
    std::string out = header;
    out.resize(kBackupHeader + plain.size());

    unsigned char tag[blockfile::kTag];
    const bool ok = blockfile::gcm_seal(key, nonce, header + "chat-keys-backup-v1",
        reinterpret_cast<const unsigned char*>(plain.data()), plain.size(),
        reinterpret_cast<unsigned char*>(&out[kBackupHeader]), tag);

    secret_wipe(plain);
    secret_wipe(key);

    if (!ok) { error = "не удалось зашифровать резервную копию"; return false; }

    out.append(reinterpret_cast<const char*>(tag), blockfile::kTag);

    if (!write_all(path, out)) { error = "не удалось записать файл " + path; return false; }
    return true;
}

inline bool keys_backup_read(KeyMaterial& km, const std::string& path, const std::string& pass,
    std::string& error)
{
    auto blob = read_all(path);
    if (!blob || blob->size() < kBackupHeader + blockfile::kTag + 4)
    {
        error = "файл резервной копии не читается или повреждён";
        return false;
    }
    if (blob->compare(0, 4, "CKB1") != 0) { error = "это не резервная копия ключей"; return false; }

    const uint32_t iter = blockfile::get_be32(*blob, 20);
    if (iter < 100000 || iter > 5000000) { error = "резервная копия повреждена"; return false; }

    const unsigned char* salt = reinterpret_cast<const unsigned char*>(blob->data()) + 4;
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob->data()) + 24;

    std::string key;
    if (!backup_derive_key(pass, salt, iter, key)) { error = "не удалось вывести ключ"; return false; }

    const size_t ct_len = blob->size() - kBackupHeader - blockfile::kTag;
    const unsigned char* ct = reinterpret_cast<const unsigned char*>(blob->data()) + kBackupHeader;
    const unsigned char* tag = ct + ct_len;

    std::string plain(ct_len, '\0');
    const bool ok = blockfile::gcm_open(key, nonce, blob->substr(0, kBackupHeader) + "chat-keys-backup-v1",
        ct, ct_len, tag, reinterpret_cast<unsigned char*>(&plain[0]));

    secret_wipe(key);

    if (!ok) { error = "неверная парольная фраза или файл повреждён"; return false; }

    const bool parsed = parse_key_material(plain, km);
    secret_wipe(plain);

    if (!parsed) { km.wipe(); error = "резервная копия имеет неизвестный формат"; return false; }
    return true;
}

// ---------- ввод секрета с консоли ----------

inline std::string read_secret(const std::string& prompt)
{
    std::cout << prompt << std::flush;
    std::string s;

#ifdef _WIN32
    int c;
    while ((c = _getch()) != '\r' && c != '\n' && c != EOF)
    {
        if (c == 3) { std::cout << std::endl; return {}; }                 // Ctrl+C
        if (c == '\b') { if (!s.empty()) s.pop_back(); continue; }
        if (c == 0 || c == 0xE0) { _getch(); continue; }                    // служебные клавиши
        s.push_back((char)c);
    }
#else
    std::getline(std::cin, s);
#endif

    std::cout << std::endl;
    return s;
}

// ---------- команды управления ключами ----------
//
//   --keys-new               создать первый ключ и файл ключей
//   --keys-import [--force]  перенести ключи из CHAT_KEYS и CHAT_KEY_ACTIVE в файл ключей
//   --keys-rotate            добавить новый ключ и сделать его активным
//   --keys-info              показать источник, номера ключей и активный (сами ключи не выводятся)
//   --keys-backup <файл>     резервная копия под парольной фразой
//   --keys-restore <файл> [--force]   восстановить файл ключей из резервной копии
//
// Возвращает -1, если аргументы не относятся к ключам (сервер запускается как обычно),
// иначе код завершения процесса.
inline int handle_keys_command(int argc, char** argv)
{
    if (argc < 2) return -1;

    const std::string cmd = argv[1];
    if (cmd.rfind("--keys-", 0) != 0) return -1;

    auto has_flag = [&](const char* flag) {
        for (int i = 2; i < argc; ++i)
            if (std::string(argv[i]) == flag) return true;
        return false;
        };

    std::string error;

    if (cmd == "--keys-new")
    {
        if (keystore_exists())
        {
            std::cerr << "Файл ключей уже есть: " << keystore_path()
                << ". Для смены ключа используйте --keys-rotate." << std::endl;
            return 1;
        }

        KeyMaterial km;
        std::string hex = Crypto::generate_key_hex();
        if (hex.empty()) { std::cerr << "Не удалось получить случайные данные." << std::endl; return 1; }
        km.keys_spec = "1:" + hex;
        km.active = 1;
        secret_wipe(hex);

        if (!keystore_save(km, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Создан ключ 1, файл ключей: " << keystore_path() << "\n"
            << "Сделайте резервную копию командой --keys-backup и храните её отдельно от сервера." << std::endl;
        return 0;
    }

    if (cmd == "--keys-import")
    {
        if (keystore_exists() && !has_flag("--force"))
        {
            std::cerr << "Файл ключей уже есть: " << keystore_path() << ". Для замены добавьте --force." << std::endl;
            return 1;
        }

        KeyMaterial km;
        km.keys_spec = secret_env("CHAT_KEYS");
        km.active = parse_small_int(secret_env("CHAT_KEY_ACTIVE"));
        if (km.keys_spec.empty() || km.active <= 0)
        {
            std::cerr << "Задайте CHAT_KEYS и CHAT_KEY_ACTIVE, это источник для импорта." << std::endl;
            return 1;
        }

        if (!keystore_save(km, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Ключи перенесены в " << keystore_path() << ".\n"
            << "Теперь удалите переменные CHAT_KEYS и CHAT_KEY_ACTIVE и сделайте резервную копию (--keys-backup)."
            << std::endl;
        return 0;
    }

    if (cmd == "--keys-rotate")
    {
        if (!keystore_exists())
        {
            std::cerr << "Нет файла ключей. Сначала --keys-import или --keys-new." << std::endl;
            return 1;
        }

        KeyMaterial km;
        if (!keystore_load(km, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        int new_id = 0;
        if (!keys_rotate(km, new_id, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }
        if (!keystore_save(km, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Добавлен ключ " << new_id << ", теперь он активный. Старые ключи сохранены.\n"
            << "Не забудьте сделать новую резервную копию (--keys-backup): в старой нового ключа нет.\n"
            << "Перезапустите сервер." << std::endl;
        return 0;
    }

    if (cmd == "--keys-info")
    {
        KeyMaterial km;
        std::string source;
        if (!load_key_material(km, source, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Источник: " << source << "\nКлючи:";
        for (int id : key_ids(km.keys_spec)) std::cout << " " << id;
        std::cout << "\nАктивный: " << km.active << std::endl;

        std::string verr;
        std::cout << "Проверка: " << (validate_key_material(km, verr) ? "ключи в порядке" : ("ОШИБКА: " + verr))
            << std::endl;
        return 0;
    }

    if (cmd == "--keys-backup")
    {
        if (argc < 3) { std::cerr << "Использование: --keys-backup <файл>" << std::endl; return 2; }

        KeyMaterial km;
        std::string source;
        if (!load_key_material(km, source, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::string p1 = read_secret("Парольная фраза (от 12 символов): ");
        std::string p2 = read_secret("Повторите: ");
        if (p1 != p2) { std::cerr << "Фразы не совпадают." << std::endl; secret_wipe(p1); secret_wipe(p2); return 1; }

        const bool ok = keys_backup_write(km, argv[2], p1, error);
        secret_wipe(p1);
        secret_wipe(p2);

        if (!ok) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Резервная копия записана: " << argv[2] << "\n"
            << "Храните файл и парольную фразу отдельно друг от друга и от сервера." << std::endl;
        return 0;
    }

    if (cmd == "--keys-restore")
    {
        if (argc < 3) { std::cerr << "Использование: --keys-restore <файл> [--force]" << std::endl; return 2; }

        if (keystore_exists() && !has_flag("--force"))
        {
            std::cerr << "Файл ключей уже есть: " << keystore_path() << ". Для замены добавьте --force." << std::endl;
            return 1;
        }

        std::string pass = read_secret("Парольная фраза: ");

        KeyMaterial km;
        const bool ok = keys_backup_read(km, argv[2], pass, error);
        secret_wipe(pass);

        if (!ok) { std::cerr << "Ошибка: " << error << std::endl; return 1; }
        if (!keystore_save(km, error)) { std::cerr << "Ошибка: " << error << std::endl; return 1; }

        std::cout << "Ключи восстановлены в " << keystore_path() << std::endl;
        return 0;
    }

    std::cerr << "Неизвестная команда " << cmd << std::endl;
    return 2;
}