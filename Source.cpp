#include "Server.h"
#include <iostream>
#include "Сrypto.h"
#include "FileCrypto.h"
#include "Logger.h"
#include "SessionRepository.h"
#include "Config.h"
#include "AuthController.h"
#include "SessionCleaner.h"
#include "ChatRepository.h"
#include "ChatController.h"
#include "ChatService.h" 
#include "UploadCleaner.h"
#include "Periodictask.h"
#include "FileLinks.h"
#include "Secretstore.h"

static std::string env_or(const char* name, const std::string& fallback)
{
#ifdef _WIN32
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) != 0 || !buf) return fallback;
    std::string v(buf);
    free(buf);
    return v.empty() ? fallback : v;
#else
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
#endif
}
int main(int argc, char** argv)
{

    file_links().init(env_or("FILE_LINK_SECRET", ""));
    Logger::instance().init("server.log");
    LOG_INFO("Server starting...");
    Config config = Config::load("config.json");
    Router router;

    ConnectionPool db_pool(
        config.database.pool_size,
        config.database.to_connection_string()
    );
    SessionRepository session_repository(db_pool, std::chrono::minutes(30), std::chrono::hours(12));
    
    std::string crypto_error;
    if (crypto().init_from_env(crypto_error))
        std::cout << "Crypto: шифрование включено, активный ключ " << crypto().active_key_id() << std::endl;
    else
        std::cout << "Crypto: ШИФРОВАНИЕ ВЫКЛЮЧЕНО (" << crypto_error << "). Данные пишутся открытым текстом." << std::endl;
    // перед боевым запуском замените на: return 1;


    SessionCleaner session_cleaner(session_repository);
    ChatRepository cleaner_repo(db_pool);
    GroupRepository groups(db_pool);
    ThreadPool pool(4);
    ChatService chat(
        db_pool,
        session_repository,
        pool,
        { "https://localhost:8080/" }
    );

    const int keys_rc = handle_keys_command(argc, argv);
    if (keys_rc >= 0) return keys_rc;

    // ключи: файл ключей (DPAPI), а если его нет, переменные окружения
    std::string key_source;
    bool keys_ok = false;
    {
        KeyMaterial km;
        if (load_key_material(km, key_source, crypto_error))
            keys_ok = crypto().init_from_strings(km.keys_spec, std::to_string(km.active), crypto_error);
    }   // деструктор KeyMaterial затирает копию ключей

    const bool dev_without_encryption = (env_or("CHAT_ENCRYPTION", "") == "off");

    if (!keys_ok && !dev_without_encryption)
    {
        std::cerr << "Crypto: сервер не запущен: " << crypto_error
            << "\n(для разработки без шифрования задайте CHAT_ENCRYPTION=off)" << std::endl;
        return 1;
    }

    if (keys_ok)
    {
        std::cout << "Crypto: шифрование включено, ключи из: " << key_source
            << ", активный ключ " << crypto().active_key_id() << std::endl;
    }
    else
    {
        auto enc_dir_has_files = [] {
            std::error_code ec;
            return std::filesystem::exists(kEncDir, ec) && !std::filesystem::is_empty(kEncDir, ec);
            };

        if (cleaner_repo.has_encrypted_data() || enc_dir_has_files())
        {
            std::cerr << "Crypto: в базе или в uploads_enc уже есть зашифрованные данные, "
                "без ключей сервер не запускается" << std::endl;
            return 1;
        }

        std::cout << "Crypto: ШИФРОВАНИЕ ВЫКЛЮЧЕНО режимом CHAT_ENCRYPTION=off" << std::endl;
    }

   

    if (!keys_ok && !dev_without_encryption)
    {
        std::cerr << "Crypto: сервер не запущен: " << crypto_error
            << "\n(для разработки без шифрования задайте CHAT_ENCRYPTION=off)" << std::endl;
        return 1;
    }

    if (keys_ok)
    {
        std::cout << "Crypto: шифрование включено, активный ключ " << crypto().active_key_id() << std::endl;
    }
    else
    {
        auto enc_dir_has_files = [] {
            std::error_code ec;
            return std::filesystem::exists(kEncDir, ec) && !std::filesystem::is_empty(kEncDir, ec);
            };

        if (cleaner_repo.has_encrypted_data() || enc_dir_has_files())
        {
            std::cerr << "Crypto: в базе или в uploads_enc уже есть зашифрованные данные, "
                "без ключей сервер не запускается" << std::endl;
            return 1;
        }

        std::cout << "Crypto: ШИФРОВАНИЕ ВЫКЛЮЧЕНО режимом CHAT_ENCRYPTION=off" << std::endl;
    }

    
    ChatController chat_controller(db_pool, session_repository);
    chat_controller.register_routes(router);
    chat_controller.on_member_removed = [&](int gid, int uid) { chat.kick_from_group_call(gid, uid); };
    chat_controller.on_group_deleted = [&](int gid) { chat.end_group_call(gid, "group_deleted"); };// до запуска сервера
    AuthController auth_controller(db_pool, session_repository,chat);
    auth_controller.register_routes(router);
    UploadCleaner cleaner(cleaner_repo);
    cleaner.start();
    PeriodicTask call_sweeper(std::chrono::seconds(5), [&]() { chat.sweep_calls(); });
    call_sweeper.start();

    if (crypto().enabled())
    {
        long long total = 0;
        int n = 0;
        while ((n = cleaner_repo.encrypt_legacy_messages(200)) > 0)  total += n;
        while ((n = groups.encrypt_legacy_messages(200)) > 0) total += n;

        const int files = migrate_legacy_files();
        const int upgraded = upgrade_encrypted_files();    // зашифрованные целиком в блочный формат
        std::cout << "Crypto: зашифровано сообщений " << total
            << ", файлов " << files << ", переведено в блочный формат " << upgraded << std::endl;
    }

    try
    {
        boost::asio::io_context io;

        Server server(io, 8765, pool, router,chat);

        std::cout << "Server started on port 8080\n";

        io.run();
        /*pool.shutdown();*/
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
    }
}