#pragma once
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <thread>
#include "ChatRepository.h"


class UploadCleaner
{
public:
    UploadCleaner(ChatRepository& repo,
        std::filesystem::path dir = "uploads/chat",
        std::chrono::hours min_age = std::chrono::hours(24),
        std::chrono::minutes period = std::chrono::minutes(60))
        : repo(repo), dir(std::move(dir)), min_age(min_age), period(period) {}

    ~UploadCleaner() { stop(); }

    void start()
    {
        worker = std::thread([this]()
            {
                std::unique_lock<std::mutex> lk(m);
                while (!stopping)
                {
                    lk.unlock();
                    run_once();
                    lk.lock();
                    cv.wait_for(lk, period, [this] { return stopping; });
                }
            });
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lk(m);
            stopping = true;
        }
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }

    void run_once()
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        int removed = 0, kept = 0;

        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        {
            if (!it->is_regular_file(ec)) continue;

            const std::string name = it->path().filename().string();
            const std::string url = "/uploads/chat/" + name;

            if (!is_valid_attachment_url(url)) continue;     // чужие файлы не трогаем

            auto age = fs::file_time_type::clock::now() - it->last_write_time(ec);
            if (ec || age < min_age) { ec.clear(); continue; }

            auto used = repo.attachment_in_use(url);
            if (!used || *used) { ++kept; continue; }        // ошибка БД или файл нужен

            if (fs::remove(it->path(), ec))
            {
                repo.delete_upload(name);                    // убираем и запись об имени файла
                ++removed;
            }
            ec.clear();
        }

        if (removed > 0)
            std::cout << "UploadCleaner: removed " << removed << " orphan files" << std::endl;
    }

private:
    ChatRepository& repo;
    std::filesystem::path dir;
    std::chrono::hours min_age;
    std::chrono::minutes period;

    std::thread worker;
    std::mutex m;
    std::condition_variable cv;
    bool stopping = false;
};