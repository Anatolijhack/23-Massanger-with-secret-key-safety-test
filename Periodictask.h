#pragma once
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

// Вызывает fn каждые period секунд в отдельном потоке. Деструктор останавливает поток.
class PeriodicTask
{
public:
    PeriodicTask(std::chrono::seconds period, std::function<void()> fn)
        : period(period), fn(std::move(fn)) {}

    ~PeriodicTask() { stop(); }

    void start()
    {
        worker = std::thread([this]()
            {
                std::unique_lock<std::mutex> lk(m);
                while (!stopping)
                {
                    cv.wait_for(lk, period, [this] { return stopping; });
                    if (stopping) break;

                    lk.unlock();
                    fn();
                    lk.lock();
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

private:
    std::chrono::seconds period;
    std::function<void()> fn;

    std::thread worker;
    std::mutex m;
    std::condition_variable cv;
    bool stopping = false;
};