#pragma once
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

class Session;

struct Call
{
    enum class State { Ringing, Active };

    std::string id;
    int caller_id = 0;
    int callee_id = 0;
    std::string caller_login;
    std::string callee_login;
    bool video = false;
    State state = State::Ringing;
    std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point answered{};

    // Устройства (WebSocket-сессии), участвующие в звонке.
    // callee_* заполняются только после принятия звонка.
    std::weak_ptr<Session> caller_ws;
    std::weak_ptr<Session> callee_ws;
    const Session* caller_raw = nullptr;     // только для сравнения адреса, не разыменовывать
    const Session* callee_raw = nullptr;
};

// Все звонки живут в памяти процесса. Медиа через сервер не идёт:
// здесь только состояние и проверка, кто что имеет право делать.
class CallManager
{
public:
    bool in_call(int user_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        return by_user.count(user_id) > 0;
    }
    // Создаёт звонок в состоянии Ringing.
    // Если кто-то из двоих уже в звонке, возвращает nullopt, а reason = "already_in_call" или "callee_busy".
    std::optional<Call> create(int caller_id, const std::string& caller_login,
        int callee_id, const std::string& callee_login,
        bool video, const std::shared_ptr<Session>& caller_ws,
        std::string& reason)
    {
        std::lock_guard<std::mutex> lock(mtx);

        if (by_user.count(caller_id)) { reason = "already_in_call"; return std::nullopt; }
        if (by_user.count(callee_id)) { reason = "callee_busy";     return std::nullopt; }

        Call c;
        c.id = new_id();
        c.caller_id = caller_id;
        c.callee_id = callee_id;
        c.caller_login = caller_login;
        c.callee_login = callee_login;
        c.video = video;
        c.caller_ws = caller_ws;
        c.caller_raw = caller_ws.get();

        by_id[c.id] = c;
        by_user[caller_id] = c.id;
        by_user[callee_id] = c.id;
        return c;
    }

    std::optional<Call> get(const std::string& id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = by_id.find(id);
        if (it == by_id.end()) return std::nullopt;
        return it->second;
    }

    // Принять может только вызываемый и только пока идёт вызов. Звонок привязывается к устройству.
    std::optional<Call> accept(const std::string& id, int user_id, const std::shared_ptr<Session>& ws)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = by_id.find(id);
        if (it == by_id.end()) return std::nullopt;

        Call& c = it->second;
        if (c.callee_id != user_id || c.state != Call::State::Ringing) return std::nullopt;

        c.state = Call::State::Active;
        c.callee_ws = ws;
        c.callee_raw = ws.get();
        c.answered = std::chrono::steady_clock::now();
        return c;
    }

    // Удаляет звонок, если условие выполнено. Проверка и удаление идут под одним замком.
    template <class Pred>
    std::optional<Call> remove_if(const std::string& id, Pred pred)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = by_id.find(id);
        if (it == by_id.end() || !pred(it->second)) return std::nullopt;

        Call copy = it->second;
        erase_locked(it);
        return copy;
    }

    // Вызовы, на которые никто не ответил за ttl
    std::vector<Call> remove_expired_ringing(std::chrono::seconds ttl)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Call> out;
        const auto now = std::chrono::steady_clock::now();

        for (auto it = by_id.begin(); it != by_id.end();)
        {
            if (it->second.state == Call::State::Ringing && now - it->second.created >= ttl)
            {
                out.push_back(it->second);
                it = erase_locked(it);
            }
            else ++it;
        }
        return out;
    }

    // Звонки, привязанные к закрывшемуся устройству
    std::vector<Call> remove_by_device(const Session* dev)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Call> out;

        for (auto it = by_id.begin(); it != by_id.end();)
        {
            if (it->second.caller_raw == dev || (it->second.callee_raw && it->second.callee_raw == dev))
            {
                out.push_back(it->second);
                it = erase_locked(it);
            }
            else ++it;
        }
        return out;
    }

    // Идущие вызовы для пользователя, у которого не осталось ни одного соединения
    std::vector<Call> remove_ringing_for_callee(int user_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Call> out;

        for (auto it = by_id.begin(); it != by_id.end();)
        {
            if (it->second.callee_id == user_id && it->second.state == Call::State::Ringing)
            {
                out.push_back(it->second);
                it = erase_locked(it);
            }
            else ++it;
        }
        return out;
    }

private:
    using Map = std::unordered_map<std::string, Call>;

    Map::iterator erase_locked(Map::iterator it)
    {
        by_user.erase(it->second.caller_id);
        by_user.erase(it->second.callee_id);
        return by_id.erase(it);
    }

    static std::string new_id()
    {
        thread_local std::mt19937_64 gen{ std::random_device{}() };
        std::uniform_int_distribution<uint64_t> dist;

        std::ostringstream oss;
        oss << std::hex << std::setw(16) << std::setfill('0') << dist(gen);
        return oss.str();
    }

    std::mutex mtx;
    Map by_id;
    std::unordered_map<int, std::string> by_user;     // пользователь -> его текущий звонок
};