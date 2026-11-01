#pragma once
#include <algorithm>
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
#include <utility>
#include <vector>

class Session;

using GcClock = std::chrono::steady_clock;

struct GroupCallMember
{
    int user_id = 0;
    std::string login;
    bool video = false;
    std::weak_ptr<Session> ws;
    const Session* raw = nullptr;
    GcClock::time_point joined = GcClock::now();
};

// Завершённый заход участника: человек мог входить и выходить несколько раз
struct GroupCallStay
{
    int user_id = 0;
    std::string login;
    GcClock::time_point joined{};
    GcClock::time_point left{};
};

struct GroupCall
{
    std::string id;
    int group_id = 0;
    std::string group_name;
    std::string started_by;
    int started_by_id = 0;
    bool video = false;
    GcClock::time_point created = GcClock::now();
    size_t peak = 0;                              // наибольшее число участников одновременно
    std::vector<GroupCallMember> members;
    std::vector<GroupCallStay> stays;             // для истории
};

class GroupCallManager
{
public:
    static constexpr size_t MAX_MEMBERS = 4;

    enum class JoinResult { Started, Joined, Full, AlreadyIn };

    struct JoinOutcome
    {
        JoinResult result = JoinResult::AlreadyIn;
        GroupCall call;
        std::vector<GroupCallMember> others;
    };

    struct LeaveOutcome
    {
        GroupCall call;                           // оставшиеся участники и накопленные заходы
        GroupCallMember left;
        bool ended = false;
    };

    JoinOutcome join(int group_id, const std::string& group_name, int user_id,
        const std::string& login, bool video, const std::shared_ptr<Session>& ws)
    {
        std::lock_guard<std::mutex> lock(mtx);
        JoinOutcome out;

        if (by_user.count(user_id)) { out.result = JoinResult::AlreadyIn; return out; }

        GroupCallMember me;
        me.user_id = user_id;
        me.login = login;
        me.video = video;
        me.ws = ws;
        me.raw = ws.get();
        me.joined = GcClock::now();

        auto git = by_group.find(group_id);
        if (git == by_group.end())
        {
            GroupCall c;
            c.id = new_id();
            c.group_id = group_id;
            c.group_name = group_name;
            c.started_by = login;
            c.started_by_id = user_id;
            c.video = video;
            c.created = me.joined;
            c.members.push_back(me);
            c.peak = 1;

            by_group[group_id] = c.id;
            by_user[user_id] = c.id;
            out.call = c;
            by_id[c.id] = std::move(c);
            out.result = JoinResult::Started;
            return out;
        }

        GroupCall& c = by_id[git->second];
        if (c.members.size() >= MAX_MEMBERS) { out.result = JoinResult::Full; return out; }

        out.others = c.members;
        c.members.push_back(me);
        c.peak = (std::max)(c.peak, c.members.size());
        by_user[user_id] = c.id;
        out.call = c;
        out.result = JoinResult::Joined;
        return out;
    }

    std::optional<LeaveOutcome> leave(const std::string& call_id, const Session* dev)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = by_id.find(call_id);
        if (it == by_id.end()) return std::nullopt;
        return leave_locked(it, dev);
    }

    std::optional<LeaveOutcome> leave_by_device(const Session* dev)
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (auto it = by_id.begin(); it != by_id.end(); ++it)
            if (auto lv = leave_locked(it, dev)) return lv;
        return std::nullopt;
    }

    // Убрать человека из звонка его группы (удалили из группы или он вышел из неё)
    std::optional<LeaveOutcome> kick_user(int group_id, int user_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto g = by_group.find(group_id);
        if (g == by_group.end()) return std::nullopt;

        auto it = by_id.find(g->second);
        if (it == by_id.end()) return std::nullopt;

        for (const auto& m : it->second.members)
            if (m.user_id == user_id)
                return leave_locked(it, m.raw);
        return std::nullopt;
    }

    // Группа удалена: закрыть звонок целиком и вернуть его, чтобы оповестить участников
    std::optional<GroupCall> end_group(int group_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto g = by_group.find(group_id);
        if (g == by_group.end()) return std::nullopt;

        const std::string id = g->second;
        auto it = by_id.find(id);
        if (it == by_id.end()) { by_group.erase(g); return std::nullopt; }

        GroupCall c = it->second;
        for (const auto& m : c.members) by_user.erase(m.user_id);
        by_group.erase(g);
        by_id.erase(it);
        return c;
    }

    std::optional<std::pair<GroupCallMember, GroupCallMember>>
        resolve_pair(const std::string& call_id, const Session* dev, const std::string& to_login)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = by_id.find(call_id);
        if (it == by_id.end()) return std::nullopt;

        const GroupCall& c = it->second;
        auto from = std::find_if(c.members.begin(), c.members.end(),
            [dev](const GroupCallMember& m) { return m.raw == dev; });
        auto to = std::find_if(c.members.begin(), c.members.end(),
            [&](const GroupCallMember& m) { return m.login == to_login; });

        if (from == c.members.end() || to == c.members.end() || from == to) return std::nullopt;
        return std::make_pair(*from, *to);
    }

    std::optional<GroupCall> find_by_group(int group_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto g = by_group.find(group_id);
        if (g == by_group.end()) return std::nullopt;
        return by_id[g->second];
    }

    bool in_call(int user_id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        return by_user.count(user_id) > 0;
    }

private:
    using Map = std::unordered_map<std::string, GroupCall>;

    std::optional<LeaveOutcome> leave_locked(Map::iterator it, const Session* dev)
    {
        GroupCall& c = it->second;
        auto m = std::find_if(c.members.begin(), c.members.end(),
            [dev](const GroupCallMember& x) { return x.raw == dev; });
        if (m == c.members.end()) return std::nullopt;

        LeaveOutcome out;
        out.left = *m;

        GroupCallStay st;
        st.user_id = m->user_id;
        st.login = m->login;
        st.joined = m->joined;
        st.left = GcClock::now();
        c.stays.push_back(std::move(st));

        by_user.erase(m->user_id);
        c.members.erase(m);
        out.call = c;

        if (c.members.empty())
        {
            out.ended = true;
            by_group.erase(c.group_id);
            by_id.erase(it);                 // после этого it и c недействительны
        }
        return out;
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
    std::unordered_map<int, std::string> by_group;
    std::unordered_map<int, std::string> by_user;
};