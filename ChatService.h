#pragma once
#include "СhatHub.h"
#include "ChatRepository.h"
#include "UserRepository.h"
#include "SessionRepository.h"
#include "ThreadPool.h"
#include <memory>
#include <nlohmann/json.hpp>
#include "GroupRepository.h"
#include "Session.h"
#include "CallManager.h"
#include "Groupcallmanager .h"

using json = nlohmann::json;
class Session;
struct AttachmentMeta
{
    std::string name;
    int duration_ms = 0;
};
class ChatService
{
public:
    ChatService(ConnectionPool& pool, SessionRepository& sessions, ThreadPool& workers,
        std::vector<std::string> allowed_origins = {})
        : chats(pool), users(pool),group_reposs(pool), sessions(sessions), workers(workers),
        allowed_origins(std::move(allowed_origins)) {}

    void on_text(const std::shared_ptr<Session>& s, const std::string& raw);   // io-поток
    void on_binary(const std::shared_ptr<Session>& s);
    void kick_user(int user_id);                                               // закрыть все соединения
    bool origin_allowed(const std::string& origin) const;
    void on_close(const Session::ChatIdentity& who, const Session* s);
    void handle_read(const std::shared_ptr<Session>& s, const json& msg);
    std::optional<std::string> attachment_name_for(const std::string& url, int user_id);
    void drop_stream(const std::string& id);
    void sse_open(const std::shared_ptr<Session>& s, const std::string& token);
    std::shared_ptr<Session> find_stream(const std::string& id);
    void poll_open(const std::shared_ptr<Session>& http, const std::string& token);
    void sweep_calls();
    void finish_call(const Call& c, const std::string& status);
    
    void kick_from_group_call(int group_id, int user_id);
    void end_group_call(int group_id, const std::string& reason);
    std::optional<AttachmentMeta> attachment_meta_for(const std::string& url, int user_id);
private:
    using json = nlohmann::json;
    
    void handle_auth(const std::shared_ptr<Session>& s, const json& msg);
    void handle_message(const std::shared_ptr<Session>& s, const json& msg);
    void reply_error(const std::shared_ptr<Session>& s, const char* code, const char* text);
    void handle_edit(const std::shared_ptr<Session>& s, const json& msg);
    void handle_delete(const std::shared_ptr<Session>& s, const json& msg);
    static bool can_message(const std::string& a, const std::string& b);
    static std::string dump(const json& j);
    void announce_online(const Session::ChatIdentity& who, const std::shared_ptr<Session>& s);
    void announce_offline(const Session::ChatIdentity& who);
    void handle_typing(const std::shared_ptr<Session>& s, const json& msg);
    void handle_call(const std::shared_ptr<Session>& s, const json& msg, const std::string& type);
    void send_to_user(int user_id, const std::string& payload);
    void end_calls_of_device(const Session* dev);
    void end_ringing_for_callee(int user_id);
    void handle_gcall(const std::shared_ptr<Session>& s, const json& msg, const std::string& type);
    void after_gcall_leave(const GroupCallManager::LeaveOutcome& lv);
    void broadcast_group(int group_id, const std::string& payload, const Session* except);
    void send_group_call_snapshot(const std::shared_ptr<Session>& s, int user_id);
    void finish_group_call(const GroupCall& call);
  

  

    
    GroupCallManager group_calls;
    CallManager calls;
    ChatHub hub;
    ChatRepository chats;
    UserRepository users;
    GroupRepository group_reposs;
    SessionRepository& sessions;
    ThreadPool& workers;
    std::mutex streams_m;
    std::unordered_map<std::string, std::weak_ptr<Session>> streams;
    std::unordered_map<std::string, std::shared_ptr<Session>> devices;

    std::vector<std::string> allowed_origins;
};