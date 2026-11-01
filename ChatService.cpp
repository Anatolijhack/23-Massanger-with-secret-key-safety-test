#include "ChatService.h"
#include "Session.h"
#include "Logger.h"
#include "Atachments.h"

using namespace std::chrono_literals;
using json = nlohmann::json;



static std::string random_hex(size_t bytes)
{
    std::string raw(bytes, '\0');
    RAND_bytes(reinterpret_cast<unsigned char*>(&raw[0]), static_cast<int>(bytes));
    static const char* d = "0123456789abcdef";
    std::string out;
    for (unsigned char c : raw) { out += d[c >> 4]; out += d[c & 15]; }
    return out;
}

std::string ChatService::dump(const json& j)
{
    // replace: битый UTF-8 не бросит исключение, как раньше с 0xEF
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

bool ChatService::can_message(const std::string& a, const std::string& b)
{
    auto staff = [](const std::string& r) { return r == "admin" || r == "employee" || r == "seller"; };
    return staff(a) || staff(b);
}

bool ChatService::origin_allowed(const std::string& origin) const
{
    if (allowed_origins.empty()) return true;   // dev-режим
    return std::find(allowed_origins.begin(), allowed_origins.end(), origin) != allowed_origins.end();
}

void ChatService::reply_error(const std::shared_ptr<Session>& s, const char* code, const char* text)
{
    s->ws_send(dump({ {"type", "error"}, {"code", code}, {"message", text} }));
}

void ChatService::kick_user(int user_id)
{
    for (auto& s : hub.sessions_of(user_id)) s->ws_close(1008, "session ended");
}

void ChatService::on_binary(const std::shared_ptr<Session>& s)
{
    reply_error(s, "unsupported", "Binary frames are not supported");
}

void ChatService::on_text(const std::shared_ptr<Session>& s, const std::string& raw)
{
    json msg = json::parse(raw, nullptr, false);   // без исключений

    if (msg.is_discarded() || !msg.is_object() || !msg.contains("type") || !msg["type"].is_string())
        return reply_error(s, "bad_request", "Invalid message");

    const std::string type = msg["type"].get<std::string>();
    if (type == "ping") { s->ws_send(R"({"type":"pong"})"); return; }
    if (type == "auth") return handle_auth(s, msg);
    
    if (!s->chat_identity)
        return reply_error(s, "unauthorized", "Send auth first");
    if (type.rfind("call_", 0) == 0) return handle_call(s, msg, type);
    if (type.rfind("gcall_", 0) == 0) return handle_gcall(s, msg, type);
    if (type == "message") return handle_message(s, msg);
    if (type == "read")    return handle_read(s, msg);
    if (type == "typing")  return handle_typing(s, msg);
    if (type == "edit")    return handle_edit(s, msg);
    if (type == "delete")  return handle_delete(s, msg);

    reply_error(s, "unknown_type", "Unknown message type");
}

void ChatService::handle_message(const std::shared_ptr<Session>& s, const json& msg)
{
    if (!s->chat_identity)
        return reply_error(s, "unauthorized", "Authenticate first");

    if (!s->allow_chat_message())
        return reply_error(s, "rate_limited", "Too many messages");

    const bool has_to = msg.contains("to") && msg["to"].is_string();
    const bool has_group = msg.contains("group") && msg["group"].is_string();

    if (!has_to && !has_group)
        return reply_error(s, "bad_request", "to or group required");

    if (msg.contains("to") && msg.contains("group"))
        return reply_error(s, "bad_request", "Specify to or group");

    // ---------- текст (необязателен, если есть вложение) ----------
    std::string text;
    if (msg.contains("text"))
    {
        if (!msg["text"].is_string())
            return reply_error(s, "bad_request", "text must be a string");
        text = msg["text"].get<std::string>();
    }

    const char* ws = " \t\r\n";
    size_t b = text.find_first_not_of(ws);
    if (b == std::string::npos) text.clear();
    else text = text.substr(b, text.find_last_not_of(ws) - b + 1);

    // ---------- вложение ----------
    std::string attachment;
    if (msg.contains("attachment"))
    {
        if (!msg["attachment"].is_string())
            return reply_error(s, "bad_request", "attachment must be a string");

        attachment = msg["attachment"].get<std::string>();
        if (!is_valid_attachment_url(attachment))
            return reply_error(s, "bad_request", "Invalid attachment");
    }

    if (text.empty() && attachment.empty())
        return reply_error(s, "empty", "Message is empty");

    if (text.size() > 2000)
        return reply_error(s, "too_long", "Message is too long (max 2000 bytes)");

    // ---------- ответ на сообщение ----------
    long long reply_to = 0;
    if (msg.contains("reply_to"))
    {
        if (!msg["reply_to"].is_number_integer())
            return reply_error(s, "bad_request", "reply_to must be an integer");

        reply_to = msg["reply_to"].get<long long>();
        if (reply_to <= 0)
            return reply_error(s, "bad_request", "Invalid reply_to");
    }

    Session::ChatIdentity sender = *s->chat_identity;

    // ======================= ГРУППА / КАНАЛ =======================
    if (has_group)
    {
        std::string group_name = msg["group"].get<std::string>();

        bool queued = workers.try_push_task(
            [this, s, sender, group_name, text, attachment, reply_to]()
            {
                std::string attachment_name;
                int attachment_duration = 0;
                if (!attachment.empty())
                {
                    auto meta = attachment_meta_for(attachment, sender.user_id);
                    if (!meta)
                    {
                        s->ws_post([this, s]() { reply_error(s, "bad_request", "Invalid attachment"); });
                        return;
                    }
                    attachment_name = meta->name;
                    attachment_duration = meta->duration_ms;
                }   
                auto group = group_reposs.find_by_name(group_name);
                
                if (!group)
                {
                    s->ws_post([this, s]() {
                        reply_error(s, "group_not_found", "Group not found");
                        });
                    return;
                }

                // участник ли отправитель и какая у него роль
                auto role = group_reposs.get_member_role(group->id, sender.user_id);

                // не участник: отвечаем так же, как «группа не найдена»
                if (!role)
                {
                    s->ws_post([this, s]() {
                        reply_error(s, "group_not_found", "Group not found");
                        });
                    return;
                }

                // в канале пишут только владелец и админы
                if (group->kind == "channel" && *role != "owner" && *role != "admin")
                {
                    s->ws_post([this, s]() {
                        reply_error(s, "forbidden", "Only admins can post in a channel");
                        });
                    return;
                }

                // отвечать можно только на сообщение из этой же группы
                if (reply_to > 0 && group_reposs.group_message_exists(group->id, reply_to) != 1)
                {
                    s->ws_post([this, s]() {
                        reply_error(s, "reply_not_found", "Message to reply to not found");
                        });
                    return;
                }

                auto saved = group_reposs.save_messages(
                    group->id, sender.user_id, text, attachment, reply_to,attachment_name);

                if (!saved)
                {
                    s->ws_post([this, s]() {
                        reply_error(s, "server_error", "Could not save group message");
                        });
                    return;
                }

                json j = {
                    {"type", "group_message"},
                    {"id", saved->id},
                    {"group_id", group->id},
                    {"group", group->name},
                    {"kind", group->kind},
                    {"from", sender.login},
                    {"text", text},
                    {"ts", saved->created_at}
                };
                if (!attachment.empty())
                {
                    j["attachment"] = attachment;
                    j["attachment_name"] = attachment_name;
                    add_attachment_meta(j, attachment, attachment_duration);
                };
                if (reply_to > 0)        j["reply_to"] = reply_to;
                std::string out = dump(j);

                auto members = group_reposs.get_member_ids(group->id);

                for (int user_id : members)
                {
                    for (auto& rs : hub.sessions_of(user_id))
                        rs->ws_send(out);
                }

                json ack = {
                    {"type", "group_sent"},
                    {"id", saved->id},
                    {"group_id", group->id},
                    {"group", group->name},
                    {"kind", group->kind},
                    {"ts", saved->created_at}
                };
                if (!attachment.empty())
                {
                    ack["attachment"] = attachment;
                    ack["attachment_name"] = attachment_name;
                    add_attachment_meta(ack, attachment, attachment_duration);
                };
                if (reply_to > 0)        ack["reply_to"] = reply_to;
                s->ws_send(dump(ack));
            }, 0);

        if (!queued)
            reply_error(s, "busy", "Server busy, try again");

        return;
    }

    // ===================== ЛИЧНОЕ СООБЩЕНИЕ =====================
    std::string to = msg["to"].get<std::string>();

    bool queued = workers.try_push_task([this, s, sender, to, text, attachment, reply_to]()
        {
            std::string attachment_name;
            int attachment_duration = 0;
            if (!attachment.empty())
            {
                auto meta = attachment_meta_for(attachment, sender.user_id);
                if (!meta)
                {
                    s->ws_post([this, s]() { reply_error(s, "bad_request", "Invalid attachment"); });
                    return;
                }
                attachment_name = meta->name;
                attachment_duration = meta->duration_ms;
            }

            auto recipient = users.find_by_username(to);

            // «нет такого» и «нельзя писать» отвечаем одинаково — логины не перебрать
            if (!recipient || recipient->id == sender.user_id || !can_message(sender.role, recipient->role))
            {
                s->ws_post([this, s]() { reply_error(s, "recipient_not_found", "Recipient not found"); });
                return;
            }

            // отвечать можно только на сообщение из этой же переписки
            if (reply_to > 0 && chats.direct_message_exists(sender.user_id, recipient->id, reply_to) != 1)
            {
                s->ws_post([this, s]() { reply_error(s, "reply_not_found", "Message to reply to not found"); });
                return;
            }

            auto saved = chats.save(sender.user_id, recipient->id, text, attachment, reply_to, attachment_name);

            if (!saved)
            {
                s->ws_post([this, s]() { reply_error(s, "server_error", "Could not save message"); });
                return;
            }

            json j = {
                {"type", "message"}, {"id", saved->id}, {"from", sender.login},
                {"text", text}, {"ts", saved->created_at}
            };
            if (!attachment.empty())
            {
                j["attachment"] = attachment;
                j["attachment_name"] = attachment_name;
                add_attachment_meta(j, attachment, attachment_duration);
            }
            if (reply_to > 0)        j["reply_to"] = reply_to;
            std::string out = dump(j);

            for (auto& rs : hub.sessions_of(recipient->id)) rs->ws_send(out);

            json ack = {
                {"type", "sent"}, {"id", saved->id},
                {"to", recipient->username}, {"ts", saved->created_at}
            };
            if (!attachment.empty())
            { 
                ack["attachment"] = attachment;
                ack["attachment_name"] = attachment_name;
                add_attachment_meta(ack, attachment, attachment_duration);
            }
            if (reply_to > 0)        ack["reply_to"] = reply_to;
            s->ws_send(dump(ack));
        }, 0);

    if (!queued) reply_error(s, "busy", "Server busy, try again");
}

void ChatService::handle_auth(const std::shared_ptr<Session>& s, const json& msg)
{
    if (s->chat_identity) return reply_error(s, "already_authenticated", "Already authenticated");

    if (!msg.contains("token") || !msg["token"].is_string())
        return reply_error(s, "bad_request", "token required");

    std::string token = msg["token"].get<std::string>();

    bool queued = workers.try_push_task([this, s, token]()
        {
            auto session = sessions.find(token);          // ÁÄ — â ïóëå, íå â io-ïîòîêå

            s->ws_post([this, s, session]()               // îáðàòíî â ïîòîê ñîêåòà
                {
                    if (s->chat_identity) return;

                    if (!session)
                    {
                        reply_error(s, "unauthorized", "Invalid or expired token");
                        s->ws_close(1008, "unauthorized");
                        return;
                    }
                    bool first = false;
                    if (!hub.attach(session->user_id, s, &first))
                    {
                        reply_error(s, "too_many_connections", "Too many open connections");
                        s->ws_close(1008, "too many connections");
                        return;
                    }

                    s->chat_identity = Session::ChatIdentity{ session->user_id, session->username, session->role };
                    s->ws_send(dump({ {"type", "auth_ok"}, {"login", session->username} }));
                    announce_online(*s->chat_identity, s);
                });
        }, 0);

    if (!queued) reply_error(s, "busy", "Server busy, try again");
}

void ChatService::handle_edit(const std::shared_ptr<Session>& s, const json& msg)
{
    if (!s->chat_identity)
        return reply_error(s, "unauthorized", "Authenticate first");

    if (!s->allow_chat_message())
        return reply_error(s, "rate_limited", "Too many messages");

    if (!msg.contains("id") || !msg["id"].is_number_integer() || msg["id"].get<long long>() <= 0)
        return reply_error(s, "bad_request", "id required");
    const long long id = msg["id"].get<long long>();

    const bool has_to = msg.contains("to") && msg["to"].is_string();
    const bool has_group = msg.contains("group") && msg["group"].is_string();
    if (has_to == has_group)
        return reply_error(s, "bad_request", "Specify to or group");

    if (!msg.contains("text") || !msg["text"].is_string())
        return reply_error(s, "bad_request", "text required");

    std::string text = msg["text"].get<std::string>();
    const char* ws = " \t\r\n";
    size_t b = text.find_first_not_of(ws);
    if (b == std::string::npos) return reply_error(s, "empty", "Message is empty");
    text = text.substr(b, text.find_last_not_of(ws) - b + 1);
    if (text.size() > 2000) return reply_error(s, "too_long", "Message is too long (max 2000 bytes)");

    Session::ChatIdentity sender = *s->chat_identity;

    if (has_group)
    {
        std::string group_name = msg["group"].get<std::string>();

        bool queued = workers.try_push_task([this, s, sender, group_name, id, text]()
            {
                auto group = group_reposs.find_by_name(group_name);
                auto role = group ? group_reposs.get_member_role(group->id, sender.user_id) : std::nullopt;

                if (!group || !role)
                {
                    s->ws_post([this, s]() { reply_error(s, "group_not_found", "Group not found"); });
                    return;
                }

                long rows = group_reposs.edit_message(group->id, sender.user_id, id, text);

                if (rows < 0)
                {
                    s->ws_post([this, s]() { reply_error(s, "server_error", "Could not edit message"); });
                    return;
                }
                if (rows == 0)
                {
                    s->ws_post([this, s]() { reply_error(s, "message_not_found", "Message not found"); });
                    return;
                }

                std::string out = dump({
                    {"type", "message_edited"}, {"group_id", group->id}, {"group", group->name},
                    {"id", id}, {"text", text}, {"edited", true}
                    });

                for (int user_id : group_reposs.get_member_ids(group->id))
                    for (auto& rs : hub.sessions_of(user_id))
                        rs->ws_send(out);
            }, 0);

        if (!queued) reply_error(s, "busy", "Server busy, try again");
        return;
    }

    std::string to = msg["to"].get<std::string>();

    bool queued = workers.try_push_task([this, s, sender, to, id, text]()
        {
            auto recipient = users.find_by_username(to);
            if (!recipient)
            {
                s->ws_post([this, s]() { reply_error(s, "recipient_not_found", "Recipient not found"); });
                return;
            }

            long rows = chats.edit_direct(sender.user_id, recipient->id, id, text);

            if (rows < 0)
            {
                s->ws_post([this, s]() { reply_error(s, "server_error", "Could not edit message"); });
                return;
            }
            if (rows == 0)
            {
                s->ws_post([this, s]() { reply_error(s, "message_not_found", "Message not found"); });
                return;
            }

            std::string out = dump({
                {"type", "message_edited"}, {"id", id}, {"from", sender.login},
                {"to", recipient->username}, {"text", text}, {"edited", true}
                });

            // получателю и всем устройствам отправителя
            for (auto& rs : hub.sessions_of(recipient->id)) rs->ws_send(out);
            for (auto& rs : hub.sessions_of(sender.user_id)) rs->ws_send(out);
        }, 0);

    if (!queued) reply_error(s, "busy", "Server busy, try again");
}

void ChatService::handle_delete(const std::shared_ptr<Session>& s, const json& msg)
{
    if (!s->chat_identity)
        return reply_error(s, "unauthorized", "Authenticate first");

    if (!s->allow_chat_message())
        return reply_error(s, "rate_limited", "Too many messages");

    if (!msg.contains("id") || !msg["id"].is_number_integer() || msg["id"].get<long long>() <= 0)
        return reply_error(s, "bad_request", "id required");
    const long long id = msg["id"].get<long long>();

    const bool has_to = msg.contains("to") && msg["to"].is_string();
    const bool has_group = msg.contains("group") && msg["group"].is_string();
    if (has_to == has_group)
        return reply_error(s, "bad_request", "Specify to or group");

    Session::ChatIdentity sender = *s->chat_identity;

    if (has_group)
    {
        std::string group_name = msg["group"].get<std::string>();

        bool queued = workers.try_push_task([this, s, sender, group_name, id]()
            {
                auto group = group_reposs.find_by_name(group_name);
                auto role = group ? group_reposs.get_member_role(group->id, sender.user_id) : std::nullopt;

                if (!group || !role)
                {
                    s->ws_post([this, s]() { reply_error(s, "group_not_found", "Group not found"); });
                    return;
                }

                // владелец и админы удаляют любые сообщения, остальные только свои
                const bool moderator = (*role == "owner" || *role == "admin");
                long rows = group_reposs.delete_message(group->id, id, moderator ? 0 : sender.user_id);

                if (rows < 0)
                {
                    s->ws_post([this, s]() { reply_error(s, "server_error", "Could not delete message"); });
                    return;
                }
                if (rows == 0)
                {
                    s->ws_post([this, s]() { reply_error(s, "message_not_found", "Message not found"); });
                    return;
                }

                std::string out = dump({
                    {"type", "message_deleted"}, {"group_id", group->id},
                    {"group", group->name}, {"id", id}
                    });

                for (int user_id : group_reposs.get_member_ids(group->id))
                    for (auto& rs : hub.sessions_of(user_id))
                        rs->ws_send(out);
            }, 0);

        if (!queued) reply_error(s, "busy", "Server busy, try again");
        return;
    }

    std::string to = msg["to"].get<std::string>();

    bool queued = workers.try_push_task([this, s, sender, to, id]()
        {
            auto recipient = users.find_by_username(to);
            if (!recipient)
            {
                s->ws_post([this, s]() { reply_error(s, "recipient_not_found", "Recipient not found"); });
                return;
            }

            long rows = chats.delete_direct(sender.user_id, recipient->id, id);

            if (rows < 0)
            {
                s->ws_post([this, s]() { reply_error(s, "server_error", "Could not delete message"); });
                return;
            }
            if (rows == 0)
            {
                s->ws_post([this, s]() { reply_error(s, "message_not_found", "Message not found"); });
                return;
            }

            std::string out = dump({
                {"type", "message_deleted"}, {"id", id},
                {"from", sender.login}, {"to", recipient->username}
                });

            for (auto& rs : hub.sessions_of(recipient->id)) rs->ws_send(out);
            for (auto& rs : hub.sessions_of(sender.user_id)) rs->ws_send(out);
        }, 0);

    if (!queued) reply_error(s, "busy", "Server busy, try again");
}

// Вызывается сразу после auth_ok
void ChatService::announce_online(const Session::ChatIdentity& who, const std::shared_ptr<Session>& s)
{
    // это первое соединение пользователя? (новая сессия уже в хабе)
   

    workers.try_push_task([this, who, s]()
        {
            send_group_call_snapshot(s, who.user_id);
            auto partners = chats.partners(who.user_id);

            // 1. снимок для самого пользователя: кто из собеседников онлайн
            json items = json::array();
            for (const auto& p : partners)
            {
                const bool online = !hub.sessions_of(p.id).empty();
                json it = { {"login", p.login}, {"online", online} };
                if (!online && !p.last_seen.empty()) it["last_seen"] = p.last_seen;
                items.push_back(std::move(it));
            }
            s->ws_send(dump({ {"type", "presence_snapshot"}, {"items", items} }));

            // 2. собеседникам сообщаем только про первое соединение
            

            std::string out = dump({ {"type", "presence"}, {"login", who.login}, {"online", true} });
            for (const auto& p : partners)
                for (auto& rs : hub.sessions_of(p.id))
                    rs->ws_send(out);
        }, 0);
}

// Вызывается при закрытии сокета, после hub.detach
void ChatService::announce_offline(const Session::ChatIdentity& who)
{
                             // остались другие устройства

    workers.try_push_task([this, who]()
        {
            std::string seen = chats.touch_last_seen(who.user_id);
            auto partners = chats.partners(who.user_id);

            json j = { {"type", "presence"}, {"login", who.login}, {"online", false} };
            if (!seen.empty()) j["last_seen"] = seen;
            std::string out = dump(j);

            for (const auto& p : partners)
                for (auto& rs : hub.sessions_of(p.id))
                    rs->ws_send(out);
        }, 0);
}

void ChatService::handle_typing(const std::shared_ptr<Session>& s, const json& msg)
{
    // ошибки не шлём: «печатает» не должно спамить клиента
    if (!s->chat_identity) return;
    Session::ChatIdentity sender = *s->chat_identity;

    // не чаще раза в 2 секунды на пользователя
    const bool has_to = msg.contains("to") && msg["to"].is_string();
    const bool has_group = msg.contains("group") && msg["group"].is_string();
    if (has_to == has_group) return;

    if (has_to)
    {
        std::string to = msg["to"].get<std::string>();

        workers.try_push_task([this, sender, to]()
            {
                auto recipient = users.find_by_username(to);
                if (!recipient || recipient->id == sender.user_id ||
                    !can_message(sender.role, recipient->role))
                    return;

                std::string out = dump({ {"type", "typing"}, {"from", sender.login} });
                for (auto& rs : hub.sessions_of(recipient->id))
                    rs->ws_send(out);
            }, 0);
        return;
    }

    std::string group_name = msg["group"].get<std::string>();

    workers.try_push_task([this, sender, group_name]()
        {
            auto group = group_reposs.find_by_name(group_name);
            if (!group) return;

            auto role = group_reposs.get_member_role(group->id, sender.user_id);
            if (!role) return;

            // в канале подписчики писать не могут, значит и «печатают» тоже
            if (group->kind == "channel" && *role != "owner" && *role != "admin")
                return;

            std::string out = dump({
                {"type", "typing"}, {"group_id", group->id},
                {"group", group->name}, {"from", sender.login}
                });

            for (int user_id : group_reposs.get_member_ids(group->id))
            {
                if (user_id == sender.user_id) continue;
                for (auto& rs : hub.sessions_of(user_id))
                    rs->ws_send(out);
            }
        }, 0);
}
void ChatService::on_close(const Session::ChatIdentity& who, const Session* s)
{
    end_calls_of_device(s);

    // true только если это было последнее живое соединение пользователя
    if (hub.detach(who.user_id, s))
    {
        end_ringing_for_callee(who.user_id);
        announce_offline(who);
    }
}

void ChatService::handle_read(const std::shared_ptr<Session>& s, const json& msg)
{
    if (!s->chat_identity) return;
    Session::ChatIdentity sender = *s->chat_identity;

    

    long long id = 0, call_id = 0;
    auto num = [&](const char* k, long long& out) -> bool {
        if (!msg.contains(k)) return true;
        if (!msg[k].is_number_integer()) return false;
        out = msg[k].get<long long>();
        return out >= 0;
        };

    if (!num("id", id) || !num("call_id", call_id))
        return reply_error(s, "bad_request", "id must be a non-negative integer");
    if (id == 0 && call_id == 0)
        return reply_error(s, "bad_request", "id or call_id required");

    const bool has_to = msg.contains("to") && msg["to"].is_string();
    const bool has_group = msg.contains("group") && msg["group"].is_string();
    if (has_to == has_group)
        return reply_error(s, "bad_request", "Specify to or group");

    if (has_to)
    {
        std::string to = msg["to"].get<std::string>();

        workers.try_push_task([this, sender, to, id, call_id]()
            {
                auto partner = users.find_by_username(to);
                if (!partner || partner->id == sender.user_id) return;

                // 0: уже прочитано дальше, 1: что-то сдвинулось
                if (chats.mark_read_direct(sender.user_id, partner->id, id, call_id) <= 0) return;

                json own = { {"type", "read"}, {"with", partner->username} };
                if (id > 0)      own["id"] = id;
                if (call_id > 0) own["call_id"] = call_id;
                std::string own_out = dump(own);
                for (auto& rs : hub.sessions_of(sender.user_id)) rs->ws_send(own_out);

                // собеседнику: квитанция только про сообщения
                if (id > 0)
                {
                    std::string receipt = dump({ {"type", "read_receipt"}, {"by", sender.login}, {"id", id} });
                    for (auto& rs : hub.sessions_of(partner->id)) rs->ws_send(receipt);
                }
            }, 0);
        return;
    }

    std::string group_name = msg["group"].get<std::string>();

    workers.try_push_task([this, sender, group_name, id, call_id]()
        {
            auto group = group_reposs.find_by_name(group_name);
            if (!group) return;
            if (!group_reposs.get_member_role(group->id, sender.user_id)) return;

            if (group_reposs.mark_read(group->id, sender.user_id, id, call_id) <= 0) return;

            // другим устройствам читающего: сбросить счётчик
            json own = { {"type", "read"}, {"group", group->name}, {"group_id", group->id} };
            if (id > 0)      own["id"] = id;
            if (call_id > 0) own["call_id"] = call_id;
            std::string out = dump(own);
            for (auto& rs : hub.sessions_of(sender.user_id)) rs->ws_send(out);
        }, 0);
}

std::optional<std::string> ChatService::attachment_name_for(const std::string& url, int user_id)
{
    static const std::string prefix = "/uploads/chat/";
    auto up = chats.find_upload(url.substr(prefix.size()));
    if (!up || up->user_id != user_id) return std::nullopt;
    return up->original_name;
}   

void ChatService::sse_open(const std::shared_ptr<Session>& s, const std::string& token)
{
    bool queued = workers.try_push_task([this, s, token]()
        {
            auto session = sessions.find(token);

            s->ws_post([this, s, session]()
                {
                    if (!session) { s->reject_http("401 Unauthorized"); return; }

                    bool first = false;
                    if (!hub.attach(session->user_id, s, &first))
                    {
                        s->reject_http("429 Too Many Requests");
                        return;
                    }

                    s->chat_identity = Session::ChatIdentity{ session->user_id, session->username, session->role };

                    const std::string id = random_hex(16);
                    s->stream_id = id;
                    {
                        std::lock_guard<std::mutex> lk(streams_m);
                        streams[id] = s;
                    }

                    s->sse_begin();
                    s->ws_send(dump({ {"type", "auth_ok"}, {"login", session->username}, {"stream", id} }));
                    announce_online(*s->chat_identity, s);
                });
        }, 0);

    if (!queued) s->reject_http("503 Service Unavailable");
}
std::shared_ptr<Session> ChatService::find_stream(const std::string& id)
{
    std::lock_guard<std::mutex> lk(streams_m);
    auto it = streams.find(id);
    if (it != streams.end()) return it->second.lock();
    auto d = devices.find(id);
    return d == devices.end() ? nullptr : d->second;
}

void ChatService::drop_stream(const std::string& id)
{
    std::shared_ptr<Session> keep;                 // освободим объект уже после снятия мьютекса
    {
        std::lock_guard<std::mutex> lk(streams_m);
        streams.erase(id);
        auto d = devices.find(id);
        if (d != devices.end()) { keep = std::move(d->second); devices.erase(d); }
    }
}

void ChatService::poll_open(const std::shared_ptr<Session>& http, const std::string& token)
{
    bool queued = workers.try_push_task([this, http, token]()
        {
            auto session = sessions.find(token);

            http->ws_post([this, http, session]()
                {
                    if (!session) { http->reject_http("401 Unauthorized"); return; }

                    auto dev = Session::make_device(*http);

                    bool first = false;
                    if (!hub.attach(session->user_id, dev, &first))
                    {
                        http->reject_http("429 Too Many Requests");
                        return;
                    }

                    dev->chat_identity = Session::ChatIdentity{ session->user_id, session->username, session->role };
                    dev->device_id = random_hex(16);
                    {
                        std::lock_guard<std::mutex> lk(streams_m);
                        devices[dev->device_id] = dev;
                    }

                    dev->arm_timer(60s);
                    dev->ws_send(dump({ {"type", "auth_ok"}, {"login", session->username},
                                        {"device", dev->device_id} }));
                    announce_online(*dev->chat_identity, dev);

                    dev->ws_post([dev, http]() { dev->poll_take(http, 0); });   // первый ответ с накопленным
                });
        }, 0);

    if (!queued) http->reject_http("503 Service Unavailable");
}

void ChatService::send_to_user(int user_id, const std::string& payload)
{
    for (auto& rs : hub.sessions_of(user_id))
        rs->ws_send(payload);
}

void ChatService::handle_call(const std::shared_ptr<Session>& s, const json& msg, const std::string& type)
{
    Session::ChatIdentity me = *s->chat_identity;

    auto field = [&](const char* k) {
        return (msg.contains(k) && msg[k].is_string()) ? msg[k].get<std::string>() : std::string();
        };

    // ---------- позвонить ----------
    if (type == "call_invite")
    {
        if (!msg.contains("to") || !msg["to"].is_string())
            return reply_error(s, "bad_request", "to required");

        const bool video = msg.contains("video") && msg["video"].is_boolean() && msg["video"].get<bool>();
        std::string to = msg["to"].get<std::string>();

       
        bool queued = workers.try_push_task([this, s, me, to, video]()
            {
                auto callee = users.find_by_username(to);

                // те же правила, что для сообщений, и тот же ответ «нет такого»
                if (!callee || callee->id == me.user_id || !can_message(me.role, callee->role))
                {
                    s->ws_post([this, s]() { reply_error(s, "recipient_not_found", "Recipient not found"); });
                    return;
                }

                if (!hub.is_online(callee->id))
                {
                    s->ws_post([this, s]() { reply_error(s, "user_offline", "User is offline"); });
                    return;
                }

                if (group_calls.in_call(me.user_id))
                {
                    s->ws_post([this, s]() { reply_error(s, "already_in_call", "You are already in a call"); });
                    return;
                }
                if (group_calls.in_call(callee->id))
                {
                    s->ws_post([this, s]() { reply_error(s, "callee_busy", "User is busy"); });
                    return;
                }

                std::string reason;
                auto call = calls.create(me.user_id, me.login, callee->id, callee->username, video, s, reason);
                if (!call)
                {
                    s->ws_post([this, s, reason]() {
                        reply_error(s, reason.c_str(), reason == "callee_busy" ? "User is busy" : "You are already in a call");
                        });
                    return;
                }

                // звонящему: вызов пошёл
                s->ws_send(dump({ {"type", "call_ringing"}, {"call_id", call->id},
                                  {"to", callee->username}, {"video", video} }));

                // вызываемому: на все его устройства
                send_to_user(callee->id, dump({ {"type", "call_incoming"}, {"call_id", call->id},
                                                {"from", me.login}, {"video", video} }));
            }, 0);

        if (!queued) reply_error(s, "busy", "Server busy, try again");
        return;
    }

    const std::string id = field("call_id");

    // ---------- принять ----------
    if (type == "call_accept")
    {
        auto call = calls.accept(id, me.user_id, s);
        if (!call) return reply_error(s, "call_not_found", "Call not found");

        // звонящему: можно создавать предложение
        if (auto cw = call->caller_ws.lock())
            cw->ws_send(dump({ {"type", "call_accepted"}, {"call_id", id}, {"by", me.login} }));

        // остальным устройствам вызываемого: перестать звонить
        std::string taken = dump({ {"type", "call_taken"}, {"call_id", id}, {"reason", "accepted_elsewhere"} });
        for (auto& rs : hub.sessions_of(me.user_id))
            if (rs != s) rs->ws_send(taken);
        return;
    }

    // ---------- отклонить ----------
    if (type == "call_reject")
    {
        auto call = calls.remove_if(id, [&](const Call& c) {
            return c.callee_id == me.user_id && c.state == Call::State::Ringing; });
        if (!call) return reply_error(s, "call_not_found", "Call not found");

        if (auto cw = call->caller_ws.lock())
            cw->ws_send(dump({ {"type", "call_rejected"}, {"call_id", id} }));

        std::string taken = dump({ {"type", "call_taken"}, {"call_id", id}, {"reason", "rejected_elsewhere"} });
        for (auto& rs : hub.sessions_of(me.user_id))
            if (rs != s) rs->ws_send(taken);
        return;
    }

    // ---------- отменить до ответа (звонящий) ----------
    if (type == "call_cancel")
    {
        auto call = calls.remove_if(id, [&](const Call& c) {
            return c.caller_raw == s.get() && c.state == Call::State::Ringing; });
        if (!call) return reply_error(s, "call_not_found", "Call not found");

        send_to_user(call->callee_id,
            dump({ {"type", "call_cancelled"}, {"call_id", id}, {"reason", "caller_cancelled"} }));
        return;
    }

    // ---------- завершить разговор ----------
    if (type == "call_end")
    {
        // завершать может только то устройство, которое участвует в звонке
        auto call = calls.remove_if(id, [&](const Call& c) {
            return c.state == Call::State::Active &&
                (c.caller_raw == s.get() || c.callee_raw == s.get()); });
        if (!call) return reply_error(s, "call_not_found", "Call not found");

        const bool caller_ended = (call->caller_raw == s.get());
        if (auto peer = (caller_ended ? call->callee_ws : call->caller_ws).lock())
            peer->ws_send(dump({ {"type", "call_ended"}, {"call_id", id}, {"reason", "hangup"} }));
        return;
    }

    // ---------- пересылка SDP и ICE второму участнику ----------
    if (type == "call_signal")
    {
       
        if (!msg.contains("data") || !msg["data"].is_object())
            return reply_error(s, "bad_request", "data required");

        if (msg["data"].dump().size() > 32 * 1024)
            return reply_error(s, "too_large", "Signal too large");

        auto call = calls.get(id);
        if (!call || call->state != Call::State::Active)
            return reply_error(s, "call_not_found", "Call not found");

        // отправитель должен быть именно тем устройством, которое ведёт звонок
        const bool is_caller = (call->caller_raw == s.get());
        const bool is_callee = (call->callee_raw == s.get());
        if (!is_caller && !is_callee)
            return reply_error(s, "call_not_found", "Call not found");

        if (auto peer = (is_caller ? call->callee_ws : call->caller_ws).lock())
            peer->ws_send(dump({ {"type", "call_signal"}, {"call_id", id},
                                 {"from", me.login}, {"data", msg["data"]} }));
        return;
    }

    reply_error(s, "unknown_type", "Unknown message type");
}

// Раз в несколько секунд: вызовы без ответа дольше 45 секунд
void ChatService::sweep_calls()
{
    for (auto& c : calls.remove_expired_ringing(std::chrono::seconds(45)))
    {
        if (auto cw = c.caller_ws.lock())
            cw->ws_send(dump({ {"type", "call_ended"}, {"call_id", c.id}, {"reason", "no_answer"} }));

        send_to_user(c.callee_id,
            dump({ {"type", "call_cancelled"}, {"call_id", c.id}, {"reason", "timeout"} }));

        finish_call(c, "missed");
    }
}

void ChatService::end_calls_of_device(const Session* dev)
{
    if (auto lv = group_calls.leave_by_device(dev))
        after_gcall_leave(*lv);

    for (auto& c : calls.remove_by_device(dev))
    {
        const bool caller_left = (c.caller_raw == dev);

        if (c.state == Call::State::Ringing)
        {
            // звонящий пропал, пока шёл вызов
            send_to_user(c.callee_id,
                dump({ {"type", "call_cancelled"}, {"call_id", c.id}, {"reason", "caller_left"} }));
            finish_call(c, "cancelled");
        }
        else
        {
            if (auto peer = (caller_left ? c.callee_ws : c.caller_ws).lock())
                peer->ws_send(dump({ {"type", "call_ended"}, {"call_id", c.id}, {"reason", "disconnected"} }));
            finish_call(c, "completed");
        }
    }
}

void ChatService::end_ringing_for_callee(int user_id)
{
    for (auto& c : calls.remove_ringing_for_callee(user_id))
    {
        if (auto cw = c.caller_ws.lock())
            cw->ws_send(dump({ {"type", "call_ended"}, {"call_id", c.id}, {"reason", "unavailable"} }));
        finish_call(c, "missed");
    }
}
void ChatService::finish_call(const Call& c, const std::string& status)
{
    using namespace std::chrono;
    const auto now = steady_clock::now();

    const int total = (int)duration_cast<seconds>(now - c.created).count();
    const int talk = (c.state == Call::State::Active)
        ? (int)duration_cast<seconds>(now - c.answered).count()
        : 0;

    workers.try_push_task([this, c, status, total, talk]()
        {
            auto rec = chats.save_call(c.caller_id, c.callee_id, c.video, status, total, talk);
            if (!rec) return;

            std::string out = dump({
                {"type", "call_log"},
                {"id", rec->id},
                {"caller", c.caller_login},
                {"callee", c.callee_login},
                {"video", c.video},
                {"status", status},
                {"duration", talk},
                {"ts", rec->ended_at}
                });

            send_to_user(c.caller_id, out);
            send_to_user(c.callee_id, out);
        }, 0);
}


// только из рабочего потока: внутри запрос к БД
void ChatService::broadcast_group(int group_id, const std::string& payload, const Session* except)
{
    for (int uid : group_reposs.get_member_ids(group_id))
        for (auto& rs : hub.sessions_of(uid))
            if (rs.get() != except) rs->ws_send(payload);
}

void ChatService::handle_gcall(const std::shared_ptr<Session>& s, const json& msg, const std::string& type)
{
    Session::ChatIdentity me = *s->chat_identity;

    auto field = [&](const char* k) {
        return (msg.contains(k) && msg[k].is_string()) ? msg[k].get<std::string>() : std::string();
        };

    // ---------- войти в звонок группы (или начать его) ----------
    if (type == "gcall_join")
    {
        const std::string group_name = field("group");
        if (group_name.empty())
            return reply_error(s, "bad_request", "group required");

        const bool video = msg.contains("video") && msg["video"].is_boolean() && msg["video"].get<bool>();

        bool queued = workers.try_push_task([this, s, me, group_name, video]()
            {
                auto group = group_reposs.find_by_name(group_name);
                auto role = group ? group_reposs.get_member_role(group->id, me.user_id) : std::nullopt;

                // не участник отвечает так же, как «нет такой группы»
                if (!group || !role)
                {
                    s->ws_post([this, s]() { reply_error(s, "group_not_found", "Group not found"); });
                    return;
                }

                if (group->kind == "channel")
                {
                    s->ws_post([this, s]() { reply_error(s, "forbidden", "Calls are not available in channels"); });
                    return;
                }

                // человек может быть только в одном звонке
                if (calls.in_call(me.user_id))
                {
                    s->ws_post([this, s]() { reply_error(s, "already_in_call", "You are already in a call"); });
                    return;
                }

                auto out = group_calls.join(group->id, group->name, me.user_id, me.login, video, s);

                if (out.result == GroupCallManager::JoinResult::AlreadyIn)
                {
                    s->ws_post([this, s]() { reply_error(s, "already_in_call", "You are already in a call"); });
                    return;
                }
                if (out.result == GroupCallManager::JoinResult::Full)
                {
                    s->ws_post([this, s]() { reply_error(s, "call_full", "Call is full"); });
                    return;
                }

                // нам: состав звонка
                json others = json::array();
                for (auto& m : out.others)
                    others.push_back({ {"login", m.login}, {"video", m.video} });

                s->ws_send(dump({ {"type", "gcall_joined"}, {"call_id", out.call.id},
                                  {"group", group->name}, {"group_id", group->id},
                                  {"video", out.call.video}, {"participants", others} }));

                // остальным участникам звонка: к ним зашёл новый человек
                std::string joined = dump({ {"type", "gcall_peer_joined"}, {"call_id", out.call.id},
                                            {"login", me.login}, {"video", video} });
                for (auto& m : out.others)
                    if (auto w = m.ws.lock()) w->ws_send(joined);

                // звонок только что начался: оповещаем всю группу
                if (out.result == GroupCallManager::JoinResult::Started)
                {
                    std::string started = dump({ {"type", "gcall_started"}, {"call_id", out.call.id},
                                                 {"group", group->name}, {"group_id", group->id},
                                                 {"by", me.login}, {"video", video} });
                    broadcast_group(group->id, started, s.get());
                }
            }, 0);

        if (!queued) reply_error(s, "busy", "Server busy, try again");
        return;
    }

    // ---------- выйти ----------
    if (type == "gcall_leave")
    {
        auto lv = group_calls.leave(field("call_id"), s.get());
        if (!lv) return reply_error(s, "call_not_found", "Call not found");

        after_gcall_leave(*lv);
        return;
    }

    // ---------- переслать SDP или ICE одному из участников ----------
    if (type == "gcall_signal")
    {
       

        if (!msg.contains("data") || !msg["data"].is_object())
            return reply_error(s, "bad_request", "data required");

        if (msg["data"].dump().size() > 32 * 1024)
            return reply_error(s, "too_large", "Signal too large");

        // отправитель должен быть тем устройством, которое в звонке, получатель тоже участник
        auto pair = group_calls.resolve_pair(field("call_id"), s.get(), field("to"));
        if (!pair) return reply_error(s, "call_not_found", "Call not found");

        if (auto w = pair->second.ws.lock())
            w->ws_send(dump({ {"type", "gcall_signal"}, {"call_id", field("call_id")},
                              {"from", me.login}, {"data", msg["data"]} }));
        return;
    }

    reply_error(s, "unknown_type", "Unknown message type");
}

// Кто-то вышел (сам или закрылось устройство)
void ChatService::after_gcall_leave(const GroupCallManager::LeaveOutcome& lv)
{
    std::string left = dump({ {"type", "gcall_peer_left"}, {"call_id", lv.call.id}, {"login", lv.left.login} });
    for (auto& m : lv.call.members)
        if (auto w = m.ws.lock()) w->ws_send(left);

    // комната опустела: группе нужно убрать кнопку «Присоединиться»
    if (lv.ended)
    {
        finish_group_call(lv.call);

        const int gid = lv.call.group_id;
        std::string ended = dump({ {"type", "gcall_ended"}, {"call_id", lv.call.id},
                                   {"group_id", gid}, {"group", lv.call.group_name} });

        workers.try_push_task([this, gid, ended]() { broadcast_group(gid, ended, nullptr); }, 0);
    }
}

// После входа: где сейчас идут звонки в моих группах
void ChatService::send_group_call_snapshot(const std::shared_ptr<Session>& s, int user_id)
{
    json mine = json::parse(group_reposs.list_for_user(user_id), nullptr, false);
    if (mine.is_discarded() || !mine.contains("items")) return;

    json items = json::array();
    for (auto& g : mine["items"])
    {
        if (g.value("kind", std::string()) == "channel") continue;

        auto call = group_calls.find_by_group(g.value("id", 0));
        if (!call) continue;

        json parts = json::array();
        for (auto& m : call->members) parts.push_back(m.login);

        items.push_back({ {"group", g.value("name", std::string())}, {"group_id", call->group_id},
                          {"call_id", call->id}, {"video", call->video}, {"participants", parts} });
    }

    if (!items.empty())
        s->ws_send(dump({ {"type", "gcall_active"}, {"items", items} }));
}

void ChatService::kick_from_group_call(int group_id, int user_id)
{
    auto lv = group_calls.kick_user(group_id, user_id);
    if (!lv) return;

    // ему самому: звонок для него закончен
    if (auto w = lv->left.ws.lock())
        w->ws_send(dump({ {"type", "gcall_kicked"}, {"call_id", lv->call.id},
                          {"group", lv->call.group_name}, {"reason", "removed_from_group"} }));

    after_gcall_leave(*lv);
}

// Группа удалена: закрываем звонок у всех, кто в нём был (в историю такой звонок не пишется)
void ChatService::end_group_call(int group_id, const std::string& reason)
{
    auto call = group_calls.end_group(group_id);
    if (!call) return;

    std::string ended = dump({ {"type", "gcall_ended"}, {"call_id", call->id},
                               {"group_id", group_id}, {"group", call->group_name}, {"reason", reason} });

    for (auto& m : call->members)
        if (auto w = m.ws.lock()) w->ws_send(ended);
}

std::optional<AttachmentMeta> ChatService::attachment_meta_for(const std::string& url, int user_id)
{
    static const std::string prefix = "/uploads/chat/";
    auto up = chats.find_upload(url.substr(prefix.size()));
    if (!up || up->user_id != user_id) return std::nullopt;

    AttachmentMeta meta;
    meta.name = up->original_name;
    meta.duration_ms = up->duration_ms;
    return meta;
}

void ChatService::finish_group_call(const GroupCall& call)
{
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const int total = (int)duration_cast<seconds>(now - call.created).count();

    std::vector<GroupCallStayRow> rows;
    json logins = json::array();
    std::vector<std::string> seen;

    for (const auto& st : call.stays)
    {
        GroupCallStayRow r;
        r.user_id = st.user_id;
        r.offset_sec = (int)duration_cast<seconds>(st.joined - call.created).count();
        r.duration_sec = (int)duration_cast<seconds>(st.left - st.joined).count();
        rows.push_back(r);

        if (std::find(seen.begin(), seen.end(), st.login) == seen.end())
        {
            seen.push_back(st.login);
            logins.push_back(st.login);
        }
    }

    workers.try_push_task([this, call, total, rows, logins]()
        {
            auto rec = group_reposs.save_group_call(call.group_id, call.started_by_id, call.video,
                total, (int)call.peak, rows);
            if (!rec) return;

            std::string out = dump({
                {"type", "gcall_log"},
                {"id", rec->id},
                {"group", call.group_name},
                {"group_id", call.group_id},
                {"started_by", call.started_by},
                {"video", call.video},
                {"duration", total},
                {"peak", (int)call.peak},
                {"participants", logins},
                {"ts", rec->ended_at}
                });

            broadcast_group(call.group_id, out, nullptr);
        }, 0);
}