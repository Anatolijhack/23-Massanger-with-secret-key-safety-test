#include "ChatRepository.h"
#include "Utf16.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include "DbHelpers.h"
#include "Messagecrypto.h"

using json = nlohmann::json;
static bool is_valid_attachment_url(const std::string& url)
{
    static const std::string prefix = "/uploads/chat/";
    if (url.size() != prefix.size() + 16 + 4 && url.size() != prefix.size() + 16 + 5)
        return false;
    if (url.compare(0, prefix.size(), prefix) != 0)
        return false;

    std::string name = url.substr(prefix.size());
    for (size_t i = 0; i < 16; ++i)
        if (!std::isxdigit((unsigned char)name[i]) || std::isupper((unsigned char)name[i]))
            return false;

    std::string ext = name.substr(16);
    return ext == ".jpg" || ext == ".png" || ext == ".webp" || ext == ".pdf";
}

static void print_odbc_error(SQLSMALLINT handle_type, SQLHANDLE handle)
{
    SQLCHAR sqlstate[6];
    SQLCHAR message[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER native_error;
    SQLSMALLINT message_len;
    SQLSMALLINT i = 1;

    while (SQLGetDiagRecA(handle_type, handle, i, sqlstate, &native_error,
        message, sizeof(message), &message_len) == SQL_SUCCESS)
    {
        std::cerr << "ODBC Error [" << sqlstate << "] " << message << std::endl;
        i++;
    }
}

std::optional<SavedMessage> ChatRepository::save(int sender_id, int recipient_id,
    const std::string& text, const std::string& attachment_url,long long reply_to, const std::string& attachment_name)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "INSERT INTO Messages (sender_id, recipient_id, body, attachment_url, reply_to, attachment_name,body_enc) "
        "OUTPUT INSERTED.id, CONVERT(NVARCHAR(30), INSERTED.created_at, 126) "
        "VALUES (?, ?, ?, ?,?,?,?)";

    auto sealed = seal_direct(sender_id, recipient_id, text);
    if (!sealed) return std::nullopt;

    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    SQLLEN i1 = 0, i2 = 0;
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &sender_id, 0, &i1);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &recipient_id, 0, &i2);

    std::wstring wtext = utf8_to_wide(sealed->text);
    SQLLEN body_ind = SQL_NTS;
    SQLBindParameter(stmt, 3, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wtext.size()), 0, (SQLPOINTER)wtext.c_str(), 0, &body_ind);

    // пустой attachment_url -> NULL
    std::wstring wurl = utf8_to_wide(attachment_url);
    SQLLEN url_ind = attachment_url.empty() ? SQL_NULL_DATA : SQL_NTS;
    SQLBindParameter(stmt, 4, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        200, 0, (SQLPOINTER)wurl.c_str(), 0, &url_ind);
    SQLLEN reply_ind = reply_to > 0 ? 0 : SQL_NULL_DATA;
    SQLBindParameter(stmt, 5, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &reply_to, 0, &reply_ind);
    std::wstring wattname = utf8_to_wide(attachment_name);
    SQLLEN attname_ind = attachment_name.empty() ? SQL_NULL_DATA : SQL_NTS;
    SQLBindParameter(stmt, 6, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        200, 0, (SQLPOINTER)wattname.c_str(), 0, &attname_ind);
    SQLLEN enc_ind = sealed->enc.empty() ? SQL_NULL_DATA : (SQLLEN)sealed->enc.size();
    SQLBindParameter(stmt, 7, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_VARBINARY,
        (std::max)((SQLULEN)1, (SQLULEN)sealed->enc.size()), 0,
        (SQLPOINTER)sealed->enc.data(), (SQLLEN)sealed->enc.size(), &enc_ind);

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
        return std::nullopt;
    }

    SQLBIGINT id = 0;
    SQLCHAR ts[32] = {};
    SQLLEN id_ind = 0, ts_ind = 0;
    SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_ind);
    SQLBindCol(stmt, 2, SQL_C_CHAR, ts, sizeof(ts), &ts_ind);

    std::optional<SavedMessage> out;
    if (SQL_SUCCEEDED(SQLFetch(stmt)))
        out = SavedMessage{ (long long)id, std::string((char*)ts) };

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return out;
}

std::string ChatRepository::history(int me, int other, long long before_id, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "SELECT TOP (?) m.id, u.login, m.body, "
        "CONVERT(NVARCHAR(30), m.created_at, 126), "
        "m.attachment_url, m.attachment_name, up.duration_ms, "
        "m.body_enc, m.sender_id, m.recipient_id, "
        "CASE WHEN m.edited_at IS NULL THEN 0 ELSE 1 END, "
        "CASE WHEN m.deleted_at IS NULL THEN 0 ELSE 1 END, "
        "m.reply_to "
        "FROM Messages m JOIN Users u ON u.id = m.sender_id "
        "LEFT JOIN Uploads up ON up.stored_name = SUBSTRING(m.attachment_url, 15, 40) "
        "WHERE ((m.sender_id = ? AND m.recipient_id = ?) "
        "OR (m.sender_id = ? AND m.recipient_id = ?)) "
        "AND (? = 0 OR m.id < ?) "
        "ORDER BY m.id DESC";
    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    SQLLEN ind[7] = {};
    auto bind_int = [&](int idx, int& v) {
        SQLBindParameter(stmt, idx, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &v, 0, &ind[idx - 1]);
        };
    bind_int(1, limit);
    bind_int(2, me);  bind_int(3, other);
    bind_int(4, other); bind_int(5, me);
    SQLBindParameter(stmt, 6, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &before_id, 0, &ind[5]);
    SQLBindParameter(stmt, 7, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &before_id, 0, &ind[6]);


    json items = json::array();

    if (SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        SQLBIGINT id = 0, reply_to = 0;
        SQLCHAR login[256] = {}, ts[64] = {};
        SQLWCHAR body[2001] = {};
        SQLWCHAR att[201] = {}, att_name[201] = {};

        SQLINTEGER edited = 0, deleted = 0;
        SQLINTEGER duration_ms = 0;
        SQLINTEGER sender_id = 0, recipient_id = 0;

        SQLLEN id_ind = 0, login_ind = 0, body_ind = 0, ts_ind = 0;
        SQLLEN att_ind = 0, att_name_i = 0, duration_i = 0;
        SQLLEN enc_i = 0, snd_i = 0, rcp_i = 0;
        SQLLEN edited_ind = 0, deleted_ind = 0, reply_ind = 0;

        unsigned char body_enc[4000] = {};

        SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_ind);
        SQLBindCol(stmt, 2, SQL_C_CHAR, login, sizeof(login), &login_ind);
        SQLBindCol(stmt, 3, SQL_C_WCHAR, body, sizeof(body), &body_ind);
        SQLBindCol(stmt, 4, SQL_C_CHAR, ts, sizeof(ts), &ts_ind);
        SQLBindCol(stmt, 5, SQL_C_WCHAR, att, sizeof(att), &att_ind);
        SQLBindCol(stmt, 6, SQL_C_WCHAR, att_name, sizeof(att_name), &att_name_i);
        SQLBindCol(stmt, 7, SQL_C_LONG, &duration_ms, 0, &duration_i);
        SQLBindCol(stmt, 8, SQL_C_BINARY, body_enc, sizeof(body_enc), &enc_i);
        SQLBindCol(stmt, 9, SQL_C_LONG, &sender_id, 0, &snd_i);
        SQLBindCol(stmt, 10, SQL_C_LONG, &recipient_id, 0, &rcp_i);
        SQLBindCol(stmt, 11, SQL_C_LONG, &edited, 0, &edited_ind);
        SQLBindCol(stmt, 12, SQL_C_LONG, &deleted, 0, &deleted_ind);
        SQLBindCol(stmt, 13, SQL_C_SBIGINT, &reply_to, 0, &reply_ind);
        while (SQL_SUCCEEDED(SQLFetch(stmt)))
        {
            json item = {
                {"id", (long long)id},
                {"from", std::string((char*)login)},
                {"text", open_direct(wcol(body, sizeof(body), body_ind),
                     bincol(body_enc, sizeof(body_enc), enc_i),
                     (int)sender_id, (int)recipient_id)},
                {"ts", std::string((char*)ts)}
            };

            if (att_ind != SQL_NULL_DATA && att_ind > 0)
                item["attachment"] = wide_to_utf8((const wchar_t*)att, (int)(att_ind / sizeof(wchar_t)));
            if (att_name_i > 0) item["attachment_name"] = wide_to_utf8((const wchar_t*)att_name, (int)(att_name_i / sizeof(wchar_t)));
            if (edited)  item["edited"] = true;
            if (deleted) item["deleted"] = true;
            if (reply_ind != SQL_NULL_DATA && reply_to > 0)
                item["reply_to"] = (long long)reply_to;
            if (duration_i != SQL_NULL_DATA)
                item["duration_ms"] = duration_ms;

            items.push_back(std::move(item));
        }
    }
    else
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    json out = { {"items", items} };
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::string ChatRepository::сreate_group(int owner_id, std::string& group_name, std::vector<std::string>& members, const std::string& kind)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    // Единая точка выхода при ошибке: откат всей транзакции + JSON с ошибкой
    auto fail = [&](SQLHSTMT stmt, const char* msg) -> std::string
        {
            if (stmt)
            {
                print_odbc_error(SQL_HANDLE_STMT, stmt);
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            }
            SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
            json err = { {"error", msg} };
            return err.dump(-1, ' ', false, json::error_handler_t::replace);
        };

    // ---------- 1. Создаём группу ----------
    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* q_group =
        "INSERT INTO ChatGroups (name, owner_id, kind) "
        "OUTPUT INSERTED.id "
        "VALUES (?, ?, ?)";
    SQLPrepareA(stmt, (SQLCHAR*)q_group, SQL_NTS);

    std::wstring wname = utf8_to_wide(group_name);
    std::wstring wkind = utf8_to_wide(kind);
    SQLLEN name_ind = SQL_NTS, owner_ind = 0, kind_ind = SQL_NTS;
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wname.size()), 0, (SQLPOINTER)wname.c_str(), 0, &name_ind);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &owner_id, 0, &owner_ind);
    SQLBindParameter(stmt, 3, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wkind.size()), 0, (SQLPOINTER)wkind.c_str(), 0, &kind_ind);

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
        return fail(stmt, "create group failed");

    SQLINTEGER group_id = 0;
    SQLLEN gid_ind = 0;
    SQLBindCol(stmt, 1, SQL_C_SLONG, &group_id, 0, &gid_ind);
    if (!SQL_SUCCEEDED(SQLFetch(stmt)))
        return fail(stmt, "no group id returned");

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    stmt = nullptr;

    // ---------- 2. Владелец -> GroupMembers с ролью 'owner' ----------
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* q_owner =
        "INSERT INTO GroupMembers (group_id, user_id, role, joined_at) "
        "VALUES (?, ?, 'owner', SYSUTCDATETIME())";
    SQLPrepareA(stmt, (SQLCHAR*)q_owner, SQL_NTS);

    SQLLEN o1 = 0, o2 = 0;
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &group_id, 0, &o1);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &owner_id, 0, &o2);

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
        return fail(stmt, "add owner failed");

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    stmt = nullptr;

    // ---------- 3. Остальные участники по логину ----------
    json added = json::array();
    json skipped = json::array();

    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    // Вставляем только если пользователь существует, это не владелец
    // и его ещё нет в группе (защита от дублей в списке)
    const char* q_member =
        "INSERT INTO GroupMembers (group_id, user_id, role, joined_at) "
        "SELECT ?, u.id, 'customer', SYSUTCDATETIME() "
        "FROM Users u "
        "WHERE u.login = ? AND u.id <> ? "
        "AND NOT EXISTS (SELECT 1 FROM GroupMembers gm WHERE gm.group_id = ? AND gm.user_id = u.id)";
    SQLPrepareA(stmt, (SQLCHAR*)q_member, SQL_NTS);

    for (const std::string& login : members)
    {
        std::wstring wlogin = utf8_to_wide(login);

        SQLLEN m_ind[4] = {};
        SQLLEN login_ind = SQL_NTS;
        SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &group_id, 0, &m_ind[0]);
        SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
            (std::max)((SQLULEN)1, (SQLULEN)wlogin.size()), 0, (SQLPOINTER)wlogin.c_str(), 0, &login_ind);
        SQLBindParameter(stmt, 3, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &owner_id, 0, &m_ind[2]);
        SQLBindParameter(stmt, 4, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &group_id, 0, &m_ind[3]);

        if (!SQL_SUCCEEDED(SQLExecute(stmt)))
            return fail(stmt, "add member failed");

        SQLLEN rows = 0;
        SQLRowCount(stmt, &rows);
        if (rows > 0) added.push_back(login);
        else          skipped.push_back(login);   // не найден / владелец / дубль

        SQLCloseCursor(stmt);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    json out = {
        {"group_id", (int)group_id},
        {"name", group_name},
        {"kind", kind},
        {"added", added},
        {"skipped", skipped}
    };
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::string ChatRepository::sync_direct(int me, long long after_id, const std::string& since, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "SELECT TOP (?) m.id, u.login, m.body, "
        "CONVERT(NVARCHAR(30), m.created_at, 126), "
        "m.attachment_url, m.attachment_name, up.duration_ms, "
        "m.body_enc, m.sender_id, m.recipient_id, "
        "CASE WHEN m.edited_at IS NULL THEN 0 ELSE 1 END, "
        "CASE WHEN m.deleted_at IS NULL THEN 0 ELSE 1 END, "
        "m.reply_to "
        "FROM Messages m JOIN Users u ON u.id = m.sender_id "
        "LEFT JOIN Uploads up ON up.stored_name = SUBSTRING(m.attachment_url, 15, 40) "
        "WHERE m.recipient_id = ? "
        "AND (m.id > ? OR m.updated_at >= CONVERT(DATETIME2, ?, 126)) "
        "ORDER BY m.id ASC";
    std::wstring wsince = utf8_to_wide(since.empty() ? "9999-12-31T00:00:00" : since);
    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    SQLLEN ind[4] = {};
    ind[3] = SQL_NTS;
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &limit, 0, &ind[0]);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &me, 0, &ind[1]);
    SQLBindParameter(stmt, 3, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &after_id, 0, &ind[2]);
    SQLBindParameter(stmt, 4, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wsince.size()), 0, (SQLPOINTER)wsince.c_str(), 0, &ind[3]);

    json items = json::array();

    if (SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        SQLBIGINT id = 0;
        SQLCHAR login[64] = {}, ts[32] = {};
        SQLWCHAR body[2049] = {}, att[201] = {};
        SQLINTEGER edited = 0, deleted = 0;
        SQLBIGINT reply_to = 0;
        SQLLEN id_ind = 0, login_ind = 0, body_ind = 0, ts_ind = 0;
        SQLLEN att_ind = 0, edited_ind = 0, deleted_ind = 0, reply_ind = 0;

        SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_ind);
        SQLBindCol(stmt, 2, SQL_C_CHAR, login, sizeof(login), &login_ind);
        SQLBindCol(stmt, 3, SQL_C_WCHAR, body, sizeof(body), &body_ind);
        SQLBindCol(stmt, 4, SQL_C_CHAR, ts, sizeof(ts), &ts_ind);
        SQLBindCol(stmt, 5, SQL_C_WCHAR, att, sizeof(att), &att_ind);

        SQLWCHAR att_name[201] = {};
        SQLLEN att_name_i = 0;
        SQLBindCol(stmt, 6, SQL_C_WCHAR, att_name, sizeof(att_name), &att_name_i);

        SQLINTEGER duration_ms = 0;
        SQLLEN duration_i = 0;
        SQLBindCol(stmt, 7, SQL_C_LONG, &duration_ms, 0, &duration_i);

        unsigned char body_enc[4000] = {};
        SQLLEN enc_i = 0;
        SQLBindCol(stmt, 8, SQL_C_BINARY, body_enc, sizeof(body_enc), &enc_i);

        SQLINTEGER sender_id = 0, recipient_id = 0;
        SQLLEN snd_i = 0, rcp_i = 0;
        SQLBindCol(stmt, 9, SQL_C_LONG, &sender_id, 0, &snd_i);
        SQLBindCol(stmt, 10, SQL_C_LONG, &recipient_id, 0, &rcp_i);

        SQLBindCol(stmt, 11, SQL_C_LONG, &edited, 0, &edited_ind);
        SQLBindCol(stmt, 12, SQL_C_LONG, &deleted, 0, &deleted_ind);
        SQLBindCol(stmt, 13, SQL_C_SBIGINT, &reply_to, 0, &reply_ind);

        while (SQL_SUCCEEDED(SQLFetch(stmt)))
        {
            json item = {
                {"id", (long long)id},
                {"from", std::string((char*)login)},
                {"text", open_direct(wcol(body, sizeof(body), body_ind),
                     bincol(body_enc, sizeof(body_enc), enc_i),
                     (int)sender_id, (int)recipient_id)},
                {"ts", std::string((char*)ts)}
            };

            if (att_ind != SQL_NULL_DATA && att_ind > 0)
                item["attachment"] = wide_to_utf8((const wchar_t*)att, (int)(att_ind / sizeof(wchar_t)));
            if (att_name_i > 0) item["attachment_name"] = wide_to_utf8((const wchar_t*)att_name, (int)(att_name_i / sizeof(wchar_t)));
            if (deleted) item["deleted"] = true;
            if (duration_i != SQL_NULL_DATA)
                item["duration_ms"] = duration_ms;
            if (reply_ind != SQL_NULL_DATA && reply_to > 0)
                item["reply_to"] = (long long)reply_to;

            items.push_back(std::move(item));
        }
    }
    else
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    return items.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::optional<bool> ChatRepository::attachment_in_use(const std::string& url)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM Messages WHERE attachment_url = ?) "
        "OR EXISTS (SELECT 1 FROM GroupMessages WHERE attachment_url = ?) "
        "THEN 1 ELSE 0 END";
    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    std::wstring wurl = utf8_to_wide(url);
    SQLLEN ind[2] = { SQL_NTS, SQL_NTS };
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wurl.size()), 0, (SQLPOINTER)wurl.c_str(), 0, &ind[0]);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wurl.size()), 0, (SQLPOINTER)wurl.c_str(), 0, &ind[1]);

    std::optional<bool> result;   // при ошибке БД остаётся пустым

    if (SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        SQLINTEGER used = 0;
        SQLLEN used_ind = 0;
        SQLBindCol(stmt, 1, SQL_C_LONG, &used, 0, &used_ind);
        if (SQL_SUCCEEDED(SQLFetch(stmt)))
            result = (used != 0);
    }
    else
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return result;
}

long ChatRepository::edit_direct(int sender_id, int recipient_id, long long id, const std::string& text)
{
    auto sealed = seal_direct(sender_id, recipient_id, text);
    if (!sealed) return -1;

    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    long rows = exec_update(dbc,
        "UPDATE Messages SET body = ?, body_enc = ?, edited_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME() "
        "WHERE id = ? AND sender_id = ? AND recipient_id = ? AND deleted_at IS NULL",
        { DbParam::Text(sealed->text), DbParam::Blob(sealed->enc),
          DbParam::BigInt(id), DbParam::Int(sender_id), DbParam::Int(recipient_id) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
    return rows;
}

long ChatRepository::delete_direct(int sender_id, int recipient_id, long long id)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    long rows = exec_update(dbc,
        "UPDATE Messages SET body = N'',body_enc = NULL, attachment_url = NULL, deleted_at = SYSUTCDATETIME(),updated_at = SYSUTCDATETIME() "
        "WHERE id = ? AND sender_id = ? AND recipient_id = ? AND deleted_at IS NULL",
        { DbParam::BigInt(id), DbParam::Int(sender_id), DbParam::Int(recipient_id) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
    return rows;
}

// сообщение с таким id есть в переписке этих двух пользователей
int ChatRepository::direct_message_exists(int a, int b, long long id)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    int r = db_exists(dbc,
        "SELECT 1 FROM Messages WHERE id = ? AND deleted_at IS NULL "
        "AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))",
        { DbParam::BigInt(id), DbParam::Int(a), DbParam::Int(b), DbParam::Int(b), DbParam::Int(a) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return r;
}

// ---------- личные диалоги: последнее сообщение с каждым собеседником ----------
std::string ChatRepository::dialogs_direct(int me, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    json items = json::array();

    db_select(dbc,
        "WITH d AS ( "
        "  SELECT m.id, m.body, m.body_enc, m.attachment_url, m.deleted_at, m.created_at, m.sender_id, "
        "         CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END AS partner_id "
        "  FROM Messages m WHERE m.sender_id = ? OR m.recipient_id = ? "
        "), r AS ( "
        "  SELECT d.*, ROW_NUMBER() OVER (PARTITION BY partner_id ORDER BY id DESC) AS rn FROM d "
        ") "
        "SELECT TOP (?) u.login, r.id, LEFT(r.body, 100), r.attachment_url, "
        "CASE WHEN r.deleted_at IS NULL THEN 0 ELSE 1 END, "
        "CONVERT(NVARCHAR(30), r.created_at, 126), "
        "CASE WHEN r.sender_id = ? THEN 1 ELSE 0 END, "
        "(SELECT COUNT(*) FROM Messages x "
        " WHERE x.sender_id = r.partner_id AND x.recipient_id = ? AND x.deleted_at IS NULL "
        " AND x.id > ISNULL((SELECT dr.last_read_id FROM DirectReads dr "
        "                    WHERE dr.user_id = ? AND dr.partner_id = r.partner_id), 0)), "
        "ISNULL((SELECT dr2.last_read_id FROM DirectReads dr2 "
        "        WHERE dr2.user_id = r.partner_id AND dr2.partner_id = ?), 0), "
        "r.body_enc, r.sender_id, r.partner_id "
        "FROM r JOIN Users u ON u.id = r.partner_id "
        "WHERE r.rn = 1 "
        "ORDER BY r.id DESC",
        { DbParam::Int(me), DbParam::Int(me), DbParam::Int(me), DbParam::Int(limit),
          DbParam::Int(me), DbParam::Int(me), DbParam::Int(me), DbParam::Int(me) },
        [&](SQLHSTMT stmt)
        {
            SQLBIGINT last_id = 0;
            SQLINTEGER deleted = 0, mine = 0;
            SQLWCHAR login[64] = {}, text[101] = {}, att[201] = {};
            SQLCHAR ts[40] = {};
            SQLINTEGER unread = 0;
            SQLBIGINT peer_read = 0;
            SQLLEN unread_i = 0, peer_i = 0;
            SQLLEN login_i = 0, last_i = 0, text_i = 0, att_i = 0, del_i = 0, ts_i = 0, mine_i = 0;

            SQLBindCol(stmt, 1, SQL_C_WCHAR, login, sizeof(login), &login_i);
            SQLBindCol(stmt, 2, SQL_C_SBIGINT, &last_id, 0, &last_i);
            SQLBindCol(stmt, 3, SQL_C_WCHAR, text, sizeof(text), &text_i);
            SQLBindCol(stmt, 4, SQL_C_WCHAR, att, sizeof(att), &att_i);
            SQLBindCol(stmt, 5, SQL_C_LONG, &deleted, 0, &del_i);
            SQLBindCol(stmt, 6, SQL_C_CHAR, ts, sizeof(ts), &ts_i);
            SQLBindCol(stmt, 7, SQL_C_LONG, &mine, 0, &mine_i);
            SQLBindCol(stmt, 8, SQL_C_LONG, &unread, 0, &unread_i);
            SQLBindCol(stmt, 9, SQL_C_SBIGINT, &peer_read, 0, &peer_i);
            unsigned char enc_buf[2112] = {};
            SQLINTEGER msg_sender = 0, partner = 0;
            SQLLEN enc_i = 0, ms_i = 0, pt_i = 0;
            SQLBindCol(stmt, 10, SQL_C_BINARY, enc_buf, sizeof(enc_buf), &enc_i);    // следующие свободные номера
            SQLBindCol(stmt, 11, SQL_C_LONG, &msg_sender, 0, &ms_i);
            SQLBindCol(stmt, 12, SQL_C_LONG, &partner, 0, &pt_i);

    

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                std::string preview = wcol(text, sizeof(text), text_i);

                const std::string enc = bincol(enc_buf, sizeof(enc_buf), enc_i);

                if (!enc.empty() && ms_i != SQL_NULL_DATA && pt_i != SQL_NULL_DATA)
                {
                    const int recipient =
                        (msg_sender == me) ? partner : me;

                    preview = utf8_preview(
                        open_direct("", enc, static_cast<int>(msg_sender), recipient),
                        100
                    );
                };


                json item = {
                    {"type", "direct"},
                    {"with", wcol(login, sizeof(login), login_i)},
                    {"last_id", (long long)last_id},
                    {"text", preview},
                    {"ts", std::string((char*)ts)},
                    {"mine", mine != 0},
                    {"unread", (int)unread },
                    {"peer_read_id", (long long)peer_read}
                };
                if (att_i > 0) item["has_attachment"] = true;
                if (deleted)   item["deleted"] = true;
                items.push_back(std::move(item));
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    return items.dump(-1, ' ', false, json::error_handler_t::replace);
}

// ---------- поиск пользователей по началу логина ----------
std::string ChatRepository::search_users(int me, const std::string& q, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    json items = json::array();
    std::string my_role_out;

    // экранируем спецсимволы LIKE, иначе запрос "%" вернёт всех
    std::string pattern;
    for (char c : q)
    {
        if (c == '%' || c == '_' || c == '[' || c == '\\') pattern += '\\';
        pattern += c;
    }
    pattern += '%';

    // порядок параметров: limit, me (для подзапроса роли), pattern, me
    db_select(dbc,
        "SELECT TOP (?) login, role, (SELECT role FROM Users WHERE id = ?) "
        "FROM Users "
        "WHERE login LIKE ? ESCAPE '\\' AND id <> ? "
        "ORDER BY login",
        { DbParam::Int(limit), DbParam::Int(me), DbParam::Text(pattern), DbParam::Int(me) },
        [&](SQLHSTMT stmt)
        {
            SQLWCHAR login[64] = {};
            SQLCHAR role[40] = {}, my_role[40] = {};
            SQLLEN login_i = 0, role_i = 0, my_i = 0;

            SQLBindCol(stmt, 1, SQL_C_WCHAR, login, sizeof(login), &login_i);
            SQLBindCol(stmt, 2, SQL_C_CHAR, role, sizeof(role), &role_i);
            SQLBindCol(stmt, 3, SQL_C_CHAR, my_role, sizeof(my_role), &my_i);

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                items.push_back({
                    {"login", wcol(login, sizeof(login), login_i)},
                    {"role", std::string((char*)role)}
                    });
                my_role_out = std::string((char*)my_role);
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    json out = { {"my_role", my_role_out}, {"items", items} };
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::vector<Partner> ChatRepository::partners(int me)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    std::vector<Partner> result;

    db_select(dbc,
        "SELECT u.id, u.login, CONVERT(NVARCHAR(30), u.last_seen_at, 126) "
        "FROM Users u "
        "WHERE u.id IN (SELECT recipient_id FROM Messages WHERE sender_id = ? "
        "               UNION "
        "               SELECT sender_id FROM Messages WHERE recipient_id = ?)",
        { DbParam::Int(me), DbParam::Int(me) },
        [&](SQLHSTMT stmt)
        {
            SQLINTEGER id = 0;
            SQLWCHAR login[64] = {};
            SQLCHAR seen[40] = {};
            SQLLEN id_i = 0, login_i = 0, seen_i = 0;

            SQLBindCol(stmt, 1, SQL_C_LONG, &id, 0, &id_i);
            SQLBindCol(stmt, 2, SQL_C_WCHAR, login, sizeof(login), &login_i);
            SQLBindCol(stmt, 3, SQL_C_CHAR, seen, sizeof(seen), &seen_i);

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                Partner p;
                p.id = (int)id;
                p.login = wcol(login, sizeof(login), login_i);
                if (seen_i > 0) p.last_seen = std::string((char*)seen);
                result.push_back(std::move(p));
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return result;
}

// записывает «был в сети» и возвращает время
std::string ChatRepository::touch_last_seen(int user_id)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    std::string ts;

    db_select(dbc,
        "UPDATE Users SET last_seen_at = SYSUTCDATETIME() "
        "OUTPUT CONVERT(NVARCHAR(30), INSERTED.last_seen_at, 126) "
        "WHERE id = ?",
        { DbParam::Int(user_id) },
        [&](SQLHSTMT stmt)
        {
            SQLCHAR buf[40] = {};
            SQLLEN ind = 0;
            SQLBindCol(stmt, 1, SQL_C_CHAR, buf, sizeof(buf), &ind);
            if (SQL_SUCCEEDED(SQLFetch(stmt)))
                ts = std::string((char*)buf);
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return ts;
}

std::string ChatRepository::db_now()
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    std::string ts;

    db_select(dbc,
        "SELECT CONVERT(NVARCHAR(30), DATEADD(SECOND, -5, SYSUTCDATETIME()), 126)",
        {},
        [&](SQLHSTMT stmt)
        {
            SQLCHAR buf[40] = {};
            SQLLEN ind = 0;
            SQLBindCol(stmt, 1, SQL_C_CHAR, buf, sizeof(buf), &ind);
            if (SQL_SUCCEEDED(SQLFetch(stmt)))
                ts = std::string((char*)buf);
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return ts;
}

long ChatRepository::mark_read_direct(int me, int partner_id, long long id, long long call_id)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    long rows = exec_update(dbc,
        "MERGE DirectReads WITH (HOLDLOCK) AS t "
        "USING (SELECT CAST(? AS INT) AS user_id, CAST(? AS INT) AS partner_id, "
        "              CAST(? AS BIGINT) AS last_id, CAST(? AS BIGINT) AS last_call) AS s "
        "ON t.user_id = s.user_id AND t.partner_id = s.partner_id "
        "WHEN MATCHED AND (t.last_read_id < s.last_id OR t.last_read_call_id < s.last_call) THEN UPDATE SET "
        "  t.last_read_id = CASE WHEN t.last_read_id < s.last_id THEN s.last_id ELSE t.last_read_id END, "
        "  t.last_read_call_id = CASE WHEN t.last_read_call_id < s.last_call THEN s.last_call ELSE t.last_read_call_id END "
        "WHEN NOT MATCHED THEN INSERT (user_id, partner_id, last_read_id, last_read_call_id) "
        "  VALUES (s.user_id, s.partner_id, s.last_id, s.last_call);",
        { DbParam::Int(me), DbParam::Int(partner_id), DbParam::BigInt(id), DbParam::BigInt(call_id) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
    return rows;
}

bool ChatRepository::save_upload(const std::string& stored, const std::string& original,
    const std::string& mime, size_t size, int user_id, int duration_ms)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    long rows = exec_update(dbc,
        "INSERT INTO Uploads (stored_name, original_name, mime, size_bytes, user_id, duration_ms) "
        "VALUES (?, ?, ?, ?, ?, NULLIF(CAST(? AS INT), 0))",
        { DbParam::Text(stored), DbParam::Text(original), DbParam::Text(mime),
          DbParam::Int((int)size), DbParam::Int(user_id), DbParam::Int(duration_ms) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
    return rows > 0;
}

std::optional<UploadInfo> ChatRepository::find_upload(const std::string& stored)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    std::optional<UploadInfo> result;

    db_select(dbc,
        "SELECT original_name, user_id, ISNULL(duration_ms, 0) FROM Uploads WHERE stored_name = ?",
        { DbParam::Text(stored) },
        [&](SQLHSTMT stmt)
        {
            SQLWCHAR name[256] = {};
            SQLINTEGER uid = 0, dur = 0;
            SQLLEN name_i = 0, uid_i = 0, dur_i = 0;

            SQLBindCol(stmt, 1, SQL_C_WCHAR, name, sizeof(name), &name_i);
            SQLBindCol(stmt, 2, SQL_C_LONG, &uid, 0, &uid_i);
            SQLBindCol(stmt, 3, SQL_C_LONG, &dur, 0, &dur_i);

            if (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                UploadInfo info;
                info.original_name = wcol(name, sizeof(name), name_i);
                info.user_id = (int)uid;
                info.duration_ms = (int)dur;
                result = std::move(info);
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return result;
}

void ChatRepository::delete_upload(const std::string& stored)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    long rows = exec_update(dbc, "DELETE FROM Uploads WHERE stored_name = ?",
        { DbParam::Text(stored) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
}

std::optional<CallRecord> ChatRepository::save_call(int caller_id, int callee_id, bool video,
    const std::string& status, int total_sec, int talk_sec)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    std::optional<CallRecord> result;

    bool ok = db_select(dbc,
        "INSERT INTO Calls (caller_id, callee_id, video, status, started_at, answered_at, ended_at, duration_sec) "
        "OUTPUT INSERTED.id, CONVERT(NVARCHAR(30), INSERTED.ended_at, 126) "
        "SELECT ?, ?, CAST(? AS BIT), ?, DATEADD(SECOND, -CAST(? AS INT), t.now_), "
        "DATEADD(SECOND, -NULLIF(CAST(? AS INT), 0), t.now_), t.now_, CAST(? AS INT) "
        "FROM (SELECT SYSUTCDATETIME() AS now_) t",
        { DbParam::Int(caller_id), DbParam::Int(callee_id), DbParam::Int(video ? 1 : 0),
          DbParam::Text(status), DbParam::Int(total_sec), DbParam::Int(talk_sec), DbParam::Int(talk_sec) },
        [&](SQLHSTMT stmt)
        {
            SQLBIGINT id = 0;
            SQLCHAR ended[40] = {};
            SQLLEN id_i = 0, ended_i = 0;

            SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
            SQLBindCol(stmt, 2, SQL_C_CHAR, ended, sizeof(ended), &ended_i);

            if (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                CallRecord rec;
                rec.id = (long long)id;
                rec.ended_at = std::string((char*)ended);
                result = std::move(rec);
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, ok ? SQL_COMMIT : SQL_ROLLBACK);
    return result;
}

// partner_id = 0: все мои звонки. before_id и after_id = 0: без ограничения.
std::string ChatRepository::list_calls(int me, int partner_id, long long before_id, long long after_id, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    json items = json::array();

    db_select(dbc,
        "SELECT TOP (?) c.id, uc.login, ue.login, c.video, c.status, c.duration_sec, "
        "CONVERT(NVARCHAR(30), c.ended_at, 126) "
        "FROM Calls c "
        "JOIN Users uc ON uc.id = c.caller_id "
        "JOIN Users ue ON ue.id = c.callee_id "
        "WHERE ((c.caller_id = ? AND (? = 0 OR c.callee_id = ?)) "
        "    OR (c.callee_id = ? AND (? = 0 OR c.caller_id = ?))) "
        "AND (? = 0 OR c.id < ?) AND (? = 0 OR c.id > ?) "
        "ORDER BY c.id DESC",
        { DbParam::Int(limit),
          DbParam::Int(me), DbParam::Int(partner_id), DbParam::Int(partner_id),
          DbParam::Int(me), DbParam::Int(partner_id), DbParam::Int(partner_id),
          DbParam::BigInt(before_id), DbParam::BigInt(before_id),
          DbParam::BigInt(after_id),  DbParam::BigInt(after_id) },
        [&](SQLHSTMT stmt)
        {
            SQLBIGINT id = 0;
            SQLINTEGER video = 0, duration = 0;
            SQLWCHAR caller[64] = {}, callee[64] = {};
            SQLCHAR status[24] = {}, ended[40] = {};
            SQLLEN id_i = 0, caller_i = 0, callee_i = 0, video_i = 0, status_i = 0, dur_i = 0, ended_i = 0;

            SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
            SQLBindCol(stmt, 2, SQL_C_WCHAR, caller, sizeof(caller), &caller_i);
            SQLBindCol(stmt, 3, SQL_C_WCHAR, callee, sizeof(callee), &callee_i);
            SQLBindCol(stmt, 4, SQL_C_LONG, &video, 0, &video_i);
            SQLBindCol(stmt, 5, SQL_C_CHAR, status, sizeof(status), &status_i);
            SQLBindCol(stmt, 6, SQL_C_LONG, &duration, 0, &dur_i);
            SQLBindCol(stmt, 7, SQL_C_CHAR, ended, sizeof(ended), &ended_i);

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                items.push_back({
                    {"id", (long long)id},
                    {"caller", wcol(caller, sizeof(caller), caller_i)},
                    {"callee", wcol(callee, sizeof(callee), callee_i)},
                    {"video", video != 0},
                    {"status", std::string((char*)status)},
                    {"duration", (int)duration},
                    {"ts", std::string((char*)ended)}
                    });
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    json out = { {"items", items} };
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}   

std::string ChatRepository::dialogs_calls(int me, int limit)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();
    json items = json::array();

    db_select(dbc,
        "WITH c AS ( "
        "  SELECT x.id, x.video, x.status, x.duration_sec, x.ended_at, x.caller_id, "
        "         CASE WHEN x.caller_id = ? THEN x.callee_id ELSE x.caller_id END AS partner_id "
        "  FROM Calls x WHERE x.caller_id = ? OR x.callee_id = ? "
        "), r AS ( "
        "  SELECT c.*, ROW_NUMBER() OVER (PARTITION BY partner_id ORDER BY id DESC) AS rn FROM c "
        ") "
        "SELECT TOP (?) u.login, r.id, r.video, r.status, r.duration_sec, "
        "CONVERT(NVARCHAR(30), r.ended_at, 126), "
        "CASE WHEN r.caller_id = ? THEN 1 ELSE 0 END, "
        "(SELECT COUNT(*) FROM Calls m "
        " WHERE m.callee_id = ? AND m.caller_id = r.partner_id AND m.status IN ('missed', 'cancelled') "
        " AND m.id > ISNULL((SELECT dr.last_read_call_id FROM DirectReads dr "
        "                    WHERE dr.user_id = ? AND dr.partner_id = r.partner_id), 0)) "
        "FROM r JOIN Users u ON u.id = r.partner_id "
        "WHERE r.rn = 1 "
        "ORDER BY r.id DESC",
        { DbParam::Int(me), DbParam::Int(me), DbParam::Int(me), DbParam::Int(limit),
          DbParam::Int(me), DbParam::Int(me), DbParam::Int(me) },
        [&](SQLHSTMT stmt)
        {
            SQLBIGINT id = 0;
            SQLINTEGER video = 0, duration = 0, outgoing = 0, missed = 0;
            SQLWCHAR login[64] = {};
            SQLCHAR status[24] = {}, ended[40] = {};
            SQLLEN login_i = 0, id_i = 0, video_i = 0, status_i = 0, dur_i = 0, ended_i = 0, out_i = 0, miss_i = 0;

            SQLBindCol(stmt, 1, SQL_C_WCHAR, login, sizeof(login), &login_i);
            SQLBindCol(stmt, 2, SQL_C_SBIGINT, &id, 0, &id_i);
            SQLBindCol(stmt, 3, SQL_C_LONG, &video, 0, &video_i);
            SQLBindCol(stmt, 4, SQL_C_CHAR, status, sizeof(status), &status_i);
            SQLBindCol(stmt, 5, SQL_C_LONG, &duration, 0, &dur_i);
            SQLBindCol(stmt, 6, SQL_C_CHAR, ended, sizeof(ended), &ended_i);
            SQLBindCol(stmt, 7, SQL_C_LONG, &outgoing, 0, &out_i);
            SQLBindCol(stmt, 8, SQL_C_LONG, &missed, 0, &miss_i);

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                items.push_back({
                    {"with", wcol(login, sizeof(login), login_i)},
                    {"id", (long long)id},
                    {"video", video != 0},
                    {"status", std::string((char*)status)},
                    {"duration", (int)duration},
                    {"ts", std::string((char*)ended)},
                    {"outgoing", outgoing != 0},
                    {"unread_calls", (int)missed}
                    });
            }
        });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

    return items.dump(-1, ' ', false, json::error_handler_t::replace);
}
// Шифрует старые сообщения пачкой. Возвращает, сколько обновлено (0: больше нечего или ошибка).
int ChatRepository::encrypt_legacy_messages(int batch)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    struct Row { long long id; int sender; int recipient; std::string body; };
    std::vector<Row> rows;

    db_select(dbc,
        "SELECT TOP (?) id, sender_id, recipient_id, body FROM Messages "
        "WHERE body_enc IS NULL AND body <> N'' ORDER BY id",
        { DbParam::Int(batch) },
        [&](SQLHSTMT stmt)
        {
            SQLBIGINT id = 0;
            SQLINTEGER s = 0, r = 0;
            SQLWCHAR body[2049] = {};
            SQLLEN id_i = 0, s_i = 0, r_i = 0, b_i = 0;

            SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
            SQLBindCol(stmt, 2, SQL_C_LONG, &s, 0, &s_i);
            SQLBindCol(stmt, 3, SQL_C_LONG, &r, 0, &r_i);
            SQLBindCol(stmt, 4, SQL_C_WCHAR, body, sizeof(body), &b_i);

            while (SQL_SUCCEEDED(SQLFetch(stmt)))
                rows.push_back({ (long long)id, (int)s, (int)r, wcol(body, sizeof(body), b_i) });
        });

    int updated = 0;
    for (const auto& row : rows)
    {
        auto blob = crypto().encrypt(row.body, aad_direct(row.sender, row.recipient));
        if (!blob) continue;

        long n = exec_update(dbc,
            "UPDATE Messages SET body = N'', body_enc = ? WHERE id = ? AND body_enc IS NULL",
            { DbParam::Blob(*blob), DbParam::BigInt(row.id) });
        if (n > 0) updated += (int)n;
    }

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return updated;
}
// Доступ есть у загрузившего файл, у участника личной переписки и у участника группы,
// где файл отправлен. У удалённого сообщения вложения нет, доступа тоже.
bool ChatRepository::can_access_upload(const std::string& stored_name, int user_id)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    const std::string url = "/uploads/chat/" + stored_name;

    int r = db_exists(dbc,
        "SELECT 1 WHERE "
        "EXISTS (SELECT 1 FROM Uploads WHERE stored_name = ? AND user_id = ?) "
        "OR EXISTS (SELECT 1 FROM Messages WHERE attachment_url = ? AND (sender_id = ? OR recipient_id = ?)) "
        "OR EXISTS (SELECT 1 FROM GroupMessages gm JOIN GroupMembers mem ON mem.group_id = gm.group_id "
        "           WHERE gm.attachment_url = ? AND mem.user_id = ?)",
        { DbParam::Text(stored_name), DbParam::Int(user_id),
          DbParam::Text(url), DbParam::Int(user_id), DbParam::Int(user_id),
          DbParam::Text(url), DbParam::Int(user_id) });

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return r == 1;
}

bool ChatRepository::has_encrypted_data()
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    int r = db_exists(dbc,
        "SELECT 1 WHERE EXISTS (SELECT 1 FROM Messages WHERE body_enc IS NOT NULL) "
        "OR EXISTS (SELECT 1 FROM GroupMessages WHERE body_enc IS NOT NULL)",
        {});

    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return r != 0;
}

