#include "GroupRepository.h"
#include <codecvt>
#include "Utf16.h"
#include <nlohmann/json.hpp>
#include "Messagecrypto.h"

using json = nlohmann::json;
static json split_logins(const std::string& joined)
{
    json out = json::array();
    size_t pos = 0;
    while (!joined.empty() && pos <= joined.size())
    {
        size_t comma = joined.find(',', pos);
        if (comma == std::string::npos) comma = joined.size();
        if (comma > pos) out.push_back(joined.substr(pos, comma - pos));
        pos = comma + 1;
    }
    return out;
}
std::optional<CreatedGroup> GroupRepository::find_by_name(const std::string& name)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "SELECT id, name, kind "
        "FROM ChatGroups "
        "WHERE name = ?";

    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    std::wstring wname = utf8_to_wide(name);
    SQLLEN name_len = SQL_NTS;
    SQLBindParameter(
        stmt, 1, SQL_PARAM_INPUT,
        SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wname.size()), 0,
        (SQLPOINTER)wname.c_str(), 0, &name_len
    );

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
        return std::nullopt;
    }

    SQLINTEGER out_id = 0;
    SQLWCHAR out_name[256] = {};
    SQLCHAR out_kind[16] = {};

    SQLLEN id_ind = 0, name_ind = 0, kind_ind = 0;

    SQLBindCol(stmt, 1, SQL_C_LONG, &out_id, 0, &id_ind);
    SQLBindCol(stmt, 2, SQL_C_WCHAR, out_name, sizeof(out_name), &name_ind);
    SQLBindCol(stmt, 3, SQL_C_CHAR, out_kind, sizeof(out_kind), &kind_ind);

    std::optional<CreatedGroup> result;

    if (SQL_SUCCEEDED(SQLFetch(stmt)))
    {
        CreatedGroup g;
        g.id = static_cast<int>(out_id);
        g.name = wide_to_utf8((const wchar_t*)out_name, (int)(name_ind / sizeof(wchar_t)));
        g.kind = std::string(reinterpret_cast<char*>(out_kind));
        result = std::move(g);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    return result;
}


std::optional<GroupMessageRecord> GroupRepository::save_messages(
    int group_id,
    int sender_id,
    const std::string& body,
    const std::string& attachment_url, long long reply_to, const std::string& attachment_name)
{
    auto leased = pool.acquire();
    SQLHDBC dbc = leased.handle();

    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

    const char* query =
        "INSERT INTO GroupMessages (group_id, sender_id, body, attachment_url,reply_to,attachment_name,body_enc) "
        "OUTPUT INSERTED.id, "
        "CONVERT(VARCHAR(33), INSERTED.created_at, 126) "
        "VALUES (?, ?, ?, ?,?,?,?)";

    auto sealed = seal_group(group_id, sender_id, body);
    if (!sealed) return std::nullopt;

    SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

    SQLINTEGER gid = group_id;
    SQLINTEGER uid = sender_id;

    SQLLEN gid_ind = 0;
    SQLLEN uid_ind = 0;

    SQLBindParameter(
        stmt, 1, SQL_PARAM_INPUT,
        SQL_C_LONG, SQL_INTEGER,
        0, 0, &gid, 0, &gid_ind
    );

    SQLBindParameter(
        stmt, 2, SQL_PARAM_INPUT,
        SQL_C_LONG, SQL_INTEGER,
        0, 0, &uid, 0, &uid_ind
    );

    // текст: UTF-8 -> UTF-16, как в ChatRepository::save
    std::wstring wbody = utf8_to_wide(body);
    SQLLEN body_ind = SQL_NTS;
    SQLBindParameter(
        stmt, 3, SQL_PARAM_INPUT,
        SQL_C_WCHAR, SQL_WVARCHAR,
        (std::max)((SQLULEN)1, (SQLULEN)wbody.size()), 0,
        (SQLPOINTER)wbody.c_str(), 0, &body_ind
    );

    // вложение: пустая строка -> NULL
    std::wstring wurl = utf8_to_wide(attachment_url);
    SQLLEN url_ind = attachment_url.empty() ? SQL_NULL_DATA : SQL_NTS;
    SQLBindParameter(
        stmt, 4, SQL_PARAM_INPUT,
        SQL_C_WCHAR, SQL_WVARCHAR,
        200, 0,
        (SQLPOINTER)wurl.c_str(), 0, &url_ind
    );

    SQLLEN reply_ind = reply_to > 0 ? 0 : SQL_NULL_DATA;
    SQLBindParameter(stmt, 5, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &reply_to, 0, &reply_ind);

    std::wstring wattname = utf8_to_wide(attachment_name);
    SQLLEN attname_ind = attachment_name.empty() ? SQL_NULL_DATA : SQL_NTS;
    SQLBindParameter(stmt, 6, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
        200, 0, (SQLPOINTER)wattname.c_str(), 0, &attname_ind);

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        print_odbc_error(SQL_HANDLE_STMT, stmt);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
        return std::nullopt;
    }

    SQLBIGINT out_id = 0;
    SQLCHAR out_created_at[40] = {};

    SQLLEN id_ind = 0;
    SQLLEN created_ind = 0;

    SQLBindCol(stmt, 1, SQL_C_SBIGINT, &out_id, 0, &id_ind);
    SQLBindCol(stmt, 2, SQL_C_CHAR, out_created_at, sizeof(out_created_at), &created_ind);

    std::optional<GroupMessageRecord> result;

    if (SQL_SUCCEEDED(SQLFetch(stmt)))
    {
        result = GroupMessageRecord{
            static_cast<long long>(out_id),
            std::string(reinterpret_cast<char*>(out_created_at))
        };
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLEndTran(SQL_HANDLE_DBC, dbc, result ? SQL_COMMIT : SQL_ROLLBACK);
    return result;
}

    std::vector<int> GroupRepository::get_member_ids(int group_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        SQLHSTMT stmt = nullptr;
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        const char* query =
            "SELECT user_id "
            "FROM GroupMembers "
            "WHERE group_id = ?";

        SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

        SQLINTEGER gid = group_id;
        SQLLEN gid_ind = 0;

        SQLBindParameter(
            stmt, 1, SQL_PARAM_INPUT,
            SQL_C_LONG, SQL_INTEGER,
            0, 0, &gid, 0, &gid_ind
        );

        SQLRETURN rc = SQLExecute(stmt);

        if (!SQL_SUCCEEDED(rc))
        {
            print_odbc_error(SQL_HANDLE_STMT, stmt);
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            return {};
        }

        SQLINTEGER user_id = 0;
        SQLLEN user_id_ind = 0;

        SQLBindCol(stmt, 1, SQL_C_LONG,
            &user_id, 0, &user_id_ind);

        std::vector<int> members;

        while (SQL_SUCCEEDED(SQLFetch(stmt)))
        {
            members.push_back(static_cast<int>(user_id));
        }

       
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return members;
    }

    std::optional<std::string> GroupRepository::get_member_role(int group_id, int user_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        SQLHSTMT stmt = nullptr;
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        const char* query =
            "SELECT role "
            "FROM GroupMembers "
            "WHERE group_id = ? AND user_id = ?";

        SQLPrepareA(stmt, (SQLCHAR*)query, SQL_NTS);

        SQLINTEGER gid = group_id;
        SQLINTEGER uid = user_id;
        SQLLEN gid_ind = 0;
        SQLLEN uid_ind = 0;

        SQLBindParameter(
            stmt, 1, SQL_PARAM_INPUT,
            SQL_C_LONG, SQL_INTEGER,
            0, 0, &gid, 0, &gid_ind
        );

        SQLBindParameter(
            stmt, 2, SQL_PARAM_INPUT,
            SQL_C_LONG, SQL_INTEGER,
            0, 0, &uid, 0, &uid_ind
        );

        if (!SQL_SUCCEEDED(SQLExecute(stmt)))
        {
            print_odbc_error(SQL_HANDLE_STMT, stmt);
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
            return std::nullopt;
        }

        SQLCHAR role[32] = {};
        SQLLEN role_ind = 0;

        SQLBindCol(stmt, 1, SQL_C_CHAR, role, sizeof(role), &role_ind);

        std::optional<std::string> result;

        if (SQL_SUCCEEDED(SQLFetch(stmt)))
            result = std::string(reinterpret_cast<char*>(role));

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return result;
    }
   
    long GroupRepository::add_member(int group_id, const std::string& login)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        long rows = exec_update(dbc,
            "INSERT INTO GroupMembers (group_id, user_id, role, joined_at) "
            "SELECT ?, u.id, 'customer', SYSUTCDATETIME() "
            "FROM Users u "
            "WHERE u.login = ? "
            "AND NOT EXISTS (SELECT 1 FROM GroupMembers gm WHERE gm.group_id = ? AND gm.user_id = u.id)",
            { DbParam::Int(group_id), DbParam::Text(login), DbParam::Int(group_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    long GroupRepository::remove_member_by_login(int group_id, const std::string& login, bool only_customers)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        // владельца не удаляет никто; админ удаляет только обычных участников
        std::string sql =
            "DELETE gm FROM GroupMembers gm "
            "JOIN Users u ON u.id = gm.user_id "
            "WHERE gm.group_id = ? AND u.login = ? AND gm.role <> 'owner'";
        if (only_customers)
            sql += " AND gm.role = 'customer'";

        long rows = exec_update(dbc, sql, { DbParam::Int(group_id), DbParam::Text(login) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    long GroupRepository::remove_member_by_id(int group_id, int user_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        long rows = exec_update(dbc,
            "DELETE FROM GroupMembers WHERE group_id = ? AND user_id = ? AND role <> 'owner'",
            { DbParam::Int(group_id), DbParam::Int(user_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    long GroupRepository::rename_group(int group_id, const std::string& name)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        long rows = exec_update(dbc,
            "UPDATE ChatGroups SET name = ? WHERE id = ?",
            { DbParam::Text(name), DbParam::Int(group_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    long GroupRepository::set_role(int group_id, const std::string& login, const std::string& role)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        // роль владельца не меняется
        long rows = exec_update(dbc,
            "UPDATE gm SET gm.role = ? "
            "FROM GroupMembers gm JOIN Users u ON u.id = gm.user_id "
            "WHERE gm.group_id = ? AND u.login = ? AND gm.role <> 'owner'",
            { DbParam::Text(role), DbParam::Int(group_id), DbParam::Text(login) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    bool GroupRepository::delete_group(int group_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        // внешние ключи без CASCADE: сначала сообщения и участники, потом сама группа
        long r1 = exec_update(dbc, "DELETE FROM GroupMessages WHERE group_id = ?", { DbParam::Int(group_id) });
        long r2 = (r1 < 0) ? -1 : exec_update(dbc, "DELETE FROM GroupMembers WHERE group_id = ?", { DbParam::Int(group_id) });
        long r3 = (r2 < 0) ? -1 : exec_update(dbc, "DELETE FROM ChatGroups WHERE id = ?", { DbParam::Int(group_id) });

        if (r3 < 0)
        {
            SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
            return false;
        }

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return r3 > 0;
    }

    std::string GroupRepository::sync_groups(int me, long long after_id, const std::string& since, int limit)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        SQLHSTMT stmt = nullptr;
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        const char* query =
            "SELECT TOP (?) gm.id, g.id, g.name, g.kind, u.login, gm.body, "
            "CONVERT(NVARCHAR(30), gm.created_at, 126), "
            "gm.attachment_url, gm.attachment_name, up.duration_ms, "
            "gm.body_enc, gm.sender_id, "
            "CASE WHEN gm.edited_at IS NULL THEN 0 ELSE 1 END, "
            "CASE WHEN gm.deleted_at IS NULL THEN 0 ELSE 1 END, "
            "gm.reply_to "
            "FROM GroupMessages gm "
            "JOIN GroupMembers mem ON mem.group_id = gm.group_id AND mem.user_id = ? "
            "JOIN ChatGroups g ON g.id = gm.group_id "
            "JOIN Users u ON u.id = gm.sender_id "
            "LEFT JOIN Uploads up ON up.stored_name = SUBSTRING(gm.attachment_url, 15, 40) "
            "WHERE (gm.id > ? OR gm.updated_at >= CONVERT(DATETIME2, ?, 126)) "
            "ORDER BY gm.id ASC";
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
            SQLBIGINT msg_id = 0, reply_to = 0;
            SQLINTEGER group_id = 0, edited = 0, deleted = 0;
            SQLINTEGER duration_ms = 0, sender_id = 0;

            SQLWCHAR group_name[256] = {};
            SQLCHAR kind[16] = {}, login[64] = {}, ts[40] = {};
            SQLWCHAR body[2049] = {}, att[201] = {}, att_name[201] = {};

            SQLLEN msg_id_ind = 0, group_id_ind = 0, gname_ind = 0;
            SQLLEN kind_ind = 0, login_ind = 0, body_ind = 0, ts_ind = 0;
            SQLLEN att_ind = 0, att_name_i = 0, duration_i = 0;
            SQLLEN enc_i = 0, snd_i = 0;
            SQLLEN edited_ind = 0, deleted_ind = 0, reply_ind = 0;

            unsigned char body_enc[4000] = {};

            SQLBindCol(stmt, 1, SQL_C_SBIGINT, &msg_id, 0, &msg_id_ind);
            SQLBindCol(stmt, 2, SQL_C_LONG, &group_id, 0, &group_id_ind);
            SQLBindCol(stmt, 3, SQL_C_WCHAR, group_name, sizeof(group_name), &gname_ind);
            SQLBindCol(stmt, 4, SQL_C_CHAR, kind, sizeof(kind), &kind_ind);
            SQLBindCol(stmt, 5, SQL_C_CHAR, login, sizeof(login), &login_ind);
            SQLBindCol(stmt, 6, SQL_C_WCHAR, body, sizeof(body), &body_ind);
            SQLBindCol(stmt, 7, SQL_C_CHAR, ts, sizeof(ts), &ts_ind);
            SQLBindCol(stmt, 8, SQL_C_WCHAR, att, sizeof(att), &att_ind);
            SQLBindCol(stmt, 9, SQL_C_WCHAR, att_name, sizeof(att_name), &att_name_i);
            SQLBindCol(stmt, 10, SQL_C_LONG, &duration_ms, 0, &duration_i);
            SQLBindCol(stmt, 11, SQL_C_BINARY, body_enc, sizeof(body_enc), &enc_i);
            SQLBindCol(stmt, 12, SQL_C_LONG, &sender_id, 0, &snd_i);
            SQLBindCol(stmt, 13, SQL_C_LONG, &edited, 0, &edited_ind);
            SQLBindCol(stmt, 14, SQL_C_LONG, &deleted, 0, &deleted_ind);
            SQLBindCol(stmt, 15, SQL_C_SBIGINT, &reply_to, 0, &reply_ind);


            while (SQL_SUCCEEDED(SQLFetch(stmt)))
            {
                json item = {
                    {"id", (long long)msg_id},
                    {"group_id", (int)group_id},
                    {"group", wide_to_utf8((const wchar_t*)group_name, (int)(gname_ind / sizeof(wchar_t)))},
                    {"kind", std::string((char*)kind)},
                    {"from", std::string((char*)login)},
                    {"text", open_group(wcol(body, sizeof(body), body_ind),
                    bincol(body_enc, sizeof(body_enc), enc_i),
                    group_id, (int)sender_id)},
                    {"ts", std::string((char*)ts)}
                };

                if (att_ind != SQL_NULL_DATA && att_ind > 0)
                    item["attachment"] = wide_to_utf8((const wchar_t*)att, (int)(att_ind / sizeof(wchar_t)));
                if (att_name_i > 0) item["attachment_name"] = wcol(att_name, sizeof(att_name), att_name_i);
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

        return items.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    long GroupRepository::edit_message(int group_id, int sender_id, long long id, const std::string& text)
    {
        auto sealed = seal_direct(sender_id, group_id, text);
        if (!sealed) return -1;

        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        long rows = exec_update(dbc,
            "UPDATE GroupMessages SET body = ?,body_enc = ?, edited_at = SYSUTCDATETIME(), updated_at = SYSUTCDATETIME() "
            "WHERE id = ? AND group_id = ? AND sender_id = ? AND deleted_at IS NULL",
            { DbParam::Text(text), DbParam::BigInt(id), DbParam::Int(group_id), DbParam::Int(sender_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    long GroupRepository::delete_message(int group_id, long long id, int only_sender_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        std::string sql =
            "UPDATE GroupMessages SET body = N'',body_enc = NULL, attachment_url = NULL, deleted_at = SYSUTCDATETIME(),updated_at = SYSUTCDATETIME()  "
            "WHERE id = ? AND group_id = ? AND deleted_at IS NULL";
        std::vector<DbParam> ps = { DbParam::BigInt(id), DbParam::Int(group_id) };

        if (only_sender_id > 0)
        {
            sql += " AND sender_id = ?";
            ps.push_back(DbParam::Int(only_sender_id));
        }

        long rows = exec_update(dbc, sql, std::move(ps));

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    int GroupRepository::group_message_exists(int group_id, long long id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        int r = db_exists(dbc,
            "SELECT 1 FROM GroupMessages WHERE id = ? AND group_id = ? AND deleted_at IS NULL",
            { DbParam::BigInt(id), DbParam::Int(group_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return r;
    }

    // ---------- история группы (от новых к старым, как history личных сообщений) ----------
    std::string GroupRepository::history(int group_id, long long before_id, int limit)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        db_select(dbc,
            "SELECT TOP (?) gm.id, u.login, gm.body, "
            "CONVERT(NVARCHAR(30), gm.created_at, 126), "
            "gm.attachment_url, gm.attachment_name, up.duration_ms, "
            "gm.body_enc, gm.sender_id, "
            "CASE WHEN gm.edited_at IS NULL THEN 0 ELSE 1 END, "
            "CASE WHEN gm.deleted_at IS NULL THEN 0 ELSE 1 END, "
            "gm.reply_to "
            "FROM GroupMessages gm JOIN Users u ON u.id = gm.sender_id "
            "LEFT JOIN Uploads up ON up.stored_name = SUBSTRING(gm.attachment_url, 15, 40) "
            "WHERE gm.group_id = ? AND (? = 0 OR gm.id < ?) "
            "ORDER BY gm.id DESC",
            { DbParam::Int(limit), DbParam::Int(group_id), DbParam::BigInt(before_id), DbParam::BigInt(before_id) },
            [&](SQLHSTMT stmt)
            {
                SQLBIGINT id = 0, reply_to = 0;
                SQLINTEGER edited = 0, deleted = 0, duration_ms = 0;
                SQLINTEGER sender_id = 0;

                SQLCHAR ts[40] = {};
                SQLWCHAR login[64] = {}, body[2049] = {};
                SQLWCHAR att[201] = {}, att_name[201] = {};

                SQLLEN id_i = 0, login_i = 0, body_i = 0, ts_i = 0;
                SQLLEN att_i = 0, att_name_i = 0, duration_i = 0;
                SQLLEN enc_i = 0, snd_i = 0;
                SQLLEN ed_i = 0, del_i = 0, rep_i = 0;

                unsigned char body_enc[4000] = {};

                SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_WCHAR, login, sizeof(login), &login_i);
                SQLBindCol(stmt, 3, SQL_C_WCHAR, body, sizeof(body), &body_i);
                SQLBindCol(stmt, 4, SQL_C_CHAR, ts, sizeof(ts), &ts_i);
                SQLBindCol(stmt, 5, SQL_C_WCHAR, att, sizeof(att), &att_i);
                SQLBindCol(stmt, 6, SQL_C_WCHAR, att_name, sizeof(att_name), &att_name_i);
                SQLBindCol(stmt, 7, SQL_C_LONG, &duration_ms, 0, &duration_i);
                SQLBindCol(stmt, 8, SQL_C_BINARY, body_enc, sizeof(body_enc), &enc_i);
                SQLBindCol(stmt, 9, SQL_C_LONG, &sender_id, 0, &snd_i);
                SQLBindCol(stmt, 10, SQL_C_LONG, &edited, 0, &ed_i);
                SQLBindCol(stmt, 11, SQL_C_LONG, &deleted, 0, &del_i);
                SQLBindCol(stmt, 12, SQL_C_SBIGINT, &reply_to, 0, &rep_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    json item = {
                        {"id", (long long)id},
                        {"from", wcol(login, sizeof(login), login_i)},
                        {"text", open_group(wcol(body, sizeof(body), body_i),
                    bincol(body_enc, sizeof(body_enc), enc_i),
                    group_id, (int)sender_id)},
                        {"ts", std::string((char*)ts)}
                    };
                    if (att_i > 0)   item["attachment"] = wcol(att, sizeof(att), att_i);
                    if (att_name_i > 0) item["attachment_name"] = wcol(att_name, sizeof(att_name), att_name_i);
                    if (edited)      item["edited"] = true;
                    if (deleted)     item["deleted"] = true;
                    if (rep_i != SQL_NULL_DATA && reply_to > 0) item["reply_to"] = (long long)reply_to;
                    if (duration_i != SQL_NULL_DATA)
                        item["duration_ms"] = duration_ms;
                    items.push_back(std::move(item));
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        json out = { {"items", items} };
        return out.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    // ---------- мои группы ----------
    std::string GroupRepository::list_for_user(int me)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        db_select(dbc,
            "SELECT g.id, g.name, g.kind, mem.role, "
            "(SELECT COUNT(*) FROM GroupMembers x WHERE x.group_id = g.id) "
            "FROM GroupMembers mem JOIN ChatGroups g ON g.id = mem.group_id "
            "WHERE mem.user_id = ? "
            "ORDER BY g.name",
            { DbParam::Int(me) },
            [&](SQLHSTMT stmt)
            {
                SQLINTEGER id = 0, count = 0;
                SQLWCHAR name[256] = {};
                SQLCHAR kind[16] = {}, role[32] = {};
                SQLLEN id_i = 0, name_i = 0, kind_i = 0, role_i = 0, cnt_i = 0;

                SQLBindCol(stmt, 1, SQL_C_LONG, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_WCHAR, name, sizeof(name), &name_i);
                SQLBindCol(stmt, 3, SQL_C_CHAR, kind, sizeof(kind), &kind_i);
                SQLBindCol(stmt, 4, SQL_C_CHAR, role, sizeof(role), &role_i);
                SQLBindCol(stmt, 5, SQL_C_LONG, &count, 0, &cnt_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    items.push_back({
                        {"id", (int)id},
                        {"name", wcol(name, sizeof(name), name_i)},
                        {"kind", std::string((char*)kind)},
                        {"role", std::string((char*)role)},
                        {"members", (int)count}
                        });
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        json out = { {"items", items} };
        return out.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    // ---------- состав группы: владелец, админы, затем остальные по алфавиту ----------
    std::string GroupRepository::members(int group_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        db_select(dbc,
            "SELECT u.login, gm.role, CONVERT(NVARCHAR(30), gm.joined_at, 126) "
            "FROM GroupMembers gm JOIN Users u ON u.id = gm.user_id "
            "WHERE gm.group_id = ? "
            "ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.login",
            { DbParam::Int(group_id) },
            [&](SQLHSTMT stmt)
            {
                SQLWCHAR login[64] = {};
                SQLCHAR role[32] = {}, joined[40] = {};
                SQLLEN login_i = 0, role_i = 0, joined_i = 0;

                SQLBindCol(stmt, 1, SQL_C_WCHAR, login, sizeof(login), &login_i);
                SQLBindCol(stmt, 2, SQL_C_CHAR, role, sizeof(role), &role_i);
                SQLBindCol(stmt, 3, SQL_C_CHAR, joined, sizeof(joined), &joined_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    items.push_back({
                        {"login", wcol(login, sizeof(login), login_i)},
                        {"role", std::string((char*)role)},
                        {"joined_at", std::string((char*)joined)}
                        });
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        json out = { {"items", items} };
        return out.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    // ---------- группы для списка диалогов: последнее сообщение каждой ----------
    // Возвращает JSON-массив. Группа без сообщений получает время создания группы.
    std::string GroupRepository::dialogs_groups(int me, int limit)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        // порядок ? в тексте: me (участник), limit, me (свои сообщения), me (начал звонок), me (участвовал)
        db_select(dbc,
            "WITH x AS ( "
            "  SELECT g.id AS gid, g.name AS gname, g.kind AS gkind, "
            "         lm.id AS msg_id, LEFT(lm.body, 100) AS body, lm.body_enc AS body_enc, "
            "         lm.sender_id AS msg_sender, lm.attachment_url AS att, "
            "         lm.deleted_at AS msg_deleted, lm.created_at AS msg_ts, u.login AS sender, "
            "         lc.id AS call_id, lc.video AS call_video, lc.duration_sec AS call_dur, "
            "         lc.peak_participants AS call_peak, lc.ended_at AS call_ts, "
            "         g.created_at AS g_ts, mem.last_read_id, mem.last_read_call_id, mem.joined_at "
            "  FROM GroupMembers mem "
            "  JOIN ChatGroups g ON g.id = mem.group_id "
            "  OUTER APPLY (SELECT TOP 1 m.id, m.body, m.body_enc, m.attachment_url, "
            "                      m.deleted_at, m.created_at, m.sender_id "
            "               FROM GroupMessages m "
            "               WHERE m.group_id = g.id ORDER BY m.id DESC) lm "
            "  OUTER APPLY (SELECT TOP 1 c.id, c.video, c.duration_sec, c.peak_participants, c.ended_at "
            "               FROM GroupCalls c WHERE c.group_id = g.id ORDER BY c.id DESC) lc "
            "  LEFT JOIN Users u ON u.id = lm.sender_id "
            "  WHERE mem.user_id = ? "
            "), y AS ( "
            "  SELECT x.*, "
            "         CASE WHEN call_ts IS NOT NULL AND (msg_ts IS NULL OR call_ts > msg_ts) "
            "              THEN call_ts ELSE COALESCE(msg_ts, g_ts) END AS last_ts, "
            "         CASE WHEN call_ts IS NOT NULL AND (msg_ts IS NULL OR call_ts > msg_ts) "
            "              THEN 1 ELSE 0 END AS call_is_last "
            "  FROM x "
            ") "
            "SELECT TOP (?) gid, gname, gkind, msg_id, body, att, "
            "CASE WHEN msg_deleted IS NULL THEN 0 ELSE 1 END, "
            "CONVERT(NVARCHAR(30), last_ts, 126), sender, "
            "(SELECT COUNT(*) FROM GroupMessages a "
            " WHERE a.group_id = y.gid AND a.id > y.last_read_id AND a.sender_id <> ? "
            " AND a.deleted_at IS NULL AND a.created_at >= y.joined_at), "
            "call_id, call_video, call_dur, call_peak, CONVERT(NVARCHAR(30), call_ts, 126), "
            "(SELECT COUNT(*) FROM GroupCalls k "
            " WHERE k.group_id = y.gid AND k.id > y.last_read_call_id AND k.started_by <> ? "
            " AND k.ended_at >= y.joined_at "
            " AND NOT EXISTS (SELECT 1 FROM GroupCallParticipants p "
            "                 WHERE p.call_id = k.id AND p.user_id = ?)), "
            "call_is_last, body_enc, msg_sender "
            "FROM y ORDER BY last_ts DESC",
            { DbParam::Int(me), DbParam::Int(limit), DbParam::Int(me), DbParam::Int(me), DbParam::Int(me) },
            [&](SQLHSTMT stmt)
            {
                SQLINTEGER gid = 0, deleted = 0, unread_msgs = 0, unread_calls = 0;
                SQLINTEGER call_video = 0, call_dur = 0, call_peak = 0, call_is_last = 0;
                SQLBIGINT msg_id = 0, call_id = 0;
                SQLWCHAR gname[256] = {}, text[101] = {}, att[201] = {}, from[64] = {};
                SQLCHAR kind[16] = {}, ts[40] = {}, call_ts[40] = {};

                SQLLEN gid_i = 0, gname_i = 0, kind_i = 0, msg_i = 0, text_i = 0, att_i = 0, del_i = 0;
                SQLLEN ts_i = 0, from_i = 0, um_i = 0, call_i = 0, cv_i = 0, cd_i = 0, cp_i = 0;
                SQLLEN cts_i = 0, uc_i = 0, cl_i = 0;

                SQLBindCol(stmt, 1, SQL_C_LONG, &gid, 0, &gid_i);
                SQLBindCol(stmt, 2, SQL_C_WCHAR, gname, sizeof(gname), &gname_i);
                SQLBindCol(stmt, 3, SQL_C_CHAR, kind, sizeof(kind), &kind_i);
                SQLBindCol(stmt, 4, SQL_C_SBIGINT, &msg_id, 0, &msg_i);
                SQLBindCol(stmt, 5, SQL_C_WCHAR, text, sizeof(text), &text_i);
                SQLBindCol(stmt, 6, SQL_C_WCHAR, att, sizeof(att), &att_i);
                SQLBindCol(stmt, 7, SQL_C_LONG, &deleted, 0, &del_i);
                SQLBindCol(stmt, 8, SQL_C_CHAR, ts, sizeof(ts), &ts_i);
                SQLBindCol(stmt, 9, SQL_C_WCHAR, from, sizeof(from), &from_i);
                SQLBindCol(stmt, 10, SQL_C_LONG, &unread_msgs, 0, &um_i);
                SQLBindCol(stmt, 11, SQL_C_SBIGINT, &call_id, 0, &call_i);
                SQLBindCol(stmt, 12, SQL_C_LONG, &call_video, 0, &cv_i);
                SQLBindCol(stmt, 13, SQL_C_LONG, &call_dur, 0, &cd_i);
                SQLBindCol(stmt, 14, SQL_C_LONG, &call_peak, 0, &cp_i);
                SQLBindCol(stmt, 15, SQL_C_CHAR, call_ts, sizeof(call_ts), &cts_i);
                SQLBindCol(stmt, 16, SQL_C_LONG, &unread_calls, 0, &uc_i);
                SQLBindCol(stmt, 17, SQL_C_LONG, &call_is_last, 0, &cl_i);
                unsigned char enc_buf[2112] = {};
                SQLINTEGER msg_sender = 0;
                SQLLEN enc_i = 0, ms_i = 0;
                SQLBindCol(stmt, 18, SQL_C_BINARY, enc_buf, sizeof(enc_buf), &enc_i);    // следующие свободные номера
                SQLBindCol(stmt, 19, SQL_C_LONG, &msg_sender, 0, &ms_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    std::string preview = wcol(text, sizeof(text), text_i);                 // старое сообщение: уже обрезано SQL
                    const std::string enc = bincol(enc_buf, sizeof(enc_buf), enc_i);
                    if (!enc.empty()) preview = utf8_preview(open_group("", enc, (int)gid, (int)msg_sender), 100);

                    json item = {
                        {"type", "group"},
                        {"group_id", (int)gid},
                        {"group", wcol(gname, sizeof(gname), gname_i)},
                        {"kind", std::string((char*)kind)},
                        {"text", preview},
                        {"ts", std::string((char*)ts)},
                        {"unread_calls", (int)unread_calls},
                        {"unread", (int)unread_msgs + (int)unread_calls}
                    };

                    if (msg_i != SQL_NULL_DATA) item["last_id"] = (long long)msg_id;
                    if (from_i > 0)             item["from"] = wcol(from, sizeof(from), from_i);
                    if (att_i > 0)              item["has_attachment"] = true;
                    if (deleted)                item["deleted"] = true;

                    if (call_i != SQL_NULL_DATA)
                    {
                        item["last_call"] = {
                            {"id", (long long)call_id},
                            {"video", call_video != 0},
                            {"duration", (int)call_dur},
                            {"peak", (int)call_peak},
                            {"ts", std::string((char*)call_ts)}
                        };
                        if (call_is_last) item["last_is_call"] = true;
                    }

                    items.push_back(std::move(item));
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        return items.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    int GroupRepository::transfer_owner(int group_id, int old_owner_id, const std::string& new_login)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        auto rollback = [&](int code) { SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK); return code; };

        // 1. новый владелец должен уже состоять в группе
        long r1 = exec_update(dbc,
            "UPDATE gm SET gm.role = 'owner' "
            "FROM GroupMembers gm JOIN Users u ON u.id = gm.user_id "
            "WHERE gm.group_id = ? AND u.login = ? AND gm.role <> 'owner'",
            { DbParam::Int(group_id), DbParam::Text(new_login) });
        if (r1 < 0) return rollback(-1);
        if (r1 == 0) return rollback(0);

        // 2. прежний владелец становится админом
        long r2 = exec_update(dbc,
            "UPDATE GroupMembers SET role = 'admin' "
            "WHERE group_id = ? AND user_id = ? AND role = 'owner'",
            { DbParam::Int(group_id), DbParam::Int(old_owner_id) });
        if (r2 <= 0) return rollback(-1);

        // 3. owner_id в самой группе
        long r3 = exec_update(dbc,
            "UPDATE ChatGroups SET owner_id = (SELECT id FROM Users WHERE login = ?) WHERE id = ?",
            { DbParam::Text(new_login), DbParam::Int(group_id) });
        if (r3 <= 0) return rollback(-1);

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return 1;
    }

    long GroupRepository::mark_read(int group_id, int me, long long id, long long call_id)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        long rows = exec_update(dbc,
            "UPDATE GroupMembers SET "
            "  last_read_id = CASE WHEN last_read_id < ? THEN ? ELSE last_read_id END, "
            "  last_read_call_id = CASE WHEN last_read_call_id < ? THEN ? ELSE last_read_call_id END "
            "WHERE group_id = ? AND user_id = ? AND (last_read_id < ? OR last_read_call_id < ?)",
            { DbParam::BigInt(id), DbParam::BigInt(id), DbParam::BigInt(call_id), DbParam::BigInt(call_id),
              DbParam::Int(group_id), DbParam::Int(me), DbParam::BigInt(id), DbParam::BigInt(call_id) });

        SQLEndTran(SQL_HANDLE_DBC, dbc, rows < 0 ? SQL_ROLLBACK : SQL_COMMIT);
        return rows;
    }

    std::optional<GroupCallRecord> GroupRepository::save_group_call(int group_id, int started_by, bool video,
        int total_sec, int peak, const std::vector<GroupCallStayRow>& stays)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        std::optional<GroupCallRecord> result;

        bool ok = db_select(dbc,
            "INSERT INTO GroupCalls (group_id, started_by, video, started_at, ended_at, duration_sec, peak_participants) "
            "OUTPUT INSERTED.id, CONVERT(NVARCHAR(30), INSERTED.ended_at, 126) "
            "SELECT ?, ?, CAST(? AS BIT), DATEADD(SECOND, -CAST(? AS INT), t.now_), t.now_, CAST(? AS INT), CAST(? AS INT) "
            "FROM (SELECT SYSUTCDATETIME() AS now_) t",
            { DbParam::Int(group_id), DbParam::Int(started_by), DbParam::Int(video ? 1 : 0),
              DbParam::Int(total_sec), DbParam::Int(total_sec), DbParam::Int(peak) },
            [&](SQLHSTMT stmt)
            {
                SQLBIGINT id = 0;
                SQLCHAR ended[40] = {};
                SQLLEN id_i = 0, ended_i = 0;

                SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_CHAR, ended, sizeof(ended), &ended_i);

                if (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    GroupCallRecord rec;
                    rec.id = (long long)id;
                    rec.ended_at = std::string((char*)ended);
                    result = std::move(rec);
                }
            });

        if (ok && result)
        {
            for (const auto& st : stays)
            {
                long rows = exec_update(dbc,
                    "INSERT INTO GroupCallParticipants (call_id, user_id, joined_at, left_at) "
                    "SELECT id, ?, DATEADD(SECOND, CAST(? AS INT), started_at), DATEADD(SECOND, CAST(? AS INT), started_at) "
                    "FROM GroupCalls WHERE id = ?",
                    { DbParam::Int(st.user_id), DbParam::Int(st.offset_sec),
                      DbParam::Int(st.offset_sec + st.duration_sec), DbParam::BigInt(result->id) });

                if (rows < 0) { ok = false; break; }
            }
        }

        const bool success = ok && result.has_value();
        SQLEndTran(SQL_HANDLE_DBC, dbc, success ? SQL_COMMIT : SQL_ROLLBACK);

        if (!success) return std::nullopt;
        return result;
    }

    std::string GroupRepository::sync_group_calls(int me, long long after_id, int limit)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        db_select(dbc,
            "SELECT TOP (?) gc.id, g.id, g.name, us.login, gc.video, gc.duration_sec, gc.peak_participants, "
            "CONVERT(NVARCHAR(30), gc.ended_at, 126), "
            "(SELECT STRING_AGG(x.login, N',') FROM "
            "   (SELECT DISTINCT u.login FROM GroupCallParticipants p "
            "    JOIN Users u ON u.id = p.user_id WHERE p.call_id = gc.id) x), "
            "CASE WHEN gc.started_by <> ? AND NOT EXISTS "
            "   (SELECT 1 FROM GroupCallParticipants p2 WHERE p2.call_id = gc.id AND p2.user_id = ?) "
            "THEN 1 ELSE 0 END "
            "FROM GroupCalls gc "
            "JOIN GroupMembers mem ON mem.group_id = gc.group_id AND mem.user_id = ? "
            "JOIN ChatGroups g ON g.id = gc.group_id "
            "JOIN Users us ON us.id = gc.started_by "
            "WHERE gc.id > ? AND gc.ended_at >= mem.joined_at "
            "ORDER BY gc.id ASC",
            { DbParam::Int(limit), DbParam::Int(me), DbParam::Int(me), DbParam::Int(me), DbParam::BigInt(after_id) },
            [&](SQLHSTMT stmt)
            {
                SQLBIGINT id = 0;
                SQLINTEGER gid = 0, video = 0, duration = 0, peak = 0, missed = 0;
                SQLWCHAR gname[256] = {}, starter[64] = {}, parts[512] = {};
                SQLCHAR ended[40] = {};
                SQLLEN id_i = 0, gid_i = 0, gname_i = 0, starter_i = 0, video_i = 0, dur_i = 0, peak_i = 0;
                SQLLEN ended_i = 0, parts_i = 0, missed_i = 0;

                SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_LONG, &gid, 0, &gid_i);
                SQLBindCol(stmt, 3, SQL_C_WCHAR, gname, sizeof(gname), &gname_i);
                SQLBindCol(stmt, 4, SQL_C_WCHAR, starter, sizeof(starter), &starter_i);
                SQLBindCol(stmt, 5, SQL_C_LONG, &video, 0, &video_i);
                SQLBindCol(stmt, 6, SQL_C_LONG, &duration, 0, &dur_i);
                SQLBindCol(stmt, 7, SQL_C_LONG, &peak, 0, &peak_i);
                SQLBindCol(stmt, 8, SQL_C_CHAR, ended, sizeof(ended), &ended_i);
                SQLBindCol(stmt, 9, SQL_C_WCHAR, parts, sizeof(parts), &parts_i);
                SQLBindCol(stmt, 10, SQL_C_LONG, &missed, 0, &missed_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    items.push_back({
                        {"id", (long long)id},
                        {"group_id", (int)gid},
                        {"group", wcol(gname, sizeof(gname), gname_i)},
                        {"started_by", wcol(starter, sizeof(starter), starter_i)},
                        {"video", video != 0},
                        {"duration", (int)duration},
                        {"peak", (int)peak},
                        {"participants", split_logins(wcol(parts, sizeof(parts), parts_i))},
                        {"missed", missed != 0},
                        {"ts", std::string((char*)ended)}
                        });
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        return items.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    // История группы, от новых к старым. Нужен SQL Server 2017 или новее (STRING_AGG).
    std::string GroupRepository::list_group_calls(int group_id, long long before_id, int limit)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();
        json items = json::array();

        db_select(dbc,
            "SELECT TOP (?) gc.id, us.login, gc.video, gc.duration_sec, gc.peak_participants, "
            "CONVERT(NVARCHAR(30), gc.ended_at, 126), "
            "(SELECT STRING_AGG(x.login, N',') FROM "
            "   (SELECT DISTINCT u.login FROM GroupCallParticipants p "
            "    JOIN Users u ON u.id = p.user_id WHERE p.call_id = gc.id) x) "
            "FROM GroupCalls gc JOIN Users us ON us.id = gc.started_by "
            "WHERE gc.group_id = ? AND (? = 0 OR gc.id < ?) "
            "ORDER BY gc.id DESC",
            { DbParam::Int(limit), DbParam::Int(group_id), DbParam::BigInt(before_id), DbParam::BigInt(before_id) },
            [&](SQLHSTMT stmt)
            {
                SQLBIGINT id = 0;
                SQLINTEGER video = 0, duration = 0, peak = 0;
                SQLWCHAR starter[64] = {}, parts[512] = {};
                SQLCHAR ended[40] = {};
                SQLLEN id_i = 0, starter_i = 0, video_i = 0, dur_i = 0, peak_i = 0, ended_i = 0, parts_i = 0;

                SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_WCHAR, starter, sizeof(starter), &starter_i);
                SQLBindCol(stmt, 3, SQL_C_LONG, &video, 0, &video_i);
                SQLBindCol(stmt, 4, SQL_C_LONG, &duration, 0, &dur_i);
                SQLBindCol(stmt, 5, SQL_C_LONG, &peak, 0, &peak_i);
                SQLBindCol(stmt, 6, SQL_C_CHAR, ended, sizeof(ended), &ended_i);
                SQLBindCol(stmt, 7, SQL_C_WCHAR, parts, sizeof(parts), &parts_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                {
                    json participants = json::array();
                    std::string joined = wcol(parts, sizeof(parts), parts_i);

                    size_t pos = 0;
                    while (pos <= joined.size() && !joined.empty())
                    {
                        size_t comma = joined.find(',', pos);
                        if (comma == std::string::npos) comma = joined.size();
                        if (comma > pos) participants.push_back(joined.substr(pos, comma - pos));
                        pos = comma + 1;
                    }

                    items.push_back({
                        {"id", (long long)id},
                        {"started_by", wcol(starter, sizeof(starter), starter_i)},
                        {"video", video != 0},
                        {"duration", (int)duration},
                        {"peak", (int)peak},
                        {"participants", participants},
                        {"ts", std::string((char*)ended)}
                        });
                }
            });

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);

        json out = { {"items", items} };
        return out.dump(-1, ' ', false, json::error_handler_t::replace);
    }

    int GroupRepository::encrypt_legacy_messages(int batch)
    {
        auto leased = pool.acquire();
        SQLHDBC dbc = leased.handle();

        struct Row { long long id; int group; int sender; std::string body; };
        std::vector<Row> rows;

        // LEN <= 2000: буфер чтения на 2048 символов, более длинный текст обрезался бы при чтении
        // и в шифротекст попал бы урезанный вариант. Такие строки остаются нетронутыми.
        db_select(dbc,
            "SELECT TOP (?) id, group_id, sender_id, body FROM GroupMessages "
            "WHERE body_enc IS NULL AND body <> N'' AND LEN(body) <= 2000 ORDER BY id",
            { DbParam::Int(batch) },
            [&](SQLHSTMT stmt)
            {
                SQLBIGINT id = 0;
                SQLINTEGER g = 0, s = 0;
                SQLWCHAR body[2049] = {};
                SQLLEN id_i = 0, g_i = 0, s_i = 0, b_i = 0;

                SQLBindCol(stmt, 1, SQL_C_SBIGINT, &id, 0, &id_i);
                SQLBindCol(stmt, 2, SQL_C_LONG, &g, 0, &g_i);
                SQLBindCol(stmt, 3, SQL_C_LONG, &s, 0, &s_i);
                SQLBindCol(stmt, 4, SQL_C_WCHAR, body, sizeof(body), &b_i);

                while (SQL_SUCCEEDED(SQLFetch(stmt)))
                    rows.push_back({ (long long)id, (int)g, (int)s, wcol(body, sizeof(body), b_i) });
            });

        int updated = 0;
        for (const auto& row : rows)
        {
            // контекст тот же, что при обычной записи и чтении: группа и отправитель
            auto blob = crypto().encrypt(row.body, aad_group(row.group, row.sender));
            if (!blob) continue;

            long n = exec_update(dbc,
                "UPDATE GroupMessages SET body = N'', body_enc = ? WHERE id = ? AND body_enc IS NULL",
                { DbParam::Blob(*blob), DbParam::BigInt(row.id) });

            if (n > 0) updated += (int)n;
        }

        SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
        return updated;
    }
   