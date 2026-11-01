#pragma once
#include <string>
#include <optional>
#include "ConnectionPool.h"
#include "Utf16.h"
#include "DbHelpers.h"
struct CreatedGroup
{
	int id = 0;
	std::string name;
	std::string kind = "group";
};
struct GroupMessageRecord
{
	long long id;
	std::string created_at;
};
struct GroupCallStayRow
{
	int user_id = 0;
	int offset_sec = 0;       // сколько секунд после начала звонка человек зашЄл
	int duration_sec = 0;     // сколько секунд пробыл
};

struct GroupCallRecord
{
	long long id = 0;
	std::string ended_at;
};
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


class GroupRepository
{
public:
	GroupRepository(ConnectionPool& pool) : pool(pool) {}
	std::optional<CreatedGroup> find_by_name(const std::string& group_name);
	std::optional<GroupMessageRecord> save_messages(int group_id, int sender_id, const std::string& body,
		const std::string& attachment_url = "", long long reply_to = 0, const std::string& attachment_name = "");
	std::vector<int> get_member_ids(int group_id);
	std::optional<std::string> get_member_role(int group_id, int user_id);
	long add_member(int group_id, const std::string& login);                  // 1 = добавлен, 0 = нет такого или уже в группе
	long remove_member_by_login(int group_id, const std::string& login, bool only_customers);
	long remove_member_by_id(int group_id, int user_id);                      // владельца не удал€ет
	long rename_group(int group_id, const std::string& name);
	bool delete_group(int group_id);
	long set_role(int group_id, const std::string& login, const std::string& role);
    long edit_message(int group_id, int sender_id, long long id, const std::string& text);
    long delete_message(int group_id, long long id, int only_sender_id);   // 0 = любое (модератор)
    int  group_message_exists(int group_id, long long id);
	std::string sync_groups(int me, long long after_id, const std::string& since, int limit);
	std::string history(int group_id, long long before_id, int limit);
	std::string list_for_user(int me);
	std::string members(int group_id);
	std::string dialogs_groups(int me, int limit);

	int transfer_owner(int group_id, int old_owner_id, const std::string& new_login);

	long mark_read(int group_id, int me, long long id, long long call_id = 0);
	std::string sync_group_calls(int me, long long after_id, int limit);
	std::optional<GroupCallRecord> save_group_call(int group_id, int started_by, bool video,
		int total_sec, int peak,
		const std::vector<GroupCallStayRow>& stays);
	std::string list_group_calls(int group_id, long long before_id, int limit);
	int encrypt_legacy_messages(int batch);
private:
	ConnectionPool& pool;
	
};