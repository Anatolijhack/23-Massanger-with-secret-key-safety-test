#pragma once
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>  
#include <sql.h>
#include <sqlext.h>
#include "Utf16.h"

struct DbParam
{
    enum class Kind { Int32, Int64, Text, Blob };

    Kind kind = Kind::Int32;
    int i = 0;
    long long ll = 0;
    std::wstring w;
    SQLLEN ind = 0;
    std::string bin;

    static DbParam Int(int v) { DbParam p; p.kind = Kind::Int32; p.i = v; return p; }
    static DbParam BigInt(long long v) { DbParam p; p.kind = Kind::Int64; p.ll = v; return p; }
    static DbParam Text(const std::string& s)
    {
        DbParam p;
        p.kind = Kind::Text;
        p.w = utf8_to_wide(s);
        p.ind = SQL_NTS;
        return p;
    }
    static DbParam Blob(const std::string& b)       // пустая строка записывается как NULL
    {
        DbParam p;
        p.kind = Kind::Blob;
        p.bin = b;
        p.ind = b.empty() ? SQL_NULL_DATA : (SQLLEN)b.size();
        return p;
    }
};

inline void db_bind(SQLHSTMT stmt, std::vector<DbParam>& ps)
{
    for (size_t k = 0; k < ps.size(); ++k)
    {
        DbParam& p = ps[k];
        SQLUSMALLINT idx = (SQLUSMALLINT)(k + 1);

        if (p.kind == DbParam::Kind::Text)
            SQLBindParameter(stmt, idx, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
                (std::max)((SQLULEN)1, (SQLULEN)p.w.size()), 0, (SQLPOINTER)p.w.c_str(), 0, &p.ind);
        else if (p.kind == DbParam::Kind::Int64)
            SQLBindParameter(stmt, idx, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT, 0, 0, &p.ll, 0, &p.ind);
        else if (p.kind == DbParam::Kind::Blob)
            SQLBindParameter(stmt, idx, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_VARBINARY,
                (std::max)((SQLULEN)1, (SQLULEN)p.bin.size()), 0,
                (SQLPOINTER)p.bin.data(), (SQLLEN)p.bin.size(), &p.ind);
        else
            SQLBindParameter(stmt, idx, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &p.i, 0, &p.ind);
    }
}

inline void db_log_error(SQLHSTMT stmt)
{
    SQLCHAR state[6], msg[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER native;
    SQLSMALLINT len;
    if (SQLGetDiagRecA(SQL_HANDLE_STMT, stmt, 1, state, &native, msg, sizeof(msg), &len) == SQL_SUCCESS)
        std::cerr << "ODBC Error [" << state << "] " << msg << std::endl;
}


// Число затронутых строк или -1 при ошибке. COMMIT/ROLLBACK делает вызывающий.
inline long exec_update(SQLHDBC dbc, const std::string& sql, std::vector<DbParam> ps)
{
    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    SQLPrepareA(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
    db_bind(stmt, ps);

    if (!SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        db_log_error(stmt);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return -1;
    }

    SQLLEN rows = 0;
    SQLRowCount(stmt, &rows);
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    return (long)rows;
}

// 1 = строка есть, 0 = нет, -1 = ошибка
inline int db_exists(SQLHDBC dbc, const std::string& sql, std::vector<DbParam> ps)
{
    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    SQLPrepareA(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
    db_bind(stmt, ps);

    int result = -1;
    if (SQL_SUCCEEDED(SQLExecute(stmt)))
    {
        SQLRETURN fr = SQLFetch(stmt);
        result = SQL_SUCCEEDED(fr) ? 1 : (fr == SQL_NO_DATA ? 0 : -1);
    }
    else
    {
        db_log_error(stmt);
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    return result;
}

// Читает NVARCHAR-колонку. NULL и пустая строка дают "", лишнее обрезается по буферу.
inline std::string wcol(const SQLWCHAR* buf, size_t buf_bytes, SQLLEN ind)
{
    if (ind <= 0) return {};
    size_t bytes = (std::min)((size_t)ind, buf_bytes - sizeof(wchar_t));
    return wide_to_utf8((const wchar_t*)buf, (int)(bytes / sizeof(wchar_t)));
}

// Подготовить, привязать параметры, выполнить, отдать stmt в rows(stmt), освободить.
template <class F>
bool db_select(SQLHDBC dbc, const char* sql, std::vector<DbParam> ps, F&& rows)
{
    SQLHSTMT stmt = nullptr;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    SQLPrepareA(stmt, (SQLCHAR*)sql, SQL_NTS);
    db_bind(stmt, ps);

    bool ok = SQL_SUCCEEDED(SQLExecute(stmt));
    if (ok) rows(stmt);
    else    db_log_error(stmt);

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    return ok;
}