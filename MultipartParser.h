#pragma once
#include <string>
#include <vector>
#include <optional>

struct UploadedFile
{
    std::string field_name;
    std::string filename;
    std::string content_type;
    std::string data; // сырые байты файла
};

inline std::optional<std::string> extract_boundary(const std::string& content_type_header)
{
    auto pos = content_type_header.find("boundary=");
    if (pos == std::string::npos)
        return std::nullopt;

    std::string boundary = content_type_header.substr(pos + 9);

    // boundary иногда в кавычках
    if (!boundary.empty() && boundary.front() == '"')
    {
        boundary = boundary.substr(1, boundary.find('"', 1) - 1);
    }

    return boundary;
}

inline std::vector<UploadedFile> parse_multipart(const std::string& body, const std::string& boundary)
{
    std::vector<UploadedFile> files;
    std::string delimiter = "--" + boundary;

    size_t pos = body.find(delimiter);
    if (pos == std::string::npos) return files;

    pos += delimiter.size();

    while (true)
    {
        // Конец всех частей
        if (body.compare(pos, 2, "--") == 0)
            break;

        // Пропускаем \r\n после разделителя
        if (body.compare(pos, 2, "\r\n") == 0)
            pos += 2;

        size_t headers_end = body.find("\r\n\r\n", pos);
        if (headers_end == std::string::npos) break;

        std::string headers = body.substr(pos, headers_end - pos);

        std::string field_name, filename, content_type;

        size_t name_pos = headers.find("name=\"");
        if (name_pos != std::string::npos)
        {
            name_pos += 6;
            size_t name_end = headers.find('"', name_pos);
            field_name = headers.substr(name_pos, name_end - name_pos);
        }

        size_t fname_pos = headers.find("filename=\"");
        if (fname_pos != std::string::npos)
        {
            fname_pos += 10;
            size_t fname_end = headers.find('"', fname_pos);
            filename = headers.substr(fname_pos, fname_end - fname_pos);
        }

        size_t ct_pos = headers.find("Content-Type: ");
        if (ct_pos != std::string::npos)
        {
            ct_pos += 14;
            size_t ct_end = headers.find("\r\n", ct_pos);
            if (ct_end == std::string::npos) ct_end = headers.size();
            content_type = headers.substr(ct_pos, ct_end - ct_pos);
        }

        size_t data_start = headers_end + 4;
        size_t next_delim = body.find(delimiter, data_start);
        if (next_delim == std::string::npos) break;

        // Данные заканчиваются перед \r\n, который идёт прямо перед разделителем
        size_t data_end = next_delim;
        if (data_end >= 2 && body.compare(data_end - 2, 2, "\r\n") == 0)
            data_end -= 2;

        if (!filename.empty())
        {
            UploadedFile file;
            file.field_name = field_name;
            file.filename = filename;
            file.content_type = content_type;
            file.data = body.substr(data_start, data_end - data_start);
            files.push_back(std::move(file));
        }

        pos = next_delim + delimiter.size();
    }

    return files;
}