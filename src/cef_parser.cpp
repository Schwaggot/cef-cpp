#include "cef_parser.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <iostream>

using namespace cef_cpp;

Event Parser::parse(const std::string& cef_line) {
    if (cef_line.empty()) {
        throw ParseException("Empty CEF line");
    }

    // Check if line starts with CEF:
    if (cef_line.substr(0, 4) != "CEF:") {
        throw ParseException("Line does not start with 'CEF:'");
    }

    // Remove the CEF: prefix
    std::string content = cef_line.substr(4);

    // CEF Format: Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    // We need to split this carefully, as the extension part is optional and contains the last |

    // First, let's split by pipes, but be careful about the last field
    std::vector<std::string> all_parts;
    std::string current_part;

    for (size_t i = 0; i < content.length(); ++i) {
        char c = content[i];

        if (c == '|' && (i == 0 || content[i - 1] != '\\')) {
            all_parts.push_back(current_part);
            current_part.clear();
        } else {
            current_part += c;
        }
    }

    // Add the last part
    all_parts.push_back(current_part);

    // Now we should have at least 7 parts: Version, Vendor, Product, DeviceVersion, ClassID, Name, Severity[, Extensions]
    if (all_parts.size() < 7) {
        throw ParseException(
            "Invalid CEF format: expected at least 7 fields (Version|Vendor|Product|DeviceVersion|ClassID|Name|Severity), got "
            +
            std::to_string(all_parts.size()));
    }

    // Extract header fields (first 7)
    std::vector<std::string> header_fields(all_parts.begin(), all_parts.begin() + 7);

    // Everything after the 7th field is extensions
    std::string extension_part;
    if (all_parts.size() > 7) {
        // Reconstruct extension part by joining remaining parts with |
        for (size_t i = 7; i < all_parts.size(); ++i) {
            if (i > 7)
                extension_part += "|";
            extension_part += all_parts[i];
        }
    }

    // Validate header fields
    validateHeaderFieldCount(header_fields);

    // Create and populate event
    Event event;

    try {
        // Parse version
        event.setVersion(std::stoi(header_fields[0]));

        // Set header fields (unescape them)
        event.setDeviceVendor(unescapeString(header_fields[1]));
        event.setDeviceProduct(unescapeString(header_fields[2]));
        event.setDeviceVersion(unescapeString(header_fields[3]));
        event.setDeviceEventClassId(unescapeString(header_fields[4]));
        event.setName(unescapeString(header_fields[5]));

        // Parse severity
        event.setSeverity(std::stoi(header_fields[6]));
    } catch (const std::exception& e) {
        throw ParseException("Error parsing CEF header fields: " + std::string(e.what()));
    }

    // Parse extensions if present
    if (!extension_part.empty()) {
        auto extensions = parseExtensions(extension_part);
        for (const auto& [key, value] : extensions) {
            event.setExtension(key, value);
        }
    }

    return event;
}

std::vector<Event> Parser::parseMultiple(const std::vector<std::string>& cef_lines) {
    std::vector<Event> events;
    events.reserve(cef_lines.size());

    for (size_t i = 0; i < cef_lines.size(); ++i) {
        try {
            events.push_back(parse(cef_lines[i]));
        } catch (const ParseException& e) {
            throw ParseException(
                "Error parsing line " + std::to_string(i + 1) + ": " + e.what());
        }
    }

    return events;
}

std::vector<Event> Parser::parseFromString(const std::string& cef_log) {
    std::vector<std::string> lines;
    boost::split(lines, cef_log, boost::is_any_of("\n\r"));

    // Remove empty lines
    std::erase_if(lines,
                  [](const std::string& line) {
                      return boost::trim_copy(line).empty();
                  });

    return parseMultiple(lines);
}

bool Parser::isValidCEF(const std::string& cef_line) {
    try {
        parse(cef_line);
        return true;
    } catch (const ParseException&) {
        return false;
    }
}

std::vector<std::string> Parser::splitHeader(const std::string& header_part) {
    std::vector<std::string> fields;
    std::string current_field;

    for (size_t i = 0; i < header_part.length(); ++i) {
        char c = header_part[i];

        if (c == '|' && (i == 0 || header_part[i - 1] != '\\')) {
            fields.push_back(current_field);
            current_field.clear();
        } else {
            current_field += c;
        }
    }

    // Add the last field (severity)
    fields.push_back(current_field);

    // Debug output for troubleshooting
#ifdef DEBUG
    std::cout << "DEBUG: Split header into " << fields.size() << " fields:" << std::endl;
    for (size_t i = 0; i < fields.size(); ++i) {
        std::cout << "  Field " << i << ": '" << fields[i] << "'" << std::endl;
    }
#endif

    return fields;
}

std::unordered_map<std::string, std::string> Parser::parseExtensions(
    const std::string& extension_part) {
    std::unordered_map<std::string, std::string> extensions;

    if (extension_part.empty()) {
        return extensions;
    }

    // Use regex to parse key=value pairs, handling escaped characters
    const boost::regex extension_regex(R"((\w+)=((?:\\.|(?!\s+\w+=).)*))");
    boost::sregex_iterator iter(extension_part.begin(),
                                extension_part.end(),
                                extension_regex);
    boost::sregex_iterator end;

    for (; iter != end; ++iter) {
        const boost::smatch& match = *iter;
        std::string key = match[1].str();
        std::string value = boost::trim_copy(match[2].str());

        // Unescape the value
        value = unescapeString(value);

        extensions[key] = value;
    }

    return extensions;
}

std::string Parser::unescapeString(const std::string& str) {
    std::string result;
    result.reserve(str.length());

    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '\\' && i + 1 < str.length()) {
            char next = str[i + 1];
            switch (next) {
            case '\\':
                result += '\\';
                break;
            case '|':
                result += '|';
                break;
            case '=':
                result += '=';
                break;
            case 'n':
                result += '\n';
                break;
            case 'r':
                result += '\r';
                break;
            case 't':
                result += '\t';
                break;
            default:
                result += '\\';
                result += next;
                break;
            }
            ++i; // Skip the next character
        } else {
            result += str[i];
        }
    }

    return result;
}

std::string Parser::escapeString(const std::string& str) {
    std::string result;
    result.reserve(str.length() * 2); // Rough estimate

    for (char c : str) {
        switch (c) {
        case '\\':
            result += "\\\\";
            break;
        case '|':
            result += "\\|";
            break;
        case '=':
            result += "\\=";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result += c;
            break;
        }
    }

    return result;
}

void Parser::validateHeaderFieldCount(const std::vector<std::string>& fields) {
    if (fields.size() != 7) {
        throw ParseException(
            "Invalid CEF header: expected 7 fields (Version|Vendor|Product|Version|ClassID|Name|Severity), got "
            +
            std::to_string(fields.size()) + " fields");
    }

    // Additional validation for empty required fields
    if (fields[0].empty())
        throw ParseException("CEF Version cannot be empty");
    if (fields[1].empty())
        throw ParseException("Device Vendor cannot be empty");
    if (fields[2].empty())
        throw ParseException("Device Product cannot be empty");
    if (fields[3].empty())
        throw ParseException("Device Version cannot be empty");
    if (fields[4].empty())
        throw ParseException("Device Event Class ID cannot be empty");
    if (fields[5].empty())
        throw ParseException("Event Name cannot be empty");
    if (fields[6].empty())
        throw ParseException("Severity cannot be empty");
}
