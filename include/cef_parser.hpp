#ifndef CEF_CPP_CEF_PARSER_H
#define CEF_CPP_CEF_PARSER_H

#include "cef_event.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace cef_cpp {

/**
 * @brief Exception thrown when CEF parsing fails
 */
class ParseException : public std::runtime_error {
public:
    explicit ParseException(const std::string& message)
        : std::runtime_error(message) {
    }
};

/**
 * @brief CEF (Common Event Format) Parser
 *
 * Parses CEF formatted log messages according to the CEF specification.
 * CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
 */
class Parser {
public:
    /**
     * @brief Parse a single CEF log line
     *
     * @param cef_line The CEF formatted string to parse
     * @return Parsed CEF Event object
     * @throws ParseException if the line cannot be parsed
     */
    static Event parse(const std::string& cef_line);

    /**
     * @brief Parse multiple CEF log lines
     *
     * @param cef_lines Vector of CEF formatted strings
     * @return Vector of parsed CEF Event objects
     * @throws ParseException if any line cannot be parsed
     */
    static std::vector<Event> parseMultiple(const std::vector<std::string>& cef_lines);

    /**
     * @brief Parse CEF log from a string containing multiple lines
     *
     * @param cef_log Multi-line string containing CEF events
     * @return Vector of parsed CEF Event objects
     * @throws ParseException if any line cannot be parsed
     */
    static std::vector<Event> parseFromString(const std::string& cef_log);

    /**
     * @brief Validate if a string appears to be a valid CEF format
     *
     * @param cef_line The string to validate
     * @return true if the string appears to be valid CEF format
     */
    static bool isValidCEF(const std::string& cef_line);

private:
    // Helper methods for parsing
    static std::vector<std::string> splitHeader(const std::string& header_part);
    static std::unordered_map<std::string, std::string> parseExtensions(
        const std::string& extension_part);
    static std::string unescapeString(const std::string& str);
    static std::string escapeString(const std::string& str);
    static void validateHeaderFieldCount(const std::vector<std::string>& fields);
};

} // namespace cef_cpp

#endif