#include <gtest/gtest.h>

#include "cef_parser.hpp"
#include "cef_event.hpp"

using namespace cef_cpp;

// Test basic parsing of required fields
TEST(CEFParserTest, BasicParsing)
{
    std::string cef_line = "CEF:0|Security|IDS|1.0|100|Test Event|2|src=192.168.1.1 dst=10.0.0.1";
    auto event = Parser::parse(cef_line);

    EXPECT_EQ(event.getVersion(), 0);
    EXPECT_EQ(event.getDeviceVendor(), "Security");
    EXPECT_EQ(event.getDeviceProduct(), "IDS");
    EXPECT_EQ(event.getDeviceVersion(), "1.0");
    EXPECT_EQ(event.getDeviceEventClassId(), "100");
    EXPECT_EQ(event.getName(), "Test Event");
    EXPECT_EQ(event.getSeverity(), Event::Severity::High);
    EXPECT_EQ(event.getSourceAddress(), "192.168.1.1");
    EXPECT_EQ(event.getDestinationAddress(), "10.0.0.1");
}

// Test parsing of various extension fields
TEST(CEFParserTest, ExtensionParsing)
{
    const std::string cef_line =
        "CEF:0|Test|Product|1.0|100|Event|1|src=1.1.1.1 spt=80 dst=2.2.2.2 dpt=443 proto=TCP msg=Test message";
    const auto event = Parser::parse(cef_line);

    EXPECT_EQ(event.getSourceAddress(), "1.1.1.1");
    EXPECT_EQ(event.getDestinationAddress(), "2.2.2.2");
    EXPECT_EQ(event.getSourcePort(), 80);
    EXPECT_EQ(event.getDestinationPort(), 443);
    EXPECT_EQ(event.getProtocol(), "TCP");
    EXPECT_EQ(event.getMessage(), "Test message");
}

// Test parsing of a CEF line with no extensions
TEST(CEFParserTest, EmptyExtensions)
{
    const std::string cef_line = "CEF:0|Test|Product|1.0|100|Event|0";
    const auto event = Parser::parse(cef_line);

    EXPECT_EQ(event.getVersion(), 0);
    EXPECT_EQ(event.getName(), "Event");
    EXPECT_EQ(event.getSeverity(), Event::Severity::Low);
    EXPECT_TRUE(event.getExtensions().empty());
}

TEST(CEFParserTest, ParseExtensions)
{
    {
        const std::string extension_part = "msg=Message with + and - chars";
        const auto extensions = Parser::parseExtensions(extension_part);

        EXPECT_EQ(extensions.size(), 1);
        EXPECT_EQ(extensions.at("msg"), "Message with + and - chars");
    }

    {
        const std::string extension_part = "msg=Message with \\= and \\| chars";
        const auto extensions = Parser::parseExtensions(extension_part);

        EXPECT_EQ(extensions.size(), 1);
        EXPECT_EQ(extensions.at("msg"), "Message with = and | chars");
    }
}

// Test escaped characters in fields
TEST(CEFParserTest, EscapedCharacters)
{
    const std::string cef_line =
        R"(CEF:0|Test\|Vendor|Product\=1|1.0|100|Event\|Name|1|msg=Message with \= and \| chars)";
    const auto event = Parser::parse(cef_line);

    EXPECT_EQ(event.getDeviceVendor(), "Test|Vendor");
    EXPECT_EQ(event.getDeviceProduct(), "Product=1");
    EXPECT_EQ(event.getName(), "Event|Name");
    EXPECT_EQ(event.getMessage(), "Message with = and | chars");
}

// Test invalid lines throw exceptions
TEST(CEFParserTest, InvalidFormat)
{
    const std::vector<std::string> invalid_lines = {
        "",
        "Not a CEF line",
        "CEF:0|Too|Few|Fields",
        "CEF:invalid|version|test|1.0|100|Event|1"
    };

    for (const auto& line : invalid_lines)
    {
        EXPECT_THROW(Parser::parse(line), ParseException);
    }
}

// Test batch parsing of multiple CEF lines
TEST(CEFParserTest, BatchParsing)
{
    const std::vector<std::string> lines = {
        "CEF:0|Vendor1|Product1|1.0|100|Event1|1|src=1.1.1.1",
        "CEF:0|Vendor2|Product2|2.0|200|Event2|2|dst=2.2.2.2"
    };

    const auto events = Parser::parseMultiple(lines);

    ASSERT_EQ(events.size(), 2);
    EXPECT_EQ(events[0].getDeviceVendor(), "Vendor1");
    EXPECT_EQ(events[1].getDeviceVendor(), "Vendor2");
    EXPECT_EQ(events[0].getSourceAddress(), "1.1.1.1");
    EXPECT_EQ(events[1].getDestinationAddress(), "2.2.2.2");
}

// Test isValidCEF utility
TEST(CEFParserTest, Validation)
{
    EXPECT_TRUE(Parser::isValidCEF("CEF:0|Test|Product|1.0|100|Event|1"));
    EXPECT_FALSE(Parser::isValidCEF("Invalid line"));
    EXPECT_FALSE(Parser::isValidCEF(""));
    EXPECT_FALSE(Parser::isValidCEF("CEF:0|Too|Few"));
}

// Test severity parsing logic
TEST(CEFParserTest, SeverityLevels)
{
    std::vector<std::pair<std::string, Event::Severity>> test_cases = {
        {"CEF:0|Test|Product|1.0|100|Event|0", Event::Severity::Low},
        {"CEF:0|Test|Product|1.0|100|Event|1", Event::Severity::Medium},
        {"CEF:0|Test|Product|1.0|100|Event|2", Event::Severity::High},
        {"CEF:0|Test|Product|1.0|100|Event|3", Event::Severity::VeryHigh},
        {"CEF:0|Test|Product|1.0|100|Event|99", Event::Severity::Unknown}
    };

    for (const auto& [line, expected] : test_cases)
    {
        auto event = Parser::parse(line);
        EXPECT_EQ(event.getSeverity(), expected);
    }
}

// Test round-trip parsing and string reconstruction
TEST(CEFParserTest, ToStringReconstruction)
{
    std::string original = "CEF:0|Security|IDS|1.0|100|Test Event|2|src=192.168.1.1 dst=10.0.0.1 proto=TCP";
    auto event = Parser::parse(original);
    std::string reconstructed = event.toString();

    auto reparsed = Parser::parse(reconstructed);

    EXPECT_EQ(reparsed.getVersion(), event.getVersion());
    EXPECT_EQ(reparsed.getDeviceVendor(), event.getDeviceVendor());
    EXPECT_EQ(reparsed.getName(), event.getName());
    EXPECT_EQ(reparsed.getSourceAddress(), event.getSourceAddress());
}
