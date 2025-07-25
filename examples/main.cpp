#include "cef_parser.hpp"
#include "cef_event.hpp"

#include <iostream>
#include <vector>

using namespace std;
using namespace cef_cpp;

int main() {
    cout << "CEF Parser Example\n";
    cout << "==================\n\n";

    // Sample CEF events
    vector<string> sample_events = {
        "CEF:0|Security|IDS|1.0|100|Attempted admin login|3|src=192.168.1.100 dst=10.0.0.1 spt=1234 dpt=22 proto=TCP msg=Failed login attempt",
        "CEF:0|ArcSight|ArcSight|4.0.1.4122.3|activity:login|User Login|1|src=192.168.1.50 suser=johndoe outcome=Success",
        "CEF:0|Checkpoint|VPN-1 & FireWall-1|4.1|Accept|Accept|0|src=192.168.1.1 dst=10.0.0.5 proto=tcp service=http",
        "CEF:0|Microsoft|MSWinEventLog|1.0|518|Windows Log Clear|1|src=WORKSTATION01 msg=Security log cleared"
    };

    try {
        for (size_t i = 0; i < sample_events.size(); ++i) {
            cout << "Parsing Event " << (i + 1) << ":\n";
            cout << "Raw: " << sample_events[i] << "\n";

            auto event = Parser::parse(sample_events[i]);

            cout << "Parsed Event Details:\n";
            cout << "  Version: " << event.getVersion() << "\n";
            cout << "  Device Vendor: " << event.getDeviceVendor() << "\n";
            cout << "  Device Product: " << event.getDeviceProduct() << "\n";
            cout << "  Device Version: " << event.getDeviceVersion() << "\n";
            cout << "  Event Class ID: " << event.getDeviceEventClassId() << "\n";
            cout << "  Name: " << event.getName() << "\n";
            cout << "  Severity: " << Event::severityToString(
                event.getSeverity()) << "\n";

            // Show common extensions
            if (auto src = event.getSourceAddress()) {
                cout << "  Source IP: " << *src << "\n";
            }
            if (auto dst = event.getDestinationAddress()) {
                cout << "  Destination IP: " << *dst << "\n";
            }
            if (auto spt = event.getSourcePort()) {
                cout << "  Source Port: " << *spt << "\n";
            }
            if (auto dpt = event.getDestinationPort()) {
                cout << "  Destination Port: " << *dpt << "\n";
            }
            if (auto proto = event.getProtocol()) {
                cout << "  Protocol: " << *proto << "\n";
            }
            if (auto msg = event.getMessage()) {
                cout << "  Message: " << *msg << "\n";
            }

            // Show all extensions
            const auto& extensions = event.getExtensions();
            if (!extensions.empty()) {
                cout << "  All Extensions:\n";
                for (const auto& [key, value] : extensions) {
                    cout << "    " << key << " = " << value << "\n";
                }
            }

            cout << "  Valid: " << (event.isValid() ? "Yes" : "No") << "\n";
            cout << "  Reconstructed: " << event.toString() << "\n";
            cout << "\n";
        }

        // Test batch parsing
        cout << "Batch Parsing Test:\n";
        cout << "===================\n";

        auto events = Parser::parseMultiple(sample_events);
        cout << "Successfully parsed " << events.size() << " events\n\n";

        // Test string parsing with multiple lines
        string multi_line_log =
            sample_events[0] + "\n" + sample_events[1] + "\n" + sample_events[2];
        auto events_from_string = Parser::parseFromString(multi_line_log);
        cout << "Parsed " << events_from_string.size() <<
            " events from multi-line string\n\n";

        // Test validation
        cout << "Validation Tests:\n";
        cout << "=================\n";

        vector<string> test_lines = {
            "CEF:0|Test|Product|1.0|100|Test Event|2|msg=Valid event",
            "Invalid CEF line",
            "CEF:0|Missing|Fields|1.0|Test Event|2",
            ""
        };

        for (const auto& line : test_lines) {
            cout << "Line: '" << line << "' -> Valid: "
                << (Parser::isValidCEF(line) ? "Yes" : "No") << "\n";
        }

    } catch (const ParseException& e) {
        cerr << "Parse error: " << e.what() << "\n";
        return 1;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}