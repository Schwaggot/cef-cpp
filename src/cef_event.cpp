#include "cef_event.hpp"

#include <sstream>

using namespace cef_cpp;

void Event::setSeverity(const int severity) {
    switch (severity) {
    case 0:
        severity_ = Severity::Low;
        break;
    case 1:
        severity_ = Severity::Medium;
        break;
    case 2:
        severity_ = Severity::High;
        break;
    case 3:
        severity_ = Severity::VeryHigh;
        break;
    default:
        severity_ = Severity::Unknown;
        break;
    }
}

void Event::setExtension(const std::string& key, const std::string& value) {
    extensions_[key] = value;
}

std::optional<std::string> Event::getExtension(const std::string& key) const {
    if (const auto it = extensions_.find(key); it != extensions_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<int> Event::getSourcePort() const {
    if (const auto port_str = getExtension("spt"); port_str.has_value()) {
        try {
            return std::stoi(port_str.value());
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<int> Event::getDestinationPort() const {
    if (const auto port_str = getExtension("dpt"); port_str.has_value()) {
        try {
            return std::stoi(port_str.value());
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

bool Event::isValid() const {
    // Check that all required header fields are present
    return version_ > 0 &&
           !device_vendor_.empty() &&
           !device_product_.empty() &&
           !device_version_.empty() &&
           !device_event_class_id_.empty() &&
           !name_.empty() &&
           severity_ != Severity::Unknown;
}

std::string Event::toString() const {
    std::ostringstream oss;

    // TODO add escaping

    // Build header
    oss << "CEF:" << version_
        << "|" << device_vendor_
        << "|" << device_product_
        << "|" << device_version_
        << "|" << device_event_class_id_
        << "|" << name_
        << "|" << static_cast<int>(severity_);

    // Add extensions
    if (!extensions_.empty()) {
        oss << "|";
        bool first = true;
        for (const auto& [key, value] : extensions_) {
            if (!first) {
                oss << " ";
            }
            oss << key << "=" << value;
            first = false;
        }
    }

    return oss.str();
}

std::string Event::severityToString(const Severity severity) {
    switch (severity) {
    case Severity::Low:
        return "Low";
    case Severity::Medium:
        return "Medium";
    case Severity::High:
        return "High";
    case Severity::VeryHigh:
        return "Very High";
    case Severity::Unknown:
        return "Unknown";
    default:
        return "Invalid";
    }
}
