#ifndef CEF_CPP_CEF_EVENT_H
#define CEF_CPP_CEF_EVENT_H

#include <optional>
#include <string>
#include <unordered_map>

namespace cef_cpp {

/**
 * @brief Represents a parsed CEF (Common Event Format) event
 *
 * CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
 */
class Event {
public:
    /**
     * @brief Severity levels as defined in CEF specification
     */
    enum class Severity {
        Low = 0,
        Medium = 1,
        High = 2,
        VeryHigh = 3,
        Unknown = -1
    };

    // Constructor
    Event() = default;

    // CEF Header fields (required)
    void setVersion(const int version) { version_ = version; }
    void setDeviceVendor(const std::string& vendor) { device_vendor_ = vendor; }
    void setDeviceProduct(const std::string& product) { device_product_ = product; }
    void setDeviceVersion(const std::string& version) { device_version_ = version; }

    void setDeviceEventClassId(const std::string& class_id) {
        device_event_class_id_ = class_id;
    }

    void setName(const std::string& name) { name_ = name; }
    void setSeverity(const Severity severity) { severity_ = severity; }
    void setSeverity(int severity);

    // Getters for header fields
    int getVersion() const { return version_; }
    const std::string& getDeviceVendor() const { return device_vendor_; }
    const std::string& getDeviceProduct() const { return device_product_; }
    const std::string& getDeviceVersion() const { return device_version_; }
    const std::string& getDeviceEventClassId() const { return device_event_class_id_; }
    const std::string& getName() const { return name_; }
    Severity getSeverity() const { return severity_; }

    // Extension fields (key-value pairs)
    void setExtension(const std::string& key, const std::string& value);
    std::optional<std::string> getExtension(const std::string& key) const;

    const std::unordered_map<std::string, std::string>& getExtensions() const {
        return extensions_;
    }

    // Common extension field helpers
    void setSourceAddress(const std::string& address) { setExtension("src", address); }

    void setDestinationAddress(const std::string& address) {
        setExtension("dst", address);
    }

    void setSourcePort(int port) { setExtension("spt", std::to_string(port)); }
    void setDestinationPort(int port) { setExtension("dpt", std::to_string(port)); }
    void setProtocol(const std::string& protocol) { setExtension("proto", protocol); }
    void setMessage(const std::string& message) { setExtension("msg", message); }

    std::optional<std::string> getSourceAddress() const { return getExtension("src"); }

    std::optional<std::string> getDestinationAddress() const {
        return getExtension("dst");
    }

    std::optional<int> getSourcePort() const;
    std::optional<int> getDestinationPort() const;
    std::optional<std::string> getProtocol() const { return getExtension("proto"); }
    std::optional<std::string> getMessage() const { return getExtension("msg"); }

    // Utility methods
    bool isValid() const;
    std::string toString() const;
    static std::string severityToString(Severity severity);

private:
    // CEF Header fields
    int version_ = 0;
    std::string device_vendor_;
    std::string device_product_;
    std::string device_version_;
    std::string device_event_class_id_;
    std::string name_;
    Severity severity_ = Severity::Unknown;

    // Extension fields
    std::unordered_map<std::string, std::string> extensions_;
};

} // namespace cef_cpp

#endif