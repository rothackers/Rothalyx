#pragma once

#include <QString>

namespace zara::desktop_qt::app {

class SecretStore {
public:
    [[nodiscard]] static bool is_available();
    [[nodiscard]] static QString availability_description();
    [[nodiscard]] static bool read_secret(const QString& account, QString& out_secret, QString& out_error);
    [[nodiscard]] static bool write_secret(const QString& account, const QString& secret, QString& out_error);
    [[nodiscard]] static bool delete_secret(const QString& account, QString& out_error);
};

}  // namespace zara::desktop_qt::app
