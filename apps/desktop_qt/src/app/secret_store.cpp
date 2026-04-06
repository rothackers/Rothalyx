#include "zara/desktop_qt/app/secret_store.hpp"

#include <QObject>
#include <QProcess>
#include <QStandardPaths>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <wincred.h>
#endif

namespace zara::desktop_qt::app {

namespace {

QString service_name() {
    return "zara.re.framework.ai";
}

#if !defined(_WIN32)
bool run_process(
    const QString& program,
    const QStringList& arguments,
    const QByteArray& input,
    QByteArray& out_stdout,
    QString& out_error
) {
    QProcess process;
    process.start(program, arguments);
    if (!process.waitForStarted(3000)) {
        out_error = QObject::tr("Failed to start %1.").arg(program);
        return false;
    }
    if (!input.isEmpty()) {
        process.write(input);
    }
    process.closeWriteChannel();
    if (!process.waitForFinished(5000)) {
        process.kill();
        out_error = QObject::tr("%1 timed out while talking to the system secret store.").arg(program);
        return false;
    }

    out_stdout = process.readAllStandardOutput();
    const QString stderr_text = QString::fromUtf8(process.readAllStandardError()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit) {
        out_error = stderr_text.isEmpty() ? QObject::tr("%1 exited unexpectedly.").arg(program) : stderr_text;
        return false;
    }
    if (process.exitCode() != 0) {
        out_error = stderr_text;
        return false;
    }
    return true;
}
#endif

}  // namespace

bool SecretStore::is_available() {
#if defined(_WIN32)
    return true;
#elif defined(__APPLE__)
    return !QStandardPaths::findExecutable("security").isEmpty();
#else
    return !QStandardPaths::findExecutable("secret-tool").isEmpty();
#endif
}

QString SecretStore::availability_description() {
#if defined(_WIN32)
    return "API keys are stored in Windows Credential Manager.";
#elif defined(__APPLE__)
    return is_available() ? "API keys are stored in the macOS Keychain."
                          : "The macOS security tool is not available. Zara will rely on environment variables for provider credentials.";
#else
    return is_available() ? "API keys are stored through the Secret Service keyring."
                          : "secret-tool is not available. Zara will rely on environment variables for provider credentials.";
#endif
}

bool SecretStore::read_secret(const QString& account, QString& out_secret, QString& out_error) {
    out_secret.clear();
    out_error.clear();

#if defined(_WIN32)
    PCREDENTIALW credential = nullptr;
    const std::wstring target = service_name().toStdWString() + L":" + account.toStdWString();
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        const DWORD error = GetLastError();
        if (error == ERROR_NOT_FOUND) {
            return true;
        }
        out_error = QString("Credential Manager read failed (%1).").arg(error);
        return false;
    }

    if (credential->CredentialBlobSize > 0 && credential->CredentialBlob != nullptr) {
        const auto* begin = reinterpret_cast<const char*>(credential->CredentialBlob);
        out_secret = QString::fromUtf8(begin, static_cast<int>(credential->CredentialBlobSize));
    }
    CredFree(credential);
    return true;
#elif defined(__APPLE__)
    const QString program = QStandardPaths::findExecutable("security");
    if (program.isEmpty()) {
        return true;
    }

    QByteArray stdout_text;
    if (!run_process(
            program,
            {"find-generic-password", "-a", account, "-s", service_name(), "-w"},
            {},
            stdout_text,
            out_error
        )) {
        if (out_error.contains("could not be found", Qt::CaseInsensitive) ||
            out_error.contains("item could not be found", Qt::CaseInsensitive)) {
            out_error.clear();
            return true;
        }
        return false;
    }
    out_secret = QString::fromUtf8(stdout_text).trimmed();
    return true;
#else
    const QString program = QStandardPaths::findExecutable("secret-tool");
    if (program.isEmpty()) {
        return true;
    }

    QByteArray stdout_text;
    if (!run_process(program, {"lookup", "service", service_name(), "account", account}, {}, stdout_text, out_error)) {
        if (out_error.contains("No such secret", Qt::CaseInsensitive) || out_error.isEmpty()) {
            out_error.clear();
            return true;
        }
        return false;
    }
    out_secret = QString::fromUtf8(stdout_text).trimmed();
    return true;
#endif
}

bool SecretStore::write_secret(const QString& account, const QString& secret, QString& out_error) {
    out_error.clear();

    if (!is_available()) {
        out_error = availability_description();
        return false;
    }

#if defined(_WIN32)
    const QByteArray secret_bytes = secret.toUtf8();
    const std::wstring target = service_name().toStdWString() + L":" + account.toStdWString();
    std::wstring username = account.toStdWString();
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(target.c_str());
    credential.CredentialBlobSize = static_cast<DWORD>(secret_bytes.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(secret_bytes.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<LPWSTR>(username.c_str());
    if (!CredWriteW(&credential, 0)) {
        out_error = QString("Credential Manager write failed (%1).").arg(GetLastError());
        return false;
    }
    return true;
#elif defined(__APPLE__)
    QByteArray ignored;
    return run_process(
        QStandardPaths::findExecutable("security"),
        {"add-generic-password", "-U", "-a", account, "-s", service_name(), "-w", secret},
        {},
        ignored,
        out_error
    );
#else
    QByteArray ignored;
    return run_process(
        QStandardPaths::findExecutable("secret-tool"),
        {"store", "--label", "ZARA RE FRAMEWORK AI", "service", service_name(), "account", account},
        secret.toUtf8(),
        ignored,
        out_error
    );
#endif
}

bool SecretStore::delete_secret(const QString& account, QString& out_error) {
    out_error.clear();

    if (!is_available()) {
        return true;
    }

#if defined(_WIN32)
    const std::wstring target = service_name().toStdWString() + L":" + account.toStdWString();
    if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
        const DWORD error = GetLastError();
        if (error == ERROR_NOT_FOUND) {
            return true;
        }
        out_error = QString("Credential Manager delete failed (%1).").arg(error);
        return false;
    }
    return true;
#elif defined(__APPLE__)
    QByteArray ignored;
    if (!run_process(
            QStandardPaths::findExecutable("security"),
            {"delete-generic-password", "-a", account, "-s", service_name()},
            {},
            ignored,
            out_error
        )) {
        if (out_error.contains("could not be found", Qt::CaseInsensitive) ||
            out_error.contains("item could not be found", Qt::CaseInsensitive)) {
            out_error.clear();
            return true;
        }
        return false;
    }
    return true;
#else
    QByteArray ignored;
    if (!run_process(
            QStandardPaths::findExecutable("secret-tool"),
            {"clear", "service", service_name(), "account", account},
            {},
            ignored,
            out_error
        )) {
        if (out_error.isEmpty()) {
            return true;
        }
        return false;
    }
    return true;
#endif
}

}  // namespace zara::desktop_qt::app
