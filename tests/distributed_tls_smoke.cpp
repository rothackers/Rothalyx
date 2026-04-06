#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <unistd.h>
#endif

#include "zara/distributed/batch_runner.hpp"

namespace {

constexpr const char* kTestCertificate = R"(-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIUAV8nRLAFcfaD2UJf4FB+2lrnXzowDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDQwNjE3MzczNVoXDTI2MDQw
NzE3MzczNVowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAyXkoR77WXPi+3RPKMmCRKc/vjK3HK3/vWG/VUh9VvpkF
bxm4ipGmn/oq4tomDcAT4VWH5aL3QY4GIRTL5Sh7rp+d+unzFkJNFrMDEW7Uopyk
TgdOJKW44rcLhJyHd2jzyQMueXFyOW3fUZAG4VzixaYMKmq6kEEkgG+JKPXwlKCD
eKAEawzdND8YJ7UC5opzTvhWJCM7YApIcmkT8Qws1uG3m4RwSl71jIac35Y9Fwdq
rYRi335FyWIk+iRN89SEu5l8fx2funbbdPU516PPxdKLuHyS96A8C3h6INA3blXG
yRwgShxI5ehIZVV2fpzf+5F/cpu4yBx/eZzNjXuwdwIDAQABo3MwcTAaBgNVHREE
EzARhwR/AAABgglsb2NhbGhvc3QwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFDgh8h9T053z7nO7
vuz8iEORtNZHMA0GCSqGSIb3DQEBCwUAA4IBAQBwM+xzCZlVVlhNh+TVDqiY0HVb
PZnXPAazib6P1JhAf6GvGDdvqKtMjnRMfzVLJHV0vTGb0Ai9dYhJg+iUvVqMUyf0
zZC/TNtlidV5EIcQkP5BYdWCh1imGZrHyYoYyf3xHWjeKCwt/HvpYjvSqY+IhT6s
scZWySp0YloIAl89fn2FSyY4HlvDe0HfV/mDCvSUzrdS/tYzSSgt2/sEq/6pOhq4
qy/ndkSxMCL2bpS8To5OAjiUXOCUIfuIlEBVinobhsBfqpBODWjjpwE54I7SR7Hy
BvPRTTUaq4U4/aox6k+hhIotyhuka+QYj4ZfsImobWybyWqkOVP97nz1piNZ
-----END CERTIFICATE-----
)";

constexpr const char* kTestPrivateKey = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJeShHvtZc+L7d
E8oyYJEpz++Mrccrf+9Yb9VSH1W+mQVvGbiKkaaf+iri2iYNwBPhVYflovdBjgYh
FMvlKHuun5366fMWQk0WswMRbtSinKROB04kpbjitwuEnId3aPPJAy55cXI5bd9R
kAbhXOLFpgwqarqQQSSAb4ko9fCUoIN4oARrDN00PxgntQLminNO+FYkIztgCkhy
aRPxDCzW4bebhHBKXvWMhpzflj0XB2qthGLffkXJYiT6JE3z1IS7mXx/HZ+6dtt0
9TnXo8/F0ou4fJL3oDwLeHog0DduVcbJHCBKHEjl6EhlVXZ+nN/7kX9ym7jIHH95
nM2Ne7B3AgMBAAECggEAIwaar5poRwKBoAqcONTb98JsGW9utEvKDvxmQCAtdnTA
4pc8o2594ssJoKWfPv25FxAZD52c0btAqoikh+LZWbrrKp94gNKm9z7I1kOH2PtV
fzE67xkWgueiq3vQ+zv2Qeh5MGi+HGjTDal14MEWtZjP/aHPbFu+3ktFs6bKG/Ra
mHefH92DY9tMziTLW0CgeAoIz/BVRqwN6i9UNK0MOBGhpqwugb25YGsM5bxoDBBR
le4hSdrXIuVmetYIQa/XO7G3oueC5xgCa5+PhquHKwAFD+3Dgv71UBBE5yuplVe/
idCcdog8W3d6xyAizlGIhgGRBKSL4vplWu5E2gAsfQKBgQD3ADSYMMuALPCQR0vU
6f0ti3bAM2+/rQYpjfjoKmdprbwafWV4RdHHSi5y73ka3Eh07pKI3EsxCAOhOPfn
26qflPEmevm2eAn4uBiBVSlBQ4hCwY4wtge04RTDF4bKVHfBlxa9kPxfJRAB/zno
jwFGPwktJru/A4Pxy1dODKfBCwKBgQDQ0FAzFt0XB4nVfFIXwKCloo4u0dBzu+JH
zYxN+TzsqIP6eCWGlcNcp4MyLXg9K6CZ3V/DyoHp4RgzbDqyvgb67DHISl/5mnAt
VOj2hNB1iLkq+x1EQR0IHUnMPLG+aoMaM9OQ04KN5UsKeMgBU4fmGKc3OlNAf+nI
Tl8HFghJxQKBgQDgxKkXzV+CVmLbiGWzbPLdnUoFAUmxzUwMSIu3Cc9tVZIVMQND
fZW2mwTFxrIYBVlSPz/Nl1o9ViOndOXzcexEqA8Ci2nt6DJ6yVxTZSHTqBa5WNWB
8kP1D9YK6r/YIyGPY2RoQSXHlzyH9K/Ht0rbl8VL9zFmU1agk//woIePnQKBgH3d
Qqo42tU5zwQmppj4nByayhdAkuRf2LotFKgfVnDT9pFwADaKaTKdKgCB1dsRRAHa
pRGwK/ScoGjGkO8SicSPwEYZRpZ+V6WLa8zEK57c5bgZmv98PBKbDNOVthGvxAx0
Ns8yHpyHHF9YhD4AaobwT0KD3pCfSXxaeP8dcat9AoGBAJBVeGQwMz1lQ8yybZ7X
0FQ2D/rlLjT40QtsiCiQtK81PJCEg7+TxSBUFjoKP7Hxz8iwipxu672f902EepvK
mMSwHz7uYsaIcsv1prMVg/eALyb5zr/UF8lYWVeAko7Cp4x8xL5TzA2uydUWMAwJ
PtOfe0O+fk8TReR0lL+lZbJ/
-----END PRIVATE KEY-----
)";

bool write_text_file(const std::filesystem::path& path, const std::string_view text) {
    std::ofstream stream(path);
    if (!stream) {
        return false;
    }
    stream << text;
    return static_cast<bool>(stream);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: distributed_tls_smoke <fixture>\n";
        return 1;
    }

#if !defined(__linux__) && !defined(__APPLE__) && !defined(__unix__)
    std::cerr << "distributed tls smoke is unsupported on this platform\n";
    return 0;
#else
    const std::filesystem::path fixture = argv[1];
    const auto output_root = std::filesystem::temp_directory_path() / "zara_distributed_tls_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(output_root, remove_error);
    std::filesystem::create_directories(output_root, remove_error);

    const auto cert_path = output_root / "tls-cert.pem";
    const auto key_path = output_root / "tls-key.pem";
    if (!write_text_file(cert_path, kTestCertificate) || !write_text_file(key_path, kTestPrivateKey)) {
        std::cerr << "failed to write TLS fixture material\n";
        return 2;
    }

    const std::uint16_t port = static_cast<std::uint16_t>(42000 + (getpid() % 1000));
    const std::string shared_secret = "zara-tls-secret";

    zara::distributed::BatchResult controller_result;
    std::string controller_error;
    bool controller_ok = false;
    std::thread controller(
        [&]() {
            controller_ok = zara::distributed::BatchRunner::analyze_remote(
                {fixture},
                output_root / "controller",
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .expected_workers = 1,
                    .accept_timeout_ms = 4000,
                    .read_timeout_ms = 4000,
                    .heartbeat_interval_ms = 100,
                    .heartbeat_timeout_ms = 1000,
                    .shared_secret = shared_secret,
                    .allowed_platforms = {"linux"},
                    .use_tls = true,
                    .tls_certificate = cert_path,
                    .tls_private_key = key_path,
                },
                controller_result,
                controller_error
            );
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::string worker_error;
    const bool worker_ok = zara::distributed::BatchRunner::run_remote_worker(
        output_root / "worker",
        zara::distributed::RemoteOptions{
            .host = "127.0.0.1",
            .port = port,
            .shared_secret = shared_secret,
            .use_tls = true,
            .tls_ca_certificate = cert_path,
        },
        worker_error
    );

    controller.join();

    if (!controller_ok) {
        std::cerr << "TLS controller failed: " << controller_error << '\n';
        return 3;
    }
    if (!worker_ok) {
        std::cerr << "TLS worker failed: " << worker_error << '\n';
        return 4;
    }
    if (controller_result.jobs.size() != 1 || controller_result.failure_count != 0 || !controller_result.jobs.front().success) {
        std::cerr << "unexpected TLS remote batch result\n";
        return 5;
    }

    return 0;
#endif
}
