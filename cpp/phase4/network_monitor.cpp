#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

// ============================================================
// KERNEL GUARDIAN PHASE 4
// NETWORK SECURITY MONITOR
// ============================================================

static volatile sig_atomic_t running = 1;

const string PROJECT_DIR =
    "/home/nishant/kernel-guardian";

const string EVENTS_LOG =
    PROJECT_DIR + "/guardian_events.jsonl";

const string ALERTS_LOG =
    PROJECT_DIR + "/guardian_alerts.jsonl";

const string PROC_TCP =
    "/proc/net/tcp";

const string PROC_TCP6 =
    "/proc/net/tcp6";

const string PROC_UDP =
    "/proc/net/udp";

const string PROC_UDP6 =
    "/proc/net/udp6";

// Scan interval
const int SCAN_INTERVAL_SECONDS = 3;

// Risk thresholds
const int MEDIUM_THRESHOLD = 40;
const int HIGH_THRESHOLD = 60;
const int CRITICAL_THRESHOLD = 80;

// ============================================================
// Known safe local ports
// ============================================================

const map<int, string> KNOWN_PORTS = {

    {22, "SSH"},
    {53, "DNS"},
    {68, "DHCP"},
    {80, "HTTP"},
    {123, "NTP"},
    {443, "HTTPS"},
    {631, "CUPS"},
    {3306, "MySQL"},
    {33060, "MySQL-X"},
    {5353, "mDNS"}

};

// ============================================================
// Signal handler
// ============================================================

void signal_handler(int signal)
{
    if (signal == SIGINT || signal == SIGTERM) {
        running = 0;
    }
}

// ============================================================
// Timestamp
// ============================================================

string current_timestamp()
{
    time_t now = time(nullptr);

    struct tm tm_now;

    localtime_r(
        &now,
        &tm_now
    );

    char buffer[64];

    strftime(
        buffer,
        sizeof(buffer),
        "%Y-%m-%dT%H:%M:%S%z",
        &tm_now
    );

    return string(buffer);
}

// ============================================================
// JSON escape
// ============================================================

string json_escape(
    const string& input
)
{
    string output;

    for (char c : input) {

        switch (c) {

            case '"':
                output += "\\\"";
                break;

            case '\\':
                output += "\\\\";
                break;

            case '\n':
                output += "\\n";
                break;

            case '\r':
                output += "\\r";
                break;

            case '\t':
                output += "\\t";
                break;

            default:
                output += c;
        }
    }

    return output;
}

// ============================================================
// Network connection
// ============================================================

struct NetworkConnection
{
    string protocol = "UNKNOWN";

    string local_address = "unknown";

    int local_port = 0;

    string remote_address = "unknown";

    int remote_port = 0;

    string state = "UNKNOWN";

    int uid = -1;

    int risk_score = 0;

    string severity = "LOW";

    bool listening = false;
};

// ============================================================
// Convert hexadecimal IPv4 address
// ============================================================

string hex_ipv4_to_string(
    const string& hex
)
{
    if (hex.size() != 8) {
        return "unknown";
    }

    unsigned long value = 0;

    try {

        value = stoul(
            hex,
            nullptr,
            16
        );

    }
    catch (...) {

        return "unknown";
    }

    struct in_addr addr;

    addr.s_addr = htonl(value);

    char buffer[INET_ADDRSTRLEN];

    if (
        inet_ntop(
            AF_INET,
            &addr,
            buffer,
            sizeof(buffer)
        ) == nullptr
    ) {

        return "unknown";
    }

    return string(buffer);
}

// ============================================================
// Convert hexadecimal IPv6 address
// ============================================================

string hex_ipv6_to_string(
    const string& hex
)
{
    if (hex.size() != 32) {
        return "unknown";
    }

    unsigned char bytes[16];

    for (int i = 0; i < 16; ++i) {

        string byte_string =
            hex.substr(
                i * 2,
                2
            );

        try {

            bytes[i] =
                static_cast<unsigned char>(
                    stoul(
                        byte_string,
                        nullptr,
                        16
                    )
                );

        }
        catch (...) {

            return "unknown";
        }
    }

    char buffer[INET6_ADDRSTRLEN];

    if (
        inet_ntop(
            AF_INET6,
            bytes,
            buffer,
            sizeof(buffer)
        ) == nullptr
    ) {

        return "unknown";
    }

    return string(buffer);
}

// ============================================================
// Parse address
// ============================================================

bool parse_address(
    const string& value,
    bool ipv6,
    string& address,
    int& port
)
{
    size_t colon =
        value.find(':');

    if (colon == string::npos) {
        return false;
    }

    string hex_address =
        value.substr(
            0,
            colon
        );

    string hex_port =
        value.substr(
            colon + 1
        );

    try {

        port =
            stoi(
                hex_port,
                nullptr,
                16
            );

    }
    catch (...) {

        return false;
    }

    if (ipv6) {

        address =
            hex_ipv6_to_string(
                hex_address
            );

    }
    else {

        address =
            hex_ipv4_to_string(
                hex_address
            );
    }

    return true;
}

// ============================================================
// Risk classification
// ============================================================

string classify_risk(
    int score
)
{
    if (score >= CRITICAL_THRESHOLD) {
        return "CRITICAL";
    }

    if (score >= HIGH_THRESHOLD) {
        return "HIGH";
    }

    if (score >= MEDIUM_THRESHOLD) {
        return "MEDIUM";
    }

    return "LOW";
}

// ============================================================
// Calculate network risk
// ============================================================

void calculate_network_risk(
    NetworkConnection& connection
)
{
    int score = 0;

    // --------------------------------------------------------
    // Listening service
    // --------------------------------------------------------

    if (connection.listening) {

        score += 5;
    }

    // --------------------------------------------------------
    // Unknown listening port
    // --------------------------------------------------------

    if (
        connection.listening &&
        KNOWN_PORTS.find(
            connection.local_port
        ) == KNOWN_PORTS.end()
    ) {

        score += 35;
    }

    // --------------------------------------------------------
    // SSH
    // --------------------------------------------------------

    if (
        connection.local_port == 22
    ) {

        score += 10;
    }

    // --------------------------------------------------------
    // Database services
    // --------------------------------------------------------

    if (
        connection.local_port == 3306 ||
        connection.local_port == 33060
    ) {

        score += 10;
    }

    // --------------------------------------------------------
    // Public listening address
    // --------------------------------------------------------

    if (
        connection.listening &&
        connection.local_address != "127.0.0.1" &&
        connection.local_address != "0.0.0.0" &&
        connection.local_address != "::1" &&
        connection.local_address != "::"
    ) {

        score += 20;
    }

    // --------------------------------------------------------
    // Remote connection
    // --------------------------------------------------------

    if (
        connection.remote_port > 0
    ) {

        score += 5;
    }

    // --------------------------------------------------------
    // Established connection
    // TCP state 01 = ESTABLISHED
    // --------------------------------------------------------

    if (
        connection.state == "01"
    ) {

        score += 5;
    }

    connection.risk_score =
        score;

    connection.severity =
        classify_risk(score);
}

// ============================================================
// Parse /proc/net files
// ============================================================

vector<NetworkConnection> parse_proc_file(
    const string& filename,
    const string& protocol,
    bool ipv6
)
{
    vector<NetworkConnection> connections;

    ifstream file(filename);

    if (!file) {
        return connections;
    }

    string line;

    // Skip header
    getline(
        file,
        line
    );

    while (
        getline(
            file,
            line
        )
    ) {

        if (line.empty()) {
            continue;
        }

        istringstream iss(line);

        string sl;
        string local;
        string remote;
        string state;
        string tx_rx;
        string tr;
        string tm_when;
        string retrnsmt;
        string uid;
        string timeout;
        string inode;

        iss
            >> sl
            >> local
            >> remote
            >> state
            >> tx_rx
            >> tr
            >> tm_when
            >> retrnsmt
            >> uid
            >> timeout
            >> inode;

        if (
            local.empty() ||
            remote.empty()
        ) {

            continue;
        }

        NetworkConnection connection;

        connection.protocol =
            protocol;

        connection.state =
            state;

        try {

            connection.uid =
                stoi(uid);

        }
        catch (...) {

            connection.uid = -1;
        }

        if (
            !parse_address(
                local,
                ipv6,
                connection.local_address,
                connection.local_port
            )
        ) {

            continue;
        }

        if (
            !parse_address(
                remote,
                ipv6,
                connection.remote_address,
                connection.remote_port
            )
        ) {

            continue;
        }

        // TCP LISTEN = 0A
        connection.listening =
            (
                state == "0A"
            );

        calculate_network_risk(
            connection
        );

        connections.push_back(
            connection
        );
    }

    return connections;
}

// ============================================================
// Read all network connections
// ============================================================

vector<NetworkConnection> get_connections()
{
    vector<NetworkConnection> result;

    vector<NetworkConnection> tcp =
        parse_proc_file(
            PROC_TCP,
            "TCP",
            false
        );

    vector<NetworkConnection> tcp6 =
        parse_proc_file(
            PROC_TCP6,
            "TCP6",
            true
        );

    vector<NetworkConnection> udp =
        parse_proc_file(
            PROC_UDP,
            "UDP",
            false
        );

    vector<NetworkConnection> udp6 =
        parse_proc_file(
            PROC_UDP6,
            "UDP6",
            true
        );

    result.insert(
        result.end(),
        tcp.begin(),
        tcp.end()
    );

    result.insert(
        result.end(),
        tcp6.begin(),
        tcp6.end()
    );

    result.insert(
        result.end(),
        udp.begin(),
        udp.end()
    );

    result.insert(
        result.end(),
        udp6.begin(),
        udp6.end()
    );

    return result;
}

// ============================================================
// Write network event
// ============================================================

void write_network_event(
    const NetworkConnection& connection
)
{
    ofstream file(
        EVENTS_LOG,
        ios::app
    );

    if (!file) {

        cerr
            << "[!] Cannot open event log."
            << endl;

        return;
    }

    file
        << "{"
        << "\"timestamp\":\""
        << json_escape(
            current_timestamp()
        )
        << "\","

        << "\"event\":\"NETWORK_ACTIVITY\","

        << "\"action\":\"CONNECTION_DETECTED\","

        << "\"protocol\":\""
        << connection.protocol
        << "\","

        << "\"local_address\":\""
        << json_escape(
            connection.local_address
        )
        << "\","

        << "\"local_port\":"
        << connection.local_port
        << ","

        << "\"remote_address\":\""
        << json_escape(
            connection.remote_address
        )
        << "\","

        << "\"remote_port\":"
        << connection.remote_port
        << ","

        << "\"state\":\""
        << connection.state
        << "\","

        << "\"uid\":"
        << connection.uid
        << ","

        << "\"risk_score\":"
        << connection.risk_score
        << ","

        << "\"severity\":\""
        << connection.severity
        << "\""

        << "}"
        << "\n";
}

// ============================================================
// Write security alert
// ============================================================

void write_network_alert(
    const NetworkConnection& connection
)
{
    // Only create alerts for medium+
    if (
        connection.risk_score <
        MEDIUM_THRESHOLD
    ) {

        return;
    }

    ofstream file(
        ALERTS_LOG,
        ios::app
    );

    if (!file) {

        cerr
            << "[!] Cannot open alert log."
            << endl;

        return;
    }

    file
        << "{"
        << "\"timestamp\":\""
        << json_escape(
            current_timestamp()
        )
        << "\","

        << "\"alert\":\"NETWORK_SECURITY_ALERT\","

        << "\"severity\":\""
        << connection.severity
        << "\","

        << "\"risk_score\":"
        << connection.risk_score
        << ","

        << "\"event\":{"

        << "\"type\":\"NETWORK_ACTIVITY\","

        << "\"protocol\":\""
        << connection.protocol
        << "\","

        << "\"local_address\":\""
        << json_escape(
            connection.local_address
        )
        << "\","

        << "\"local_port\":"
        << connection.local_port
        << ","

        << "\"remote_address\":\""
        << json_escape(
            connection.remote_address
        )
        << "\","

        << "\"remote_port\":"
        << connection.remote_port
        << ","

        << "\"state\":\""
        << connection.state
        << "\""

        << "}"

        << "}"
        << "\n";
}

// ============================================================
// Connection key
// ============================================================

string connection_key(
    const NetworkConnection& connection
)
{
    return
        connection.protocol
        + "|" +
        connection.local_address
        + "|" +
        to_string(
            connection.local_port
        )
        + "|" +
        connection.remote_address
        + "|" +
        to_string(
            connection.remote_port
        )
        + "|" +
        connection.state;
}

// ============================================================
// Print connection
// ============================================================

void print_connection(
    const NetworkConnection& connection
)
{
    cout
        << "[NETWORK] "
        << connection.protocol
        << " "
        << connection.local_address
        << ":"
        << connection.local_port
        << " -> "
        << connection.remote_address
        << ":"
        << connection.remote_port
        << " state="
        << connection.state
        << " risk="
        << connection.risk_score
        << " "
        << connection.severity
        << endl;
}

// ============================================================
// Main
// ============================================================

int main()
{
    signal(
        SIGINT,
        signal_handler
    );

    signal(
        SIGTERM,
        signal_handler
    );

    cout
        << "======================================================================"
        << endl;

    cout
        << "KERNEL GUARDIAN PHASE 4"
        << endl;

    cout
        << "Network Security Monitor"
        << endl;

    cout
        << "======================================================================"
        << endl;

    cout
        << "[+] Project: "
        << PROJECT_DIR
        << endl;

    cout
        << "[+] Event Log: "
        << EVENTS_LOG
        << endl;

    cout
        << "[+] Alert Log: "
        << ALERTS_LOG
        << endl;

    cout
        << "[+] Scan interval: "
        << SCAN_INTERVAL_SECONDS
        << " seconds"
        << endl;

    cout
        << "[+] Reading Linux /proc network tables..."
        << endl;

    map<string, NetworkConnection> known_connections;

    // --------------------------------------------------------
    // Initial scan
    // --------------------------------------------------------

    vector<NetworkConnection> initial =
        get_connections();

    cout
        << "[+] Initial connections detected: "
        << initial.size()
        << endl;

    for (
        const auto& connection :
        initial
    ) {

        print_connection(
            connection
        );

        string key =
            connection_key(
                connection
            );

        known_connections[key] =
            connection;
    }

    cout
        << "[+] Phase 4 network monitoring ACTIVE"
        << endl;

    cout
        << "[+] Press Ctrl+C to stop."
        << endl;

    // --------------------------------------------------------
    // Monitoring loop
    // --------------------------------------------------------

    while (running) {

        vector<NetworkConnection> current =
            get_connections();

        map<string, NetworkConnection>
            current_map;

        for (
            const auto& connection :
            current
        ) {

            string key =
                connection_key(
                    connection
                );

            current_map[key] =
                connection;

            // ------------------------------------------------
            // New connection
            // ------------------------------------------------

            if (
                known_connections.find(
                    key
                ) ==
                known_connections.end()
            ) {

                print_connection(
                    connection
                );

                write_network_event(
                    connection
                );

                write_network_alert(
                    connection
                );
            }
        }

        known_connections =
            current_map;

        for (
            int i = 0;
            i < SCAN_INTERVAL_SECONDS;
            ++i
        ) {

            if (!running) {
                break;
            }

            sleep(1);
        }
    }

    cout
        << endl
        << "[+] Phase 4 network monitoring stopped."
        << endl;

    return 0;
}
