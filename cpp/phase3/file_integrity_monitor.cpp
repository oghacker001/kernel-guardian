#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <regex>
#include <csignal>
#include <chrono>
#include <iomanip>
#include <thread>
#include <mutex>
#include <cstring>

#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include <openssl/sha.h>

using namespace std;
namespace fs = std::filesystem;

// ============================================================
// KERNEL GUARDIAN - PHASE 3
// FILE INTEGRITY MONITOR
// ============================================================

static volatile sig_atomic_t running = 1;

const string PROJECT_DIR =
    "/home/nishant/kernel-guardian";

const string EVENTS_LOG =
    PROJECT_DIR + "/guardian_events.jsonl";

const string ALERTS_LOG =
    PROJECT_DIR + "/guardian_alerts.jsonl";

const string BASELINE_FILE =
    PROJECT_DIR + "/guardian_file_baseline.jsonl";

// Critical files
const vector<string> CRITICAL_FILES = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers"
};

// Critical directories
const vector<string> CRITICAL_DIRECTORIES = {
    "/etc/ssh"
};

mutex log_mutex;

// ============================================================
// SIGNAL HANDLER
// ============================================================

void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
    }
}

// ============================================================
// JSON ESCAPE
// ============================================================

string json_escape(const string& input)
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
// TIMESTAMP
// ============================================================

string current_timestamp()
{
    auto now =
        chrono::system_clock::now();

    time_t time_now =
        chrono::system_clock::to_time_t(now);

    tm local_tm{};

    localtime_r(
        &time_now,
        &local_tm
    );

    char buffer[64];

    strftime(
        buffer,
        sizeof(buffer),
        "%Y-%m-%dT%H:%M:%S%z",
        &local_tm
    );

    return string(buffer);
}

// ============================================================
// SHA-256
// ============================================================

string sha256_file(const string& path)
{
    ifstream file(
        path,
        ios::binary
    );

    if (!file) {
        return "UNAVAILABLE";
    }

    SHA256_CTX sha256;

    SHA256_Init(&sha256);

    char buffer[8192];

    while (file.good()) {

        file.read(
            buffer,
            sizeof(buffer)
        );

        streamsize count =
            file.gcount();

        if (count > 0) {

            SHA256_Update(
                &sha256,
                buffer,
                count
            );
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Final(
        hash,
        &sha256
    );

    stringstream ss;

    for (int i = 0;
         i < SHA256_DIGEST_LENGTH;
         ++i) {

        ss
            << hex
            << setw(2)
            << setfill('0')
            << static_cast<int>(
                hash[i]
            );
    }

    return ss.str();
}

// ============================================================
// FILE METADATA
// ============================================================

struct FileMetadata
{
    bool exists = false;

    string path;

    string hash = "UNAVAILABLE";

    long long size = 0;

    mode_t permissions = 0;

    uid_t uid = 0;

    gid_t gid = 0;
};

// ============================================================
// GET FILE METADATA
// ============================================================

FileMetadata get_file_metadata(
    const string& path
)
{
    FileMetadata metadata;

    metadata.path = path;

    struct stat st{};

    if (
        stat(
            path.c_str(),
            &st
        ) != 0
    ) {
        return metadata;
    }

    metadata.exists = true;

    metadata.size =
        static_cast<long long>(
            st.st_size
        );

    metadata.permissions =
        st.st_mode & 07777;

    metadata.uid =
        st.st_uid;

    metadata.gid =
        st.st_gid;

    metadata.hash =
        sha256_file(path);

    return metadata;
}

// ============================================================
// BASELINE STORAGE
// ============================================================

map<string, FileMetadata> baseline;

// ============================================================
// LOAD BASELINE
// ============================================================

void load_baseline()
{
    ifstream file(
        BASELINE_FILE
    );

    if (!file) {
        return;
    }

    string line;

    while (getline(file, line)) {

        smatch match;

        regex pattern(
	R"REGEX("path":"([^"]+)".*"hash":"([^"]+)".*"size":([0-9]+).*"permissions":([0-9]+).*"uid":([0-9]+).*"gid":([0-9]+))REGEX"
        );

        if (
            regex_search(
                line,
                match,
                pattern
            )
        ) {

            FileMetadata metadata;

            metadata.exists = true;

            metadata.path =
                match[1].str();

            metadata.hash =
                match[2].str();

            metadata.size =
                stoll(
                    match[3].str()
                );

            metadata.permissions =
                static_cast<mode_t>(
                    stoi(
                        match[4].str()
                    )
                );

            metadata.uid =
                static_cast<uid_t>(
                    stoi(
                        match[5].str()
                    )
                );

            metadata.gid =
                static_cast<gid_t>(
                    stoi(
                        match[6].str()
                    )
                );

            baseline[
                metadata.path
            ] = metadata;
        }
    }
}

// ============================================================
// SAVE BASELINE ENTRY
// ============================================================

void save_baseline_entry(
    const FileMetadata& metadata
)
{
    ofstream file(
        BASELINE_FILE,
        ios::app
    );

    if (!file) {
        return;
    }

    file
        << "{"
        << "\"path\":\""
        << json_escape(
            metadata.path
        )
        << "\","

        << "\"hash\":\""
        << metadata.hash
        << "\","

        << "\"size\":"
        << metadata.size
        << ","

        << "\"permissions\":"
        << metadata.permissions
        << ","

        << "\"uid\":"
        << metadata.uid
        << ","

        << "\"gid\":"
        << metadata.gid

        << "}"
        << '\n';
}

// ============================================================
// UPDATE BASELINE
// ============================================================

void update_baseline(
    const FileMetadata& metadata
)
{
    baseline[
        metadata.path
    ] = metadata;

    save_baseline_entry(
        metadata
    );
}

// ============================================================
// WRITE FILE EVENT
// ============================================================

void write_file_event(
    const string& action,
    const string& path,
    const FileMetadata& metadata,
    const string& severity,
    int risk_score
)
{
    lock_guard<mutex> lock(
        log_mutex
    );

    ofstream file(
        EVENTS_LOG,
        ios::app
    );

    if (!file) {
        return;
    }

    file
        << "{"
        << "\"timestamp\":\""
        << current_timestamp()
        << "\","

        << "\"event\":\"FILE_INTEGRITY\","

        << "\"action\":\""
        << json_escape(action)
        << "\","

        << "\"path\":\""
        << json_escape(path)
        << "\","

        << "\"severity\":\""
        << severity
        << "\","

        << "\"risk_score\":"
        << risk_score
        << ","

        << "\"exists\":"
        << (metadata.exists ? "true" : "false")
        << ","

        << "\"hash\":\""
        << metadata.hash
        << "\","

        << "\"size\":"
        << metadata.size
        << ","

        << "\"permissions\":"
        << metadata.permissions

        << "}"
        << '\n';
}

// ============================================================
// WRITE SECURITY ALERT
// ============================================================

void write_alert(
    const string& action,
    const string& path,
    const FileMetadata& metadata,
    const string& reason,
    int risk_score
)
{
    lock_guard<mutex> lock(
        log_mutex
    );

    ofstream file(
        ALERTS_LOG,
        ios::app
    );

    if (!file) {
        return;
    }

    string severity;

    if (risk_score >= 80) {
        severity = "CRITICAL";
    }
    else if (risk_score >= 60) {
        severity = "HIGH";
    }
    else {
        severity = "MEDIUM";
    }

    file
        << "{"
        << "\"timestamp\":\""
        << current_timestamp()
        << "\","

        << "\"alert\":\"FILE_INTEGRITY_ALERT\","

        << "\"severity\":\""
        << severity
        << "\","

        << "\"risk_score\":"
        << risk_score
        << ","

        << "\"event\":{"

        << "\"type\":\"FILE_INTEGRITY\","

        << "\"action\":\""
        << json_escape(action)
        << "\","

        << "\"path\":\""
        << json_escape(path)
        << "\","

        << "\"reason\":\""
        << json_escape(reason)
        << "\""

        << "},"

        << "\"file\":{"

        << "\"exists\":"
        << (metadata.exists ? "true" : "false")
        << ","

        << "\"hash\":\""
        << metadata.hash
        << "\","

        << "\"permissions\":"
        << metadata.permissions

        << "}"

        << "}"
        << '\n';
}

// ============================================================
// INITIAL BASELINE
// ============================================================

void initialize_baseline()
{
    cout
        << "[+] Initializing file integrity baseline..."
        << endl;

    for (
        const string& path :
        CRITICAL_FILES
    ) {

        FileMetadata metadata =
            get_file_metadata(path);

        if (!metadata.exists) {

            cerr
                << "[!] Cannot access "
                << path
                << endl;

            continue;
        }

        baseline[path] =
            metadata;

        cout
            << "[BASELINE] "
            << path
            << endl;

        cout
            << "            SHA-256: "
            << metadata.hash
            << endl;

        cout
            << "            Permissions: "
            << oct
            << metadata.permissions
            << dec
            << endl;
    }

    // --------------------------------------------------------
    // SSH files
    // --------------------------------------------------------

    for (
        const string& directory :
        CRITICAL_DIRECTORIES
    ) {

        if (
            !fs::exists(
                directory
            )
        ) {
            continue;
        }

        for (
            const auto& entry :
            fs::recursive_directory_iterator(
                directory,
                fs::directory_options::skip_permission_denied
            )
        ) {

            if (
                !entry.is_regular_file()
            ) {
                continue;
            }

            string path =
                entry.path().string();

            FileMetadata metadata =
                get_file_metadata(path);

            if (!metadata.exists) {
                continue;
            }

            baseline[path] =
                metadata;

            cout
                << "[BASELINE] "
                << path
                << endl;
        }
    }

    // --------------------------------------------------------
    // Write baseline
    // --------------------------------------------------------

    ofstream clear_file(
        BASELINE_FILE,
        ios::trunc
    );

    clear_file.close();

    for (
        const auto& pair :
        baseline
    ) {

        save_baseline_entry(
            pair.second
        );
    }

    cout
        << "[+] Baseline initialized: "
        << baseline.size()
        << " files"
        << endl;
}

// ============================================================
// MONITOR PATH
// ============================================================

struct WatchInfo
{
    int wd = -1;

    string path;
};

map<int, WatchInfo> watches;

// ============================================================
// ADD INOTIFY WATCH
// ============================================================

void add_watch(
    int fd,
    const string& path
)
{
    uint32_t mask =
        IN_CREATE |
        IN_MODIFY |
        IN_DELETE |
        IN_MOVED_FROM |
        IN_MOVED_TO |
        IN_ATTRIB |
        IN_CLOSE_WRITE;

    int wd =
        inotify_add_watch(
            fd,
            path.c_str(),
            mask
        );

    if (wd < 0) {

        cerr
            << "[!] Cannot watch "
            << path
            << ": "
            << strerror(errno)
            << endl;

        return;
    }

    watches[wd] = {
        wd,
        path
    };

    cout
        << "[WATCH] "
        << path
        << endl;
}

// ============================================================
// ADD RECURSIVE WATCHES
// ============================================================

void add_recursive_watches(
    int fd,
    const string& directory
)
{
    add_watch(
        fd,
        directory
    );

    try {

        for (
            const auto& entry :
            fs::recursive_directory_iterator(
                directory,
                fs::directory_options::skip_permission_denied
            )
        ) {

            if (
                entry.is_directory()
            ) {

                add_watch(
                    fd,
                    entry.path().string()
                );
            }
        }

    }
    catch (...) {
        // Ignore inaccessible directories.
    }
}

// ============================================================
// EVENT ACTION
// ============================================================

string get_action(
    uint32_t mask
)
{
    if (mask & IN_CREATE)
        return "CREATE";

    if (mask & IN_MODIFY)
        return "MODIFY";

    if (mask & IN_DELETE)
        return "DELETE";

    if (mask & IN_MOVED_FROM)
        return "MOVE_FROM";

    if (mask & IN_MOVED_TO)
        return "MOVE_TO";

    if (mask & IN_ATTRIB)
        return "ATTRIBUTE_CHANGE";

    if (mask & IN_CLOSE_WRITE)
        return "WRITE_COMPLETE";

    return "UNKNOWN";
}

// ============================================================
// RISK SCORE
// ============================================================

int calculate_file_risk(
    const string& path,
    const string& action
)
{
    int score = 50;

    if (
        path == "/etc/shadow"
    ) {
        score += 30;
    }

    else if (
        path == "/etc/sudoers"
    ) {
        score += 25;
    }

    else if (
        path == "/etc/passwd"
    ) {
        score += 20;
    }

    else if (
        path.find("/etc/ssh/") == 0
    ) {
        score += 20;
    }

    if (
        action == "DELETE" ||
        action == "MOVE_FROM"
    ) {
        score += 15;
    }

    if (
        action == "ATTRIBUTE_CHANGE"
    ) {
        score += 10;
    }

    if (score > 100)
        score = 100;

    return score;
}

// ============================================================
// PROCESS FILE CHANGE
// ============================================================

void process_file_change(
    const string& path,
    const string& action
)
{
    FileMetadata current =
        get_file_metadata(path);

    int risk_score =
        calculate_file_risk(
            path,
            action
        );

    string reason =
        "critical file modification";

    // --------------------------------------------------------
    // Compare SHA-256
    // --------------------------------------------------------

    auto previous =
        baseline.find(path);

    if (
        previous != baseline.end() &&
        current.exists &&
        previous->second.hash != current.hash
    ) {

        reason =
            "SHA-256 integrity mismatch";

        risk_score += 10;

        if (risk_score > 100)
            risk_score = 100;
    }

    // --------------------------------------------------------
    // Log event
    // --------------------------------------------------------

    string severity =
        risk_score >= 80
            ? "CRITICAL"
            : risk_score >= 60
                ? "HIGH"
                : "MEDIUM";

    write_file_event(
        action,
        path,
        current,
        severity,
        risk_score
    );

    // --------------------------------------------------------
    // Security alert
    // --------------------------------------------------------

    write_alert(
        action,
        path,
        current,
        reason,
        risk_score
    );

    cout
        << "[FILE ALERT] "
        << action
        << " | "
        << path
        << " | risk="
        << risk_score
        << endl;

    // --------------------------------------------------------
    // Update baseline if file still exists
    // --------------------------------------------------------

    if (current.exists) {

        update_baseline(
            current
        );
    }
    else {

        baseline.erase(
            path
        );
    }
}

// ============================================================
// MAIN
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
        << "KERNEL GUARDIAN PHASE 3"
        << endl;

    cout
        << "File Integrity Monitoring"
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

    // --------------------------------------------------------
    // Load previous baseline
    // --------------------------------------------------------

    load_baseline();

    // --------------------------------------------------------
    // First run = initialize baseline
    // --------------------------------------------------------

    if (
        baseline.empty()
    ) {

        initialize_baseline();
    }

    else {

        cout
            << "[+] Existing baseline loaded: "
            << baseline.size()
            << " files"
            << endl;
    }

    // --------------------------------------------------------
    // Create inotify
    // --------------------------------------------------------

    int fd =
        inotify_init1(
            0
        );

    if (fd < 0) {

        cerr
            << "[!] Cannot initialize inotify: "
            << strerror(errno)
            << endl;

        return 1;
    }

    // --------------------------------------------------------
    // Watch critical files
    // --------------------------------------------------------

    for (
        const string& file :
        CRITICAL_FILES
    ) {

        if (
            fs::exists(file)
        ) {

            add_watch(
                fd,
                file
            );
        }
    }

    // --------------------------------------------------------
    // Watch SSH directory
    // --------------------------------------------------------

    for (
        const string& directory :
        CRITICAL_DIRECTORIES
    ) {

        if (
            fs::exists(directory)
        ) {

            add_recursive_watches(
                fd,
                directory
            );
        }
    }

    cout
        << "[+] Phase 3 file monitoring ACTIVE"
        << endl;

    cout
        << "[+] Monitoring critical Linux security files..."
        << endl;

    // --------------------------------------------------------
    // Event buffer
    // --------------------------------------------------------

    const size_t BUFFER_SIZE =
        64 * 1024;

    vector<char> buffer(
        BUFFER_SIZE
    );

    // --------------------------------------------------------
    // Monitoring loop
    // --------------------------------------------------------

    while (running) {

        int length =
            read(
                fd,
                buffer.data(),
                buffer.size()
            );

        if (length < 0) {

            if (errno == EINTR) {
                continue;
            }

            cerr
                << "[!] inotify read error: "
                << strerror(errno)
                << endl;

            break;
        }

        int offset = 0;

        while (
            offset < length
        ) {

            struct inotify_event* event =
                reinterpret_cast<
                    struct inotify_event*
                >(
                    buffer.data() + offset
                );

            auto watch =
                watches.find(
                    event->wd
                );

            if (
                watch == watches.end()
            ) {

                offset +=
                    sizeof(
                        struct inotify_event
                    ) +
                    event->len;

                continue;
            }

            string base_path =
                watch->second.path;

            string path =
                base_path;

            if (
                event->len > 0
            ) {

                if (
                    fs::is_directory(
                        base_path
                    )
                ) {

                    path =
                        base_path +
                        "/" +
                        string(
                            event->name
                        );
                }
            }

            string action =
                get_action(
                    event->mask
                );

            // ------------------------------------------------
            // Ignore temporary noise
            // ------------------------------------------------

            if (
                event->mask &
                IN_ISDIR
            ) {

                // New directory inside SSH
                // gets monitored.

                if (
                    event->mask &
                    IN_CREATE
                ) {

                    if (
                        fs::exists(path) &&
                        fs::is_directory(path)
                    ) {

                        add_recursive_watches(
                            fd,
                            path
                        );
                    }
                }

                offset +=
                    sizeof(
                        struct inotify_event
                    ) +
                    event->len;

                continue;
            }

            // ------------------------------------------------
            // Process critical file event
            // ------------------------------------------------

            process_file_change(
                path,
                action
            );

            offset +=
                sizeof(
                    struct inotify_event
                ) +
                event->len;
        }
    }

    close(fd);

    cout
        << "[+] Phase 3 stopped."
        << endl;

    return 0;
}
