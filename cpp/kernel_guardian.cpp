#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/file.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <regex>
#include <set>
#include <filesystem>
#include <csignal>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <ctime>

using namespace std;
namespace fs = std::filesystem;


// ============================================================
// KERNEL GUARDIAN PHASE 2
// C++ Linux Kernel Process Security Monitor
// ============================================================

static volatile sig_atomic_t running = 1;


// ============================================================
// CONFIGURATION
// ============================================================

const string PROJECT_DIR =
    "/home/nishant/kernel-guardian";
const string LOCK_FILE =
    PROJECT_DIR + "/kernel_guardian.lock";
const string TRACE_ROOT =
    "/sys/kernel/debug/tracing";

const string TRACE_FILE =
    TRACE_ROOT + "/trace_pipe";

const string FORK_ENABLE =
    TRACE_ROOT +
    "/events/sched/sched_process_fork/enable";

const string EVENTS_LOG =
    PROJECT_DIR +
    "/guardian_events.jsonl";

const string ALERTS_LOG =
    PROJECT_DIR +
    "/guardian_alerts.jsonl";

const int ALERT_THRESHOLD = 40;


// ============================================================
// SENSITIVE EXECUTABLES
// ============================================================

const set<string> SENSITIVE_EXECUTABLES = {

    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chroot",
    "/usr/bin/pkexec"
};


// ============================================================
// KNOWN SYSTEM PARENTS
// ============================================================

const set<string> KNOWN_SYSTEM_PARENTS = {

    "systemd",
    "kthreadd",
    "pool-spawner",
    "preload"
};


// ============================================================
// SIGNAL HANDLER
// ============================================================
// ------------------------------------------------------------
// Single-instance protection
// ------------------------------------------------------------

int acquire_instance_lock()
{
    int fd = open(
        LOCK_FILE.c_str(),
        O_CREAT | O_RDWR,
        0644
    );

    if (fd < 0) {
        cerr
            << "[!] Cannot create lock file: "
            << LOCK_FILE
            << endl;

        return -1;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {

        cerr
            << "[!] Kernel Guardian is already running."
            << endl;

        close(fd);

        return -1;
    }

    return fd;
}
void signal_handler(int signal)
{
    if (
        signal == SIGINT ||
        signal == SIGTERM
    ) {
        running = 0;
    }
}


// ============================================================
// JSON ESCAPE
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
                break;
        }
    }

    return output;
}


// ============================================================
// CURRENT TIMESTAMP
// ============================================================

string current_timestamp()
{
    time_t now = time(nullptr);

    struct tm tm_now {};

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
// PROCESS INFORMATION
// ============================================================

struct ProcessInfo
{
    string name = "unknown";

    string executable = "unknown";

    int pid = -1;

    int uid = -1;

    string username = "unknown";

    bool exists = false;
};


// ============================================================
// USERNAME FROM UID
// ============================================================

string username_from_uid(
    uid_t uid
)
{
    struct passwd* pw =
        getpwuid(uid);

    if (pw != nullptr) {

        return string(
            pw->pw_name
        );
    }

    return "unknown";
}


// ============================================================
// READ PROCESS INFORMATION FROM /PROC
// ============================================================

ProcessInfo get_process_info(
    int pid
)
{
    ProcessInfo info;

    info.pid = pid;

    string proc_dir =
        "/proc/" +
        to_string(pid);

    if (!fs::exists(proc_dir)) {

        return info;
    }

    info.exists = true;


    // --------------------------------------------------------
    // PROCESS NAME
    // --------------------------------------------------------

    {
        ifstream file(
            proc_dir + "/comm"
        );

        if (file) {

            getline(
                file,
                info.name
            );
        }
    }


    // --------------------------------------------------------
    // EXECUTABLE
    // --------------------------------------------------------

    {
        char buffer[4096];

        ssize_t length =
            readlink(
                (
                    proc_dir +
                    "/exe"
                ).c_str(),

                buffer,

                sizeof(buffer) - 1
            );

        if (length > 0) {

            buffer[length] =
                '\0';

            info.executable =
                string(buffer);
        }
    }


    // --------------------------------------------------------
    // UID
    // --------------------------------------------------------

    {
        ifstream file(
            proc_dir + "/status"
        );

        string line;

        while (
            getline(file, line)
        ) {

            if (
                line.rfind(
                    "Uid:",
                    0
                ) == 0
            ) {

                istringstream iss(
                    line
                );

                string label;

                int real_uid;

                iss
                    >> label
                    >> real_uid;

                info.uid =
                    real_uid;

                info.username =
                    username_from_uid(
                        real_uid
                    );

                break;
            }
        }
    }

    return info;
}


// ============================================================
// FORK EVENT
// ============================================================

struct ForkEvent
{
    string parent_name =
        "unknown";

    string child_name =
        "unknown";

    int parent_pid =
        -1;

    int child_pid =
        -1;
};


// ============================================================
// PARSE sched_process_fork
// ============================================================
//
// IMPORTANT:
//
// Your kernel provides:
//
// comm=pool-spawner pid=5088
// child_comm=pool-spawner child_pid=11098
//
// NOT:
//
// parent_comm=...
// parent_pid=...
//
// ============================================================

bool parse_fork_event(
    const string& line,
    ForkEvent& event
)
{
    event.parent_name =
        "unknown";

    event.child_name =
        "unknown";

    event.parent_pid =
        -1;

    event.child_pid =
        -1;


    // --------------------------------------------------------
    // Confirm fork event
    // --------------------------------------------------------

    if (
        line.find(
            "sched_process_fork"
        ) == string::npos
    ) {

        return false;
    }


    // --------------------------------------------------------
    // ACTUAL KERNEL FORMAT
    //
    // comm=<parent>
    // pid=<parent pid>
    // child_comm=<child>
    // child_pid=<child pid>
    // --------------------------------------------------------

    regex pattern(
        R"(comm=([^\s]+)\s+pid=(\d+)\s+child_comm=([^\s]+)\s+child_pid=(\d+))"
    );

    smatch match;


    if (
        regex_search(
            line,
            match,
            pattern
        )
    ) {

        event.parent_name =
            match[1].str();

        event.parent_pid =
            stoi(
                match[2].str()
            );

        event.child_name =
            match[3].str();

        event.child_pid =
            stoi(
                match[4].str()
            );

        return true;
    }


    // --------------------------------------------------------
    // FALLBACK PARSER
    // --------------------------------------------------------

    regex parent_name_pattern(
        R"(comm=([^\s]+))"
    );

    regex parent_pid_pattern(
        R"(\bpid=(\d+))"
    );

    regex child_name_pattern(
        R"(child_comm=([^\s]+))"
    );

    regex child_pid_pattern(
        R"(child_pid=(\d+))"
    );


    smatch m;


    if (
        regex_search(
            line,
            m,
            parent_name_pattern
        )
    ) {

        event.parent_name =
            m[1].str();
    }


    if (
        regex_search(
            line,
            m,
            parent_pid_pattern
        )
    ) {

        event.parent_pid =
            stoi(
                m[1].str()
            );
    }


    if (
        regex_search(
            line,
            m,
            child_name_pattern
        )
    ) {

        event.child_name =
            m[1].str();
    }


    if (
        regex_search(
            line,
            m,
            child_pid_pattern
        )
    ) {

        event.child_pid =
            stoi(
                m[1].str()
            );
    }


    return (
        event.child_pid > 0
    );
}


// ============================================================
// RISK RESULT
// ============================================================

struct RiskResult
{
    int score = 0;

    string level = "LOW";

    vector<string> reasons;
};


// ============================================================
// CLASSIFY RISK
// ============================================================

string classify_risk(
    int score
)
{
    if (score >= 80) {

        return "CRITICAL";
    }

    if (score >= 60) {

        return "HIGH";
    }

    if (score >= 40) {

        return "MEDIUM";
    }

    return "LOW";
}


// ============================================================
// CALCULATE RISK
// ============================================================

RiskResult calculate_risk(
    const ProcessInfo& process,
    const ForkEvent& event
)
{
    RiskResult result;


    // --------------------------------------------------------
    // ROOT EXECUTION
    // --------------------------------------------------------

    if (
        process.uid == 0
    ) {

        result.score += 20;

        result.reasons.push_back(
            "root execution"
        );
    }


    // --------------------------------------------------------
    // SENSITIVE EXECUTABLE
    // --------------------------------------------------------

    if (
        SENSITIVE_EXECUTABLES.count(
            process.executable
        )
    ) {

        result.score += 25;

        result.reasons.push_back(
            "sensitive executable"
        );
    }


    // --------------------------------------------------------
    // UNKNOWN EXECUTABLE
    // --------------------------------------------------------

    if (
        process.executable ==
        "unknown"
    ) {

        if (
            KNOWN_SYSTEM_PARENTS.count(
                event.parent_name
            ) == 0
        ) {

            result.score += 10;

            result.reasons.push_back(
                "executable unavailable"
            );
        }
    }


    // --------------------------------------------------------
    // ROOT SHELL
    // --------------------------------------------------------

    if (
        process.uid == 0 &&
        (
            process.name == "bash" ||
            process.name == "sh" ||
            process.name == "zsh"
        )
    ) {

        result.score += 15;

        result.reasons.push_back(
            "root shell"
        );
    }


    // --------------------------------------------------------
    // PRIVILEGED PROCESS CHAIN
    // --------------------------------------------------------

    if (
        event.parent_name == "sudo" &&
        process.uid == 0
    ) {

        result.score += 10;

        result.reasons.push_back(
            "privileged process chain"
        );
    }


    result.level =
        classify_risk(
            result.score
        );

    return result;
}


// ============================================================
// WRITE EVENT
// ============================================================

void write_event(
    const ForkEvent& event,
    const ProcessInfo& process,
    const RiskResult& risk
)
{
    ofstream file(
        EVENTS_LOG,
        ios::app
    );

    if (!file) {

        cerr
            << "[!] Cannot open event log: "
            << EVENTS_LOG
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


        << "\"event\":\"PROCESS_CREATED\","


        << "\"parent\":{"

        << "\"name\":\""
        << json_escape(
            event.parent_name
        )
        << "\","

        << "\"pid\":"
        << event.parent_pid

        << "},"


        << "\"child\":{"

        << "\"name\":\""
        << json_escape(

            process.name != "unknown"
                ? process.name
                : event.child_name

        )
        << "\","

        << "\"pid\":"
        << event.child_pid

        << "},"


        << "\"security\":{"

        << "\"username\":\""
        << json_escape(
            process.username
        )
        << "\","

        << "\"uid\":"
        << process.uid
        << ","

        << "\"classification\":\""

        << (
            risk.score > 0
                ? "PRIVILEGED"
                : "NORMAL"
        )

        << "\","

        << "\"risk_score\":"
        << risk.score
        << ","

        << "\"risk_level\":\""
        << risk.level
        << "\","

        << "\"reasons\":[";


    for (
        size_t i = 0;
        i < risk.reasons.size();
        ++i
    ) {

        if (i > 0) {

            file << ",";
        }

        file
            << "\""
            << json_escape(
                risk.reasons[i]
            )
            << "\"";
    }


    file
        << "]"

        << "},"

        << "\"executable\":\""
        << json_escape(
            process.executable
        )
        << "\""

        << "}"

        << "\n";
}


// ============================================================
// WRITE SECURITY ALERT
// ============================================================

void write_alert(
    const ForkEvent& event,
    const ProcessInfo& process,
    const RiskResult& risk
)
{
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


        << "\"alert\":\"SECURITY_ALERT\","


        << "\"severity\":\""
        << risk.level
        << "\","


        << "\"risk_score\":"
        << risk.score
        << ","


        << "\"event\":{"

        << "\"type\":\"PROCESS_CREATED\","

        << "\"parent\":{"

        << "\"name\":\""
        << json_escape(
            event.parent_name
        )
        << "\","

        << "\"pid\":"
        << event.parent_pid

        << "},"

        << "\"child\":{"

        << "\"name\":\""
        << json_escape(
            process.name
        )
        << "\","

        << "\"pid\":"
        << process.pid

        << "},"

        << "\"executable\":\""
        << json_escape(
            process.executable
        )
        << "\""

        << "},"


        << "\"security\":{"

        << "\"username\":\""
        << json_escape(
            process.username
        )
        << "\","

        << "\"uid\":"
        << process.uid
        << ","


        << "\"reasons\":[";


    for (
        size_t i = 0;
        i < risk.reasons.size();
        ++i
    ) {

        if (i > 0) {

            file << ",";
        }

        file
            << "\""
            << json_escape(
                risk.reasons[i]
            )
            << "\"";
    }


    file
        << "]"

        << "}"

        << "}"

        << "\n";
}


// ============================================================
// PRINT EVENT
// ============================================================

void print_event(
    const ForkEvent& event,
    const ProcessInfo& process,
    const RiskResult& risk
)
{
    cout
        << "[PROCESS CREATED] "
        << event.parent_name
        << "["
        << event.parent_pid
        << "] -> "
        << process.name
        << "["
        << process.pid
        << "]";

    cout
        << " | user="
        << process.username;

    cout
        << " | exe="
        << process.executable;

    cout
        << " | risk="
        << risk.score
        << " ("
        << risk.level
        << ")"
        << endl;


    if (
        !risk.reasons.empty()
    ) {

        cout
            << "    reasons: ";

        for (
            size_t i = 0;
            i < risk.reasons.size();
            ++i
        ) {

            if (i > 0) {

                cout << ", ";
            }

            cout
                << risk.reasons[i];
        }

        cout << endl;
    }
}


// ============================================================
// ENABLE FORK TRACE
// ============================================================

bool enable_fork_trace()
{
    ofstream file(
        FORK_ENABLE
    );

    if (!file) {

        cerr
            << "[!] Cannot enable sched_process_fork."
            << endl;

        return false;
    }

    file << "1";

    file.close();

    cout
        << "[+] Enabling sched_process_fork..."
        << endl;

    return true;
}


// ============================================================
// DISABLE FORK TRACE
// ============================================================

void disable_fork_trace()
{
    ofstream file(
        FORK_ENABLE
    );

    if (file) {

        file << "0";
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
        << "KERNEL GUARDIAN v2.1"
        << endl;

    cout
        << "Linux Kernel Process Security Monitor"
        << endl;

    cout
        << "======================================================================"
        << endl;


    cout
        << "[+] Project : "
        << PROJECT_DIR
        << endl;

    cout
        << "[+] Event Log : "
        << EVENTS_LOG
        << endl;

    cout
        << "[+] Alert Log : "
        << ALERTS_LOG
        << endl;


    // --------------------------------------------------------
    // Enable tracepoint
    // --------------------------------------------------------

    if (
        !enable_fork_trace()
    ) {

        return 1;
    }


    // --------------------------------------------------------
    // Open trace pipe
    // --------------------------------------------------------

    cout
        << "[+] Opening kernel trace pipe..."
        << endl;


    ifstream trace(
        TRACE_FILE
    );


    if (!trace) {

        cerr
            << "[!] Cannot open:"
            << endl;

        cerr
            << TRACE_FILE
            << endl;

        disable_fork_trace();

        return 1;
    }


    cout
        << "[+] Kernel trace connected."
        << endl;

    cout
        << "[+] Kernel Guardian is monitoring..."
        << endl;

    cout
        << "[+] Press Ctrl+C to stop."
        << endl;


    // --------------------------------------------------------
    // Main monitoring loop
    // --------------------------------------------------------

    string line;

    while (
        running &&
        getline(
            trace,
            line
        )
    ) {

        ForkEvent event;


        if (
            !parse_fork_event(
                line,
                event
            )
        ) {

            continue;
        }


        // ----------------------------------------------------
        // Get child process information
        // ----------------------------------------------------

        ProcessInfo process =
            get_process_info(
                event.child_pid
            );


        // ----------------------------------------------------
        // If process disappeared before /proc lookup,
        // still preserve trace information.
        // ----------------------------------------------------

        if (
            process.name == "unknown"
        ) {

            process.name =
                event.child_name;
        }


        // ----------------------------------------------------
        // Calculate security risk
        // ----------------------------------------------------

        RiskResult risk =
            calculate_risk(
                process,
                event
            );


        // ----------------------------------------------------
        // Write event
        // ----------------------------------------------------

        write_event(
            event,
            process,
            risk
        );


        // ----------------------------------------------------
        // Display event
        // ----------------------------------------------------

        print_event(
            event,
            process,
            risk
        );


        // ----------------------------------------------------
        // Generate security alert
        // ----------------------------------------------------

        if (
            risk.score >=
            ALERT_THRESHOLD
        ) {

            write_alert(
                event,
                process,
                risk
            );


            cout
                << "    [!] SECURITY ALERT GENERATED"
                << endl;
        }
    }


    // --------------------------------------------------------
    // Shutdown
    // --------------------------------------------------------

    trace.close();

    disable_fork_trace();


    cout
        << endl
        << "[+] Kernel Guardian stopped."
        << endl;


    return 0;
}
