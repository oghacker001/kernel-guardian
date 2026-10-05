#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <regex>
#include <map>
#include <set>
#include <ctime>
#include <iomanip>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>

using namespace std;

// ============================================================
// KERNEL GUARDIAN
// PHASE 5 - RISK ENGINE
// ============================================================
//
// Responsibilities:
//
// 1. Read guardian_events.jsonl
// 2. Classify security events
// 3. Calculate risk scores
// 4. Detect repeated activity
// 5. Generate risk assessments
// 6. Generate security alerts
// 7. Continuously monitor new events
//
// ============================================================


// ============================================================
// CONFIGURATION
// ============================================================

static const string PROJECT_DIR =
    "/home/nishant/kernel-guardian";

static const string EVENT_LOG =
    PROJECT_DIR + "/guardian_events.jsonl";

static const string RISK_LOG =
    PROJECT_DIR + "/guardian_risk.jsonl";

static const string ALERT_LOG =
    PROJECT_DIR + "/guardian_alerts.jsonl";


// ============================================================
// SCORE CONFIGURATION
// ============================================================

static const int PROCESS_SCORE   = 20;
static const int FILE_SCORE      = 30;
static const int PRIVILEGE_SCORE = 40;
static const int NETWORK_SCORE   = 20;

static const int CRITICAL_FILE_BONUS = 30;
static const int REPEATED_SCORE      = 25;


// ============================================================
// ALERT CONFIGURATION
// ============================================================

static const int ALERT_THRESHOLD = 30;

// Prevent the same repeated event from generating
// an alert every 3 seconds.
static const int ALERT_COOLDOWN = 5;


// ============================================================
// STATISTICS
// ============================================================

struct Statistics
{
    long totalEvents = 0;

    long processEvents = 0;
    long fileEvents = 0;
    long privilegeEvents = 0;
    long networkEvents = 0;
    long otherEvents = 0;

    long lowRisk = 0;
    long mediumRisk = 0;
    long highRisk = 0;
    long criticalRisk = 0;

    long alertsGenerated = 0;
};


// ============================================================
// RISK RECORD
// ============================================================

struct RiskRecord
{
    string timestamp;
    string event;
    string action;
    string path;
    string category;

    int baseScore = 0;
    int repeatedScore = 0;
    int totalScore = 0;

    string severity;
};


// ============================================================
// CURRENT TIMESTAMP
// ============================================================

string currentTimestamp()
{
    time_t now = time(nullptr);

    tm localTime{};

    localtime_r(&now, &localTime);

    stringstream ss;

    ss << put_time(
        &localTime,
        "%Y-%m-%dT%H:%M:%S%z"
    );

    return ss.str();
}


// ============================================================
// JSON STRING ESCAPE
// ============================================================

string jsonEscape(const string& input)
{
    string output;

    for (char c : input)
    {
        switch (c)
        {
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
// JSON STRING EXTRACTION
// ============================================================

string getJsonString(
    const string& line,
    const string& key
)
{
    string pattern =
        "\"" +
        key +
        "\"\\s*:\\s*\"([^\"]*)\"";

    try
    {
        regex expression(pattern);

        smatch match;

        if (regex_search(
                line,
                match,
                expression))
        {
            return match[1];
        }
    }
    catch (...)
    {
        return "";
    }

    return "";
}


// ============================================================
// JSON INTEGER EXTRACTION
// ============================================================

int getJsonInt(
    const string& line,
    const string& key
)
{
    string pattern =
        "\"" +
        key +
        "\"\\s*:\\s*(-?[0-9]+)";

    try
    {
        regex expression(pattern);

        smatch match;

        if (regex_search(
                line,
                match,
                expression))
        {
            try
            {
                return stoi(match[1]);
            }
            catch (...)
            {
                return 0;
            }
        }
    }
    catch (...)
    {
        return 0;
    }

    return 0;
}


// ============================================================
// SEVERITY
// ============================================================

string getSeverity(int score)
{
    if (score >= 90)
        return "CRITICAL";

    if (score >= 60)
        return "HIGH";

    if (score >= 30)
        return "MEDIUM";

    return "LOW";
}


// ============================================================
// EVENT CATEGORY
// ============================================================

string detectCategory(
    const string& event,
    const string& action,
    const string& path
)
{
    // --------------------------------------------------------
    // Explicit event categories
    // --------------------------------------------------------

    if (event == "PROCESS_ACTIVITY")
        return "PROCESS";

    if (event == "FILE_INTEGRITY")
        return "FILE";

    if (event == "NETWORK_ACTIVITY")
        return "NETWORK";


    // --------------------------------------------------------
    // Privilege-related activity
    // --------------------------------------------------------

    if (action.find("PRIVILEGE") != string::npos)
        return "PRIVILEGE";

    if (action.find("ROOT") != string::npos)
        return "PRIVILEGE";

    if (action.find("SUDO") != string::npos)
        return "PRIVILEGE";

    if (action.find("UID") != string::npos)
        return "PRIVILEGE";


    // --------------------------------------------------------
    // Sensitive file activity
    // --------------------------------------------------------

    if (path == "/etc/passwd" ||
        path == "/etc/shadow" ||
        path == "/etc/sudoers" ||
        path == "/etc/group")
    {
        return "FILE";
    }

    if (path.find("/etc/ssh") == 0)
        return "FILE";

    if (path.find("/root") == 0)
        return "FILE";


    return "OTHER";
}


// ============================================================
// CATEGORY SCORE
// ============================================================

int categoryScore(
    const string& category
)
{
    if (category == "PROCESS")
        return PROCESS_SCORE;

    if (category == "FILE")
        return FILE_SCORE;

    if (category == "PRIVILEGE")
        return PRIVILEGE_SCORE;

    if (category == "NETWORK")
        return NETWORK_SCORE;

    return 0;
}


// ============================================================
// UPDATE STATISTICS
// ============================================================

void updateStatistics(
    const RiskRecord& record,
    Statistics& stats
)
{
    stats.totalEvents++;

    if (record.category == "PROCESS")
        stats.processEvents++;

    else if (record.category == "FILE")
        stats.fileEvents++;

    else if (record.category == "PRIVILEGE")
        stats.privilegeEvents++;

    else if (record.category == "NETWORK")
        stats.networkEvents++;

    else
        stats.otherEvents++;


    if (record.severity == "LOW")
        stats.lowRisk++;

    else if (record.severity == "MEDIUM")
        stats.mediumRisk++;

    else if (record.severity == "HIGH")
        stats.highRisk++;

    else if (record.severity == "CRITICAL")
        stats.criticalRisk++;
}


// ============================================================
// WRITE RISK ASSESSMENT
// ============================================================

void writeRiskRecord(
    const RiskRecord& record
)
{
    ofstream out(
        RISK_LOG,
        ios::app
    );

    if (!out)
    {
        cerr
            << "[-] Cannot open risk log: "
            << RISK_LOG
            << endl;

        return;
    }

    out
        << "{"
        << "\"timestamp\":\""
        << jsonEscape(record.timestamp)
        << "\","

        << "\"event\":\"RISK_ASSESSMENT\","

        << "\"source_event\":\""
        << jsonEscape(record.event)
        << "\","

        << "\"action\":\""
        << jsonEscape(record.action)
        << "\","

        << "\"path\":\""
        << jsonEscape(record.path)
        << "\","

        << "\"category\":\""
        << jsonEscape(record.category)
        << "\","

        << "\"base_score\":"
        << record.baseScore
        << ","

        << "\"repeated_score\":"
        << record.repeatedScore
        << ","

        << "\"risk_score\":"
        << record.totalScore
        << ","

        << "\"severity\":\""
        << record.severity
        << "\""

        << "}"
        << "\n";

    out.flush();
}


// ============================================================
// WRITE SECURITY ALERT
// ============================================================

void writeAlert(
    const RiskRecord& record,
    Statistics& stats
)
{
    if (record.totalScore < ALERT_THRESHOLD)
        return;


    ofstream out(
        ALERT_LOG,
        ios::app
    );

    if (!out)
    {
        cerr
            << "[-] Cannot open alert log: "
            << ALERT_LOG
            << endl;

        return;
    }


    out
        << "{"
        << "\"timestamp\":\""
        << jsonEscape(record.timestamp)
        << "\","

        << "\"alert\":\"RISK_ENGINE_ALERT\","

        << "\"severity\":\""
        << record.severity
        << "\","

        << "\"risk_score\":"
        << record.totalScore
        << ","

        << "\"category\":\""
        << jsonEscape(record.category)
        << "\","

        << "\"event\":\""
        << jsonEscape(record.event)
        << "\","

        << "\"action\":\""
        << jsonEscape(record.action)
        << "\","

        << "\"path\":\""
        << jsonEscape(record.path)
        << "\""

        << "}"
        << "\n";

    out.flush();

    stats.alertsGenerated++;
}


// ============================================================
// BUILD REPEAT KEY
// ============================================================

string buildRepeatKey(
    const RiskRecord& record
)
{
    return
        record.category +
        "|" +
        record.event +
        "|" +
        record.action +
        "|" +
        record.path;
}


// ============================================================
// PROCESS EVENT
// ============================================================

RiskRecord processEvent(
    const string& line,
    map<string, int>& repeatedEvents
)
{
    RiskRecord record{};


    // --------------------------------------------------------
    // Extract event information
    // --------------------------------------------------------

    record.timestamp =
        getJsonString(
            line,
            "timestamp"
        );

    record.event =
        getJsonString(
            line,
            "event"
        );

    record.action =
        getJsonString(
            line,
            "action"
        );

    record.path =
        getJsonString(
            line,
            "path"
        );


    // --------------------------------------------------------
    // Category
    // --------------------------------------------------------

    record.category =
        detectCategory(
            record.event,
            record.action,
            record.path
        );


    // --------------------------------------------------------
    // Base score
    // --------------------------------------------------------

    record.baseScore =
        categoryScore(
            record.category
        );


    // --------------------------------------------------------
    // Existing score from another monitor
    // --------------------------------------------------------

    int existingRisk =
        getJsonInt(
            line,
            "risk_score"
        );

    if (existingRisk > record.baseScore)
    {
        record.baseScore =
            existingRisk;
    }


    // --------------------------------------------------------
    // Critical file activity
    // --------------------------------------------------------

    if (record.path == "/etc/shadow" ||
        record.path == "/etc/sudoers")
    {
        record.baseScore +=
            CRITICAL_FILE_BONUS;
    }


    // --------------------------------------------------------
    // Privilege activity
    // --------------------------------------------------------

    bool privilegeActivity =
        record.action.find("PRIVILEGE") != string::npos ||
        record.action.find("SUDO") != string::npos ||
        record.action.find("ROOT") != string::npos ||
        record.action.find("UID") != string::npos;


    if (privilegeActivity)
    {
        record.baseScore +=
            PRIVILEGE_SCORE;
    }


    // --------------------------------------------------------
    // Repeated activity
    // --------------------------------------------------------

    string repeatKey =
        buildRepeatKey(record);

    repeatedEvents[repeatKey]++;


    if (repeatedEvents[repeatKey] >= 3)
    {
        record.repeatedScore =
            REPEATED_SCORE;
    }
    else
    {
        record.repeatedScore = 0;
    }


    // --------------------------------------------------------
    // Final score
    // --------------------------------------------------------

    record.totalScore =
        record.baseScore +
        record.repeatedScore;


    if (record.totalScore > 100)
        record.totalScore = 100;


    // --------------------------------------------------------
    // Severity
    // --------------------------------------------------------

    record.severity =
        getSeverity(
            record.totalScore
        );


    return record;
}


// ============================================================
// FILE SIZE
// ============================================================

long long getFileSize(
    const string& filename
)
{
    struct stat fileInfo{};

    if (stat(
            filename.c_str(),
            &fileInfo) != 0)
    {
        return 0;
    }

    return fileInfo.st_size;
}


// ============================================================
// DISPLAY HEADER
// ============================================================

void displayHeader()
{
    cout
        << "\n"
        << "============================================================\n"
        << "             KERNEL GUARDIAN - PHASE 5\n"
        << "                    RISK ENGINE\n"
        << "============================================================\n";

    cout
        << "[+] Project: "
        << PROJECT_DIR
        << "\n";

    cout
        << "[+] Event Log: "
        << EVENT_LOG
        << "\n";

    cout
        << "[+] Risk Log: "
        << RISK_LOG
        << "\n";

    cout
        << "[+] Alert Log: "
        << ALERT_LOG
        << "\n";

    cout
        << "------------------------------------------------------------\n";

    cout
        << "[+] Process score       : +20\n"
        << "[+] File score          : +30\n"
        << "[+] Privilege score     : +40\n"
        << "[+] Network score       : +20\n"
        << "[+] Repeated activity   : +25\n"
        << "[+] Critical file bonus : +30\n";

    cout
        << "------------------------------------------------------------\n";

    cout
        << "[+] LOW       : 0-29\n"
        << "[+] MEDIUM    : 30-59\n"
        << "[+] HIGH      : 60-89\n"
        << "[+] CRITICAL  : 90-100\n";

    cout
        << "============================================================\n"
        << endl;
}


// ============================================================
// DISPLAY STATISTICS
// ============================================================

void displayStatistics(
    const Statistics& stats
)
{
    cout
        << "\n"
        << "---------------- RISK ENGINE STATISTICS ----------------\n";

    cout
        << "Total events      : "
        << stats.totalEvents
        << "\n";

    cout
        << "Process events    : "
        << stats.processEvents
        << "\n";

    cout
        << "File events       : "
        << stats.fileEvents
        << "\n";

    cout
        << "Privilege events  : "
        << stats.privilegeEvents
        << "\n";

    cout
        << "Network events    : "
        << stats.networkEvents
        << "\n";

    cout
        << "Other events      : "
        << stats.otherEvents
        << "\n";

    cout
        << "--------------------------------------------------------\n";

    cout
        << "LOW               : "
        << stats.lowRisk
        << "\n";

    cout
        << "MEDIUM            : "
        << stats.mediumRisk
        << "\n";

    cout
        << "HIGH              : "
        << stats.highRisk
        << "\n";

    cout
        << "CRITICAL          : "
        << stats.criticalRisk
        << "\n";

    cout
        << "Alerts generated  : "
        << stats.alertsGenerated
        << "\n";

    cout
        << "--------------------------------------------------------\n";
}


// ============================================================
// PROCESS SINGLE LINE
// ============================================================

void handleEvent(
    const string& line,
    map<string, int>& repeatedEvents,
    set<string>& alertedKeys,
    Statistics& stats
)
{
    if (line.empty())
        return;


    RiskRecord record =
        processEvent(
            line,
            repeatedEvents
        );


    // Ignore unknown lines.
    if (record.event.empty())
        return;


    updateStatistics(
        record,
        stats
    );


    // --------------------------------------------------------
    // Always record risk assessment
    // --------------------------------------------------------

    writeRiskRecord(
        record
    );


    // --------------------------------------------------------
    // Alert handling
    //
    // For repeated activity, only generate the alert when
    // the severity reaches a meaningful level for that
    // specific event signature.
    // --------------------------------------------------------

    string alertKey =
        buildRepeatKey(record) +
        "|" +
        record.severity;


    bool shouldAlert =
        record.totalScore >= ALERT_THRESHOLD;


    if (shouldAlert)
    {
        bool alreadyAlerted =
            alertedKeys.find(alertKey)
            != alertedKeys.end();


        // For HIGH and CRITICAL events we always allow
        // the alert to be recorded.
        bool serious =
            record.severity == "HIGH" ||
            record.severity == "CRITICAL";


        if (!alreadyAlerted || serious)
        {
            writeAlert(
                record,
                stats
            );

            alertedKeys.insert(
                alertKey
            );

            cout
                << "[ALERT] "
                << record.category
                << " | "
                << record.action
                << " | score="
                << record.totalScore
                << " "
                << record.severity
                << "\n";
        }
    }


    // --------------------------------------------------------
    // Console risk output
    // --------------------------------------------------------

    cout
        << "[RISK] "
        << record.category
        << " | "
        << record.action
        << " | score="
        << record.totalScore
        << " "
        << record.severity
        << endl;
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    displayHeader();


    // ========================================================
    // VERIFY EVENT LOG
    // ========================================================

    ifstream test(
        EVENT_LOG
    );

    if (!test)
    {
        cerr
            << "[-] Event log not found:\n"
            << "    "
            << EVENT_LOG
            << "\n";

        return 1;
    }

    test.close();


    cout
        << "[+] Event log found.\n";


    // ========================================================
    // STATE
    // ========================================================

    streampos currentPosition = 0;

    map<string, int> repeatedEvents;

    set<string> alertedKeys;

    Statistics stats;


    // ========================================================
    // INITIAL FILE SIZE
    // ========================================================

    long long lastFileSize =
        getFileSize(
            EVENT_LOG
        );


    cout
        << "[+] Existing event log size: "
        << lastFileSize
        << " bytes\n";


    cout
        << "[+] Starting risk analysis...\n";


    cout
        << "[+] Monitoring new events...\n";

    cout
        << "[+] Press Ctrl+C to stop.\n\n";


    // ========================================================
    // MAIN MONITOR LOOP
    // ========================================================

    while (true)
    {
        ifstream events(
            EVENT_LOG
        );


        if (!events)
        {
            cerr
                << "[-] Unable to read event log.\n";

            sleep(3);

            continue;
        }


        // ----------------------------------------------------
        // Detect log truncation / rotation
        // ----------------------------------------------------

        long long currentFileSize =
            getFileSize(
                EVENT_LOG
            );


        if (currentFileSize <
            lastFileSize)
        {
            cout
                << "[!] Event log was truncated/rotated.\n"
                << "[+] Restarting read position.\n";

            currentPosition = 0;

            repeatedEvents.clear();

            alertedKeys.clear();
        }


        lastFileSize =
            currentFileSize;


        // ----------------------------------------------------
        // Move to last processed position
        // ----------------------------------------------------

        events.seekg(
            currentPosition
        );


        string line;


        // ----------------------------------------------------
        // Process all new lines
        // ----------------------------------------------------

        while (
            getline(
                events,
                line
            )
        )
        {
            handleEvent(
                line,
                repeatedEvents,
                alertedKeys,
                stats
            );
        }


        // ----------------------------------------------------
        // Save new position
        // ----------------------------------------------------

        streampos newPosition =
            events.tellg();


        if (newPosition !=
        static_cast<streampos>(-1))
        {
            currentPosition =
                newPosition;
        }
        else
        {
            events.clear();

            events.seekg(
                0,
                ios::end
            );

            currentPosition =
                events.tellg();
        }


        events.close();


        // ----------------------------------------------------
        // Wait before next scan
        // ----------------------------------------------------

        sleep(3);
    }


    return 0;
}
