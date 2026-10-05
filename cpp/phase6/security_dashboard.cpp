#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <regex>
#include <map>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <unistd.h>

using namespace std;

// ============================================================
// KERNEL GUARDIAN - PHASE 6
// Unified Security Dashboard
// ============================================================

static const string PROJECT_DIR =
    "/home/nishant/kernel-guardian";

static const string EVENT_LOG =
    PROJECT_DIR + "/guardian_events.jsonl";

static const string ALERT_LOG =
    PROJECT_DIR + "/guardian_alerts.jsonl";

static const string RISK_LOG =
    PROJECT_DIR + "/guardian_risk.jsonl";


// ============================================================
// HELPERS
// ============================================================

string getJsonString(const string& line, const string& key)
{
    string pattern =
        "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";

    regex r(pattern);
    smatch match;

    if (regex_search(line, match, r))
        return match[1];

    return "";
}


int getJsonInt(const string& line, const string& key)
{
    string pattern =
        "\"" + key + "\"\\s*:\\s*(-?[0-9]+)";

    regex r(pattern);
    smatch match;

    if (regex_search(line, match, r))
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

    return 0;
}


long countLines(const string& file)
{
    ifstream input(file);

    if (!input)
        return 0;

    long count = 0;
    string line;

    while (getline(input, line))
        count++;

    return count;
}


// ============================================================
// COMPONENT STATUS
// ============================================================

bool processRunning(const string& process)
{
    // Linux limits /proc/<pid>/comm to 15 characters.
    // guardian_network is longer than 15 characters, so
    // pgrep -x cannot match it directly.

    string command =
        "pgrep -f \"(^|/)"+ process +"( |$)\" > /dev/null 2>&1";

    return system(command.c_str()) == 0;
}


void printComponentStatus(
    const string& name,
    const string& process,
    const string& executable)
{
    bool running = processRunning(process);

    cout << left
         << setw(25)
         << name
         << " : ";

    if (running)
        cout << "RUNNING";
    else
        cout << "NOT RUNNING";

    cout << " | " << executable << "\n";
}


// ============================================================
// RISK STATISTICS
// ============================================================

struct Statistics
{
    long total = 0;

    long low = 0;
    long medium = 0;
    long high = 0;
    long critical = 0;

    long process = 0;
    long file = 0;
    long network = 0;
    long privilege = 0;
    long other = 0;

    int highestRisk = 0;
};


void analyzeRiskLog(Statistics& stats)
{
    ifstream input(RISK_LOG);

    if (!input)
        return;

    string line;

    while (getline(input, line))
    {
        if (line.empty())
            continue;

        stats.total++;

        string severity =
            getJsonString(line, "severity");

        string category =
            getJsonString(line, "category");

        int score =
            getJsonInt(line, "risk_score");

        if (score > stats.highestRisk)
            stats.highestRisk = score;

        if (severity == "LOW")
            stats.low++;

        else if (severity == "MEDIUM")
            stats.medium++;

        else if (severity == "HIGH")
            stats.high++;

        else if (severity == "CRITICAL")
            stats.critical++;

        if (category == "PROCESS")
            stats.process++;

        else if (category == "FILE")
            stats.file++;

        else if (category == "NETWORK")
            stats.network++;

        else if (category == "PRIVILEGE")
            stats.privilege++;

        else
            stats.other++;
    }
}


// ============================================================
// RECENT CRITICAL ALERTS
// ============================================================

void showRecentCriticalAlerts(int limit)
{
    ifstream input(ALERT_LOG);

    if (!input)
    {
        cout << "[!] Alert log unavailable.\n";
        return;
    }

    vector<string> critical;

    string line;

    while (getline(input, line))
    {
        if (line.find("\"severity\":\"CRITICAL\"") !=
            string::npos)
        {
            critical.push_back(line);
        }
    }

    cout << "\n===== RECENT CRITICAL ALERTS =====\n";

    if (critical.empty())
    {
        cout << "No critical alerts found.\n";
        return;
    }

    int start =
        max(
            0,
            static_cast<int>(critical.size()) - limit
        );

    for (int i = start;
         i < static_cast<int>(critical.size());
         i++)
    {
        string timestamp =
            getJsonString(
                critical[i],
                "timestamp"
            );

        string category =
            getJsonString(
                critical[i],
                "category"
            );

        string action =
            getJsonString(
                critical[i],
                "action"
            );

        string path =
            getJsonString(
                critical[i],
                "path"
            );

        int score =
            getJsonInt(
                critical[i],
                "risk_score"
            );

        cout
            << "[" << timestamp << "] "
            << category
            << " | "
            << action
            << " | score="
            << score;

        if (!path.empty())
            cout << " | " << path;

        cout << "\n";
    }
}


// ============================================================
// DASHBOARD
// ============================================================

void printDashboard()
{
    Statistics stats;

    analyzeRiskLog(stats);

    long eventCount =
        countLines(EVENT_LOG);

    long alertCount =
        countLines(ALERT_LOG);

    long riskCount =
        countLines(RISK_LOG);

    cout << "\033[2J\033[H";

    cout
        << "======================================================================\n"
        << "                    KERNEL GUARDIAN v2.1\n"
        << "                 UNIFIED SECURITY DASHBOARD\n"
        << "======================================================================\n\n";

    cout
        << "PROJECT\n"
        << "----------------------------------------------------------------------\n"
        << "Directory : "
        << PROJECT_DIR
        << "\n\n";

    cout
        << "COMPONENT STATUS\n"
        << "----------------------------------------------------------------------\n";

    printComponentStatus(
        "Process Monitor",
        "kernel_guardian",
        "kernel_guardian"
    );

    printComponentStatus(
        "File Integrity",
        "guardian_fim",
        "guardian_fim"
    );

    printComponentStatus(
        "Network Monitor",
        "guardian_network",
        "guardian_network"
    );

    printComponentStatus(
        "Risk Engine",
        "guardian_risk",
        "guardian_risk"
    );

    cout << "\n";

    cout
        << "LOG STATISTICS\n"
        << "----------------------------------------------------------------------\n";

    cout
        << "Kernel events       : "
        << eventCount << "\n";

    cout
        << "Security alerts     : "
        << alertCount << "\n";

    cout
        << "Risk assessments    : "
        << riskCount << "\n";

    cout << "\n";

    cout
        << "RISK SEVERITY DISTRIBUTION\n"
        << "----------------------------------------------------------------------\n";

    cout
        << "LOW                 : "
        << stats.low << "\n";

    cout
        << "MEDIUM              : "
        << stats.medium << "\n";

    cout
        << "HIGH                : "
        << stats.high << "\n";

    cout
        << "CRITICAL            : "
        << stats.critical << "\n";

    cout
        << "Highest risk score  : "
        << stats.highestRisk << "\n";

    cout << "\n";

    cout
        << "RISK CATEGORY DISTRIBUTION\n"
        << "----------------------------------------------------------------------\n";

    cout
        << "PROCESS             : "
        << stats.process << "\n";

    cout
        << "FILE                : "
        << stats.file << "\n";

    cout
        << "NETWORK             : "
        << stats.network << "\n";

    cout
        << "PRIVILEGE           : "
        << stats.privilege << "\n";

    cout
        << "OTHER               : "
        << stats.other << "\n";

    cout << "\n";

    showRecentCriticalAlerts(10);

    cout << "\n";

    cout
        << "======================================================================\n"
        << "Dashboard refresh: 5 seconds\n"
        << "Press Ctrl+C to exit.\n"
        << "======================================================================\n";
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    cout
        << "Starting Kernel Guardian Phase 6...\n";

    while (true)
    {
        printDashboard();

        sleep(5);
    }

    return 0;
}
