#!/var/ossec/framework/python/bin/python3
# SOCFortress
# https://www.socfortress.co
# info@socfortress.co
#
# Wazuh integration: enrich alerts that carry data.srcip with AbuseIPDB
# reputation and send the result back to the manager as an "abuseipdb" event
# (matched by rule 100651).
#
# Called by wazuh-integratord as:
#   custom-abuseipdb <alert_file> <api_key> <hook_url> [debug]
#
# The API key is never written to integrations.log.
import json
import os
import sys
import time
from socket import AF_UNIX, SOCK_DGRAM, socket

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = "{0}/logs/integrations.log".format(pwd)
socket_addr = "{0}/queue/sockets/queue".format(pwd)


def main(args):
    debug("# Starting")
    alert_file_location = args[1]
    apikey = args[2]
    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Request AbuseIPDB info
    msg = request_abuseipdb_info(json_alert, apikey)

    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(log_file, "a") as f:
            f.write(msg)


def collect(data):
    return (
        data["abuseConfidenceScore"],
        data["countryCode"],
        data["usageType"],
        data["isp"],
        data["domain"],
        data["totalReports"],
        data["lastReportedAt"],
    )


def in_database(data):
    return data["totalReports"] != 0


def query_api(srcip, apikey):
    params = {"maxAgeInDays": "90", "ipAddress": srcip}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Accept": "application/json",
        "Key": apikey,
    }
    response = requests.get("https://api.abuseipdb.com/api/v2/check", params=params, headers=headers, timeout=30)
    if response.status_code == 200:
        return response.json()["data"]

    alert_output = {"abuseipdb": {}, "integration": "custom-abuseipdb"}
    debug("# Error: The AbuseIPDB encountered an error")
    alert_output["abuseipdb"]["error"] = response.status_code
    try:
        alert_output["abuseipdb"]["description"] = response.json()["errors"][0]["detail"]
    except Exception:
        alert_output["abuseipdb"]["description"] = response.text[:200]
    send_event(alert_output)
    sys.exit(0)


def request_abuseipdb_info(alert, apikey):
    # If there is no source ip address present in the alert. Exit.
    if "srcip" not in alert.get("data", {}):
        return 0

    srcip = alert["data"]["srcip"]
    data = query_api(srcip, apikey)

    alert_output = {
        "integration": "custom-abuseipdb",
        "abuseipdb": {
            "found": 0,
            "source": {
                "alert_id": alert["id"],
                "rule": alert["rule"]["id"],
                "description": alert["rule"]["description"],
                "full_log": alert.get("full_log", ""),
                "srcip": srcip,
            },
        },
    }

    # Info about the IP found in AbuseIPDB
    if in_database(data):
        alert_output["abuseipdb"]["found"] = 1
        (score, country_code, usage_type, isp, domain, total_reports, last_reported_at) = collect(data)
        alert_output["abuseipdb"]["abuse_confidence_score"] = score
        alert_output["abuseipdb"]["country_code"] = country_code
        alert_output["abuseipdb"]["usage_type"] = usage_type
        alert_output["abuseipdb"]["isp"] = isp
        alert_output["abuseipdb"]["domain"] = domain
        alert_output["abuseipdb"]["total_reports"] = total_reports
        alert_output["abuseipdb"]["last_reported_at"] = last_reported_at

    debug(alert_output)
    return alert_output


def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:abuseipdb:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->abuseipdb:{3}".format(
            agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg)
        )
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


if __name__ == "__main__":
    try:
        bad_arguments = False
        if len(sys.argv) >= 4:
            # argv[2] is the API key: log a placeholder, never the key itself
            msg = "{0} {1} {2} {3} {4}".format(
                now, sys.argv[1], "<api_key>", sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ""
            )
            debug_enabled = len(sys.argv) > 4 and sys.argv[4] == "debug"
        else:
            msg = "{0} Wrong arguments".format(now)
            bad_arguments = True

        # Logging the call
        with open(log_file, "a") as f:
            f.write(msg + "\n")

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        main(sys.argv)
    except Exception as e:
        debug(str(e))
        raise
