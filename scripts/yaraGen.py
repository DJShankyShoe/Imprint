#!/usr/bin/python3

import json
import hashlib
import re
import sys
import csv
import gzip
import os

fingerprint_log_file = "/var/log/scythe/fingerprint.txt"
signature_path = "/opt/signatures/"
result_filepath = sys.argv[8]
alert = sys.argv[4].lower()

with gzip.open(result_filepath, 'r') as file:
    file_content = file.read()

with open("data.csv", 'wb') as file:
    file.write(file_content)

with open('data.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)
    uniqueID = next(reader)[0]

os.remove("data.csv")


# extarct appropriate fingerprint
with open(fingerprint_log_file, 'r') as log:
    fingerprints = log.read()

json_data = re.search(f"\\[\\d+:\\w+:\\d+:\\d+:\\d+:\\d+\\s(\\W|\\D)\\d+]\\s{uniqueID}\\s(.*)", fingerprints).group(2)


# hash the json_data
json_hash = hashlib.md5(json_data.encode("utf-8")).hexdigest()
json_dict = json.loads(json_data)


# customizable yara rule
level_1 = ["jscd_agent", "network_zip", "network_query", "browser_timezone"]
level_2 = ["jscd_agent", "jscd_mobile", "hardware_gpu", "browser_permissions", "browser_fonts", "browser_canvas"]
level_3 = ["jscd_agent", "jscd_mobile", "jscd_os", "hardware_cpuCores", "hardware_gpu", "browser_permissions", "browser_fonts", "browser_canvas", "browser_plugins", "visitorId"]


# pass in json parameters and returns with yara formated rule
def createYaraRule(values):
    string = ""
    conditions = "    "

    for idx, access in enumerate(values):
        data_names = access.split("_")

        command = "json_dict"
        for x in data_names:
            command += f"['{x}']"

        pos = access.find("_")
        letter = access[pos + 1].upper()
        access_mod = access[:pos] + letter + access[pos + 2:]

        data_value = eval(command)
        if type(data_value) != str:
            data_value = str(data_value).replace("': '", "':'").replace("', '", "','").replace("'", '\\"')
            string += f'''   ${access_mod} = "\\"{data_names[-1]}\\":{data_value}" nocase\n'''
        else:
            string += f'''   ${access_mod} = "\\"{data_names[-1]}\\":\\"{data_value}\\"" nocase\n'''

        if idx != len(values) - 1:
            conditions += f"${access_mod} and "
        else:
            conditions += f"${access_mod}"

    return string, conditions


# appends yara rules in the right file
if json_hash not in open(signature_path + "myhash.txt").read():
    with open(signature_path + "myhash.txt", 'a+') as hash_data:
        hash_data.write(json_hash + "\n")

    with open(signature_path + 'level1.yara', 'a+') as yara1:
        strings, condition = createYaraRule(level_1)
        yara1.write("rule " + uniqueID + ": level_1\n{\nstrings:\n" + strings + "\ncondition:\n" + condition + "\n}\n")

    with open(signature_path + 'level2.yara', 'a+') as yara2:
        strings, condition = createYaraRule(level_2)
        yara2.write("rule " + uniqueID + ": level_2\n{\nstrings:\n" + strings + "\ncondition:\n" + condition + "\n}\n")

    with open(signature_path + 'level3.yara', 'a+') as yara3:
        strings, condition = createYaraRule(level_3)
        yara3.write("rule " + uniqueID + ": level_3\n{\nstrings:\n" + strings + "\ncondition:\n" + condition + "\n}\n")


# modify accordingly from splunk alert name (block, captcha, limit)
if alert == "limit":
    rule_type = "level_1"
elif alert == "captcha":
    rule_type = "level_2"
elif alert == "block":
    rule_type = "level_3"
else:
    rule_type = "clear"


# removes old rule with same uniqueID from live.yara
try:
    with open(signature_path + 'live.yara', 'r') as live:
        live_data = live.read()

    regex_ex = re.search("rule\\s" + uniqueID + ":\\slevel_(\\d)\\n{(.|\\n[^}])*\\n}", live_data)
    live_extract = regex_ex.group(0)
    live_value = "live_" + regex_ex.group(1)

    if rule_type != live_value or rule_type == "clear":
        new_live_data = live_data.replace(live_extract + "\n", "")
        with open(signature_path + 'live.yara', 'w') as live:
            live.write(new_live_data)

except AttributeError:
    pass


# pushes appropriate yara rule to live.yara
if rule_type != "clear":
    with open(signature_path + 'live.yara', 'a+') as live:
        strings, condition = createYaraRule(eval(rule_type))
        live.write("rule " + uniqueID + ": " + rule_type + "\n{\nstrings:\n" + strings + "\ncondition:\n" + condition + "\n}\n")
