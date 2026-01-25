#!/usr/bin/python3

import yara
import sys
import re

fingerprint_log_file = "/var/log/scythe/fingerprint.txt"
signature_path = "/opt/signatures/"

uniqueID = sys.argv[1]


with open(fingerprint_log_file, 'r') as log:
    fingerprints = log.read()

json_data = re.search(f"\\[\\d+:\\w+:\\d+:\\d+:\\d+:\\d+\\s(\\W|\\D)\\d+]\\s{uniqueID}\\s(.*)", fingerprints).group(2)

with open(signature_path + "live.yara", "r") as rules:
    yara_rules = rules.read()

if yara_rules == "":
    print("none")
    exit()


yara_rules = yara_rules.split("\nrule")
for x, rule in enumerate(yara_rules):
    if not rule.startswith("rule"):
        yara_rules[x] = "\nrule" + rule
    rule = yara.compile(source=yara_rules[x])
    matches = rule.match(data=json_data)
    # print(matches[0].rule)
    # print(matches[0].tags[0])
    if matches:
        if matches[0].tags[0] == "level_3":
            print("block")
        elif matches[0].tags[0] == "level_2":
            print("captcha")
        elif matches[0].tags[0] == "level_1":
            print("limit")
        exit()

print("none")

