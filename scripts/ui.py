#!/usr/bin/python3

import os
import re
import time
import logging
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

status_path = "/var/log/scythe/status.txt"
live_path = "/opt/signatures/live.yara"

global_content = {}

size = {}


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def printData(data, colour):
    if data is None:
        print(f'{eval(colour) + "| User ID": <47} {"| Email": <40} {"| Login Status": <15} {"| Fingerprint": <81} {"| Alert": <8} {"| Yara Signature": <81} {"| Modified": <5}' + eval(colour))
        print("-" * 284)
    else:
        print(f'{eval(colour) + "| " + data[0]: <43} {"| " + data[1]: <40} {"| " + data[2]: <15} {"| " + data[3]: <81} {"| " + data[4]: <8} {"| " + data[5]: <81} {"| " + data[6]: <5}' + eval(colour))


def extractor(data, type):
    global global_content

    if type == "status":
        pattern = "\[.*\]\s(.*)\sUser\s(.*)\sattempted\sa\s(\w*)\slogin"
        extract = re.findall(pattern, data)

        for content in extract:
            id = content[0]
            email = content[1]
            state = content[2].capitalize()

            global_content[id] = [email, state]
            printData([id, email, state, f"127.0.0.1/dataview.php?id={id}&type=finger", "no", "-", "no"], "color.GREEN")


    elif type == "live":
        pattern = "rule\s(.*):\slevel_\d"
        extract = re.findall(pattern, data)

        for id in extract:
            email = global_content[id][0]
            state = global_content[id][1]

            printData([id, email, state, f"127.0.0.1/dataview.php?id={id}&type=finger", "yes", f"127.0.0.1/dataview.php?id={id}&type=yara", "yes"], "color.RED")


def read_file(file_path, type):
    global size

    if os.path.getsize(file_path) != 0:
        size[type + "_new"] = os.path.getsize(file_path)

        x = size[type + "_old"] - size[type + "_new"]
        if x < 0:
            value = x
        else:
            value = 0

        size[type + "_old"] = size[type + "_new"]

        with open(file_path, 'rb') as file:
            file.seek(value, os.SEEK_END)  # Note minus sign
            data = file.read().decode()

        return data

    else:
        return ""


class myEventHandler(FileSystemEventHandler):

    def __init__(self, path, type):
        self.path = path
        self.type = type

    def on_modified(self, event):
        captured_path = event.src_path.replace('\\', '/')

        if captured_path == self.path:
            data = read_file(self.path, self.type)

            if data != "":
                extractor(data, self.type)


def monitor(path):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    type = re.search(".*/(.*)\..*", path).group(1)

    size[type + '_old'] = 0
    size[type + '_new'] = 0

    read_file(path, type)
    just_path = re.search("(.*)/.*", path).group(1)

    event_handler = myEventHandler(path, type)
    observer = Observer()
    observer.schedule(event_handler, just_path, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(0.1)
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    printData(None, "color.GREEN")

    t1 = threading.Thread(target=monitor, args=(status_path,))
    t2 = threading.Thread(target=monitor, args=(live_path,))

    t1.start()
    t2.start()

    # printData(["YOneXkRxx4fh48X31gCm3NfonBQsDUxkQECCYaqP", "zebrapal123@gmail.com", "Failed", "127.0.0.1/fingerview.php?id=YOneXkRxx4fh48X31gCm3NfonBQsDUxkQECCYaqP&type=log", "no", "-", "no"])
    # printData(["YOneXkRxx4fh48X31gCm3NfonBQsDUxkQECCYaqP", "zebrapal123@gmail.com", "Successful", "127.0.0.1/fingerview.php?id=YOneXkRxx4fh48X31gCm3NfonBQsDUxkQECCYaqP&type=log", "yes", "127.0.0.1/fingerview.php?id=YOneXkRxx4fh48X31gCm3NfonBQsDUxkQECCYaqP&type=yara", "yes"])
