#!/usr/bin/python3

import requests
from random_username.generate import generate_username
import random
import string
import os

# create a pastebin account and retrieve your dev_key from here: "https://pastebin.com/doc_api"
api_key = ""
url = 'https://pastebin.com/api/api_post.php'
path = "/opt/signatures/creds.txt"


def generate_msg():
    special_char = random.choice(["!", "@", "$", "%", "&", "-", "_"])
    upper_char = random.choice(list(string.ascii_uppercase))
    lower_char = random.choice(list(string.ascii_lowercase))

    rand_number = str(random.randrange(1, 99))

    username = generate_username(1)[0] + rand_number + "@gmail.com"
    password = generate_username(1)[0] + lower_char + upper_char + special_char

    data = f'''Hey John our new site up on http://zebrapal.hopto.org. We need you to help us manage the site. Here are your credentials: 
Username: {username}
Password: {password}
'''

    return data, username, password


def custom_message():
    username = "Username: " + input("Enter Custom Email: ")
    password = "Password: " + input("Enter Custom Password: ")

    print("\nEnter/Paste your Message. Ctrl-D to save it.")
    contents = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents += line + "\n"

    contents += username + "\n" + password + "\n"
    return contents, username, password



file_writable = os.access(path, os.W_OK)
if not file_writable:
    try:
        if not os.path.exists(path):
            open(path, "w").close()
        else:
            print("Path /var/www/html/login/creds.txt not writable. Might require elevated privileges!!")
            exit()
    except PermissionError:
        print("Path /var/www/html/login/creds.txt not writable. Might require elevated privileges!!")
        exit()


choice = input("Custom/Default Message: ").lower()
print()

if choice == "custom":
    data = custom_message()
elif choice == "default":
    data = generate_msg()
else:
    print("Invalid Choice")
    exit()


result = input(f"\n\n\nVerify message. Hit Enter to send message else type 'exit'\nMessage:\n\n{data[0]}\n> ")
if result != "":
    exit()

myobj = {"api_dev_key":api_key, "api_paste_code":data[0], "api_paste_name":'Creds', "api_option":"paste"}
x_url = requests.post(url, data=myobj)


if "bad api request" in x_url.text.lower():
    print(x_url.text)
else:
    with open(path, "a") as file:
            file.write(data[1] + " " + data[2] + " 1" + "\n")

    print(f"\nURL: {x_url.text}")
