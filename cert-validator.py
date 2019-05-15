import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from textwrap import wrap
import requests
import argparse
import re
import json
import os
from sys import exit 
import configparser

requests.packages.urllib3.disable_warnings()

def read_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Enter vault's url", type=validate_url)
    parser.add_argument("--token", help="Enter vault's token", type=validate_token)
    parser.add_argument("-s", "--show", help="Show root mounts", action='store_true')
    parser.add_argument("-g", "--get", help="Root path from where to search the certs", type=validate_path)
    return parser.parse_args()



def validate_path(arg, secret=re.compile(r"((?:^\w+\/?)(?:(?:\w+(?:[\.-]+)?\w+\/?)+)?(?:\/$))")):
    if not secret.match(arg):
        raise argparse.ArgumentTypeError("Invalid value, must not start with / and must end with /")
    return arg

def validate_url(arg):
    if "https" not in arg:
        arg = "https://" + arg
    return arg

def validate_token(arg, token=re.compile(r"(^\w{8}-(?:\w{4}-){3}\w{12}$)")):
    if not token.match(arg):
        raise argparse.ArgumentTypeError("Invalid token")
    return arg

def validate_file(arg, file = re.compile(r".*\.vaulty")):
    if not file.match(arg):
        raise argparse.ArgumentTypeError("File must end with .vaulty extension")
    return arg

def read_config():
    config = configparser.ConfigParser()
    config.optionxform = str
    if os.path.isfile("/etc/vaulty.conf"):
        try:
            with open("/etc/vaulty.conf", "r+") as config_file:
                config.read_file(config_file)
        except IOError as error:
            print(error)
            exit(1)
    else:
        print("No config file found, please create one as /etc/vaulty.conf or use --url --token as arguments")
        exit(1)
    return config

def query_path(method_type, path, **data):
    if args.url:
        url = args.url
        if not args.token:
            url_token = read_config()
            token = url_token["client"]["token"]
        else:
            token = args.token
    if args.token:
        token = args.token
        if not args.url:
            url_token = read_config()
            url = url_token["client"]["host"]
            if "https" not in url:
                url = "https://" + url
        else:
            url = args.url
    elif not args.token and not args.url:
        url_token = read_config()
        url = url_token["client"]["host"]
        token = url_token["client"]["token"]
        if "https" not in url:
            url = "https://" + url
    if data:
        payload = data["data"]
    else:
        payload = {None:None}
    session = requests.Session()
    session.headers.update({"X-Vault-Token": token})
    vault_response = session.request(method_type, url + "/v1/" + path, json=payload, verify=False)
    if vault_response.status_code == 200:
        return json.loads(vault_response.content.decode('utf-8'))
    elif vault_response.status_code == 204:
        if method_type == "POST":
            print("Operation successful")
            exit(0)
        else:
            return vault_response.status_code
    elif vault_response.status_code == 500:
        print("There's something wrong but I'll try to continue...")
        pass
    elif vault_response.status_code == 400:
        print("Malformed JSON body")
        exit(1)
    elif vault_response.status_code == 403:
        print("Forbidden 403")
        exit(1)
    elif vault_response.status_code == 503:
        print("Vault is down for maintenance or is currently sealed. Try again later")
        exit(1)
    else:
        return None

def obtain_root_mounts():
    mounts = query_path("GET","sys/mounts")
    return mounts

def explore(path, row):
    paths = query_path("LIST", path)
    if paths is not None and paths is not int:
        for value in paths['data'].values():
            for item in value:
                string = path + item
                explore(string,row)
                if not re.search("\w+\/$", string, re.IGNORECASE):
                    row.append(string)
    return row

def read_secret(secret):
        secrets = query_path("GET", secret)
        if secrets is not None:
            return secrets

def check_cert(path):
    for i in path:
        secret = read_secret(i)
        if secret is not None:
            for key, value in secret['data'].items():
                if isinstance(value, str):
                    if re.search("CERTIFICATE", value):
                        cert_list = (re.findall("(?<=-----BEGIN CERTIFICATE-----)([a-zA-Z0-9\/=\+]+)(?=-----END CERTIFICATE-----)", value))
                        #for cert in cert_list:
                        #    format_cert = wrap(cert,64)
                        format_cert = wrap(cert_list[0],64)
                        cert_pem = bytes("-----BEGIN CERTIFICATE-----" + "\n" + "\n".join(format_cert) + "\n" + "-----END CERTIFICATE-----" + "\n", "utf-8")
                        certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
                        print("CERT " + i + " VALID UNTIL: " + certificate.not_valid_after.strftime("%Y-%m-%d"))

def read_file(file_path):
    tmp = {}
    try:
        with open(file_path) as secrets_file:
            data = secrets_file.readlines()
    except IOError as error:
        print(error)
    for line in data:
        if re.match(r"[\w\d \-_\.]+:[\w\d \-_=\.\?\\\/\$%\^\+@]+", line):
            tmp[line.split(":")[0]] = line.split(":")[1].strip("\n")
    return tmp

if __name__ == '__main__':
    tmp = []
    row = []
    args = read_args()

    if args.show:
        mounts = obtain_root_mounts()
        for key in mounts.keys():
            result = query_path("LIST", key)
            if result is not None:
                tmp.append(key)
        mount_list = sorted(tmp)
        for i in mount_list:
            print(i)

    if args.get:
        print("Looking for certificates, please wait...\n")
        if args.get == "root/":
            mounts = obtain_root_mounts()
            for key in mounts.keys():
                result = query_path("LIST", key)
                if result is not None:
                    tmp.append(key)
            mount_list = sorted(tmp)
            for i in mount_list:
                row1 = explore(i, row)
                check_cert(row1)
        else:
            row1 = explore(args.get, row)
            check_cert(row1)

