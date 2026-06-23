import csv
from urllib.parse import urlparse


KNOWN_SHORTENERS = {
    "adf.ly",
    "bit.do",
    "bit.ly",
    "bitly.com",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "j.mp",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
    "trib.al",
    "t.ly",
}


def convertion(url, prediction):
    if shortlink(url) == -1:
        return [url, "Not Safe", "Still want to Continue"]
    if prediction == 1:
        return [url, "Safe", "Continue", "1"]
    return [url, "Not Safe", "Still want to Continue"]


def shortlink(url):
    host = urlparse(url).netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    if host in KNOWN_SHORTENERS:
        return -1
    return 1


def find_url_in_csv(csv_file, target_url):
    with open(csv_file, "r", newline="", encoding="utf-8") as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            url = row[0].strip()
            if url == target_url:
                return url
    return None
