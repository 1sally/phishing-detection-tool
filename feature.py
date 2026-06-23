import ipaddress
import re
import socket
import urllib.request
from datetime import date
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup
from googlesearch import search


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = urlparse(url)
        self.response = None
        self.soup = BeautifulSoup("", "html.parser")

        try:
            self.domain = self.urlparse.netloc
        except Exception:
            self.domain = ""

        try:
            self.response = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10,
            )
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except Exception:
            pass

        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except Exception:
            self.whois_response = None

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def _host_name(self):
        if not self.domain:
            return ""
        return self.domain.split(":")[0].lower()

    def _is_internal_resource(self, resource_url):
        if not resource_url:
            return False

        resource_url = resource_url.lower()
        host_name = self._host_name()

        return (
            resource_url.startswith("/")
            or resource_url.startswith("./")
            or resource_url.startswith("../")
            or resource_url.startswith("data:")
            or (host_name and host_name in resource_url)
            or self.url.lower() in resource_url
        )

    def _normalize_whois_date(self, value):
        if isinstance(value, list) and value:
            value = value[0]
        return value

    def UsingIp(self):
        try:
            ipaddress.ip_address(self._host_name())
            return -1
        except Exception:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(
            r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
            r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|"
            r"q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net",
            self.url,
        )
        return -1 if match else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind("//") > 7 else 1

    def prefixSuffix(self):
        try:
            return -1 if "-" in self._host_name() else 1
        except Exception:
            return 0

    def SubDomains(self):
        try:
            dot_count = self._host_name().count(".")
            if dot_count == 1:
                return 1
            if dot_count == 2:
                return 0
            return -1
        except Exception:
            return 0

    def Hppts(self):
        try:
            return 1 if self.urlparse.scheme == "https" else -1
        except Exception:
            return 0

    def DomainRegLen(self):
        try:
            expiration_date = self._normalize_whois_date(self.whois_response.expiration_date)
            creation_date = self._normalize_whois_date(self.whois_response.creation_date)
            age = (expiration_date.year - creation_date.year) * 12 + (
                expiration_date.month - creation_date.month
            )
            return 1 if age >= 12 else -1
        except Exception:
            return 0

    def Favicon(self):
        try:
            icon_links = [
                link
                for link in self.soup.find_all("link", href=True)
                if "icon" in " ".join(link.get("rel", [])).lower()
            ]

            if not icon_links:
                return 0

            for link in icon_links:
                href = link["href"]
                if self._is_internal_resource(href):
                    return 1
            return 0
        except Exception:
            return 0

    def NonStdPort(self):
        try:
            return -1 if ":" in self.domain else 1
        except Exception:
            return 0

    def HTTPSDomainURL(self):
        try:
            return -1 if "https" in self._host_name() else 1
        except Exception:
            return 0

    def RequestURL(self):
        try:
            total = 0
            internal = 0

            for tag, attr in (("img", "src"), ("audio", "src"), ("embed", "src"), ("iframe", "src")):
                for item in self.soup.find_all(tag, **{attr: True}):
                    total += 1
                    if self._is_internal_resource(item[attr]):
                        internal += 1

            if total == 0:
                return 0

            percentage = internal / float(total) * 100
            if percentage < 22.0:
                return -1
            if percentage < 61.0:
                return 0
            return 1
        except Exception:
            return 0

    def AnchorURL(self):
        try:
            total = 0
            unsafe = 0

            for anchor in self.soup.find_all("a", href=True):
                total += 1
                href = anchor["href"].lower()
                if (
                    "#" in href
                    or "javascript" in href
                    or "mailto" in href
                    or not self._is_internal_resource(href)
                ):
                    unsafe += 1

            if total == 0:
                return 0

            percentage = unsafe / float(total) * 100
            if percentage < 31.0:
                return 1
            if percentage < 67.0:
                return 0
            return -1
        except Exception:
            return 0

    def LinksInScriptTags(self):
        try:
            total = 0
            internal = 0

            for link in self.soup.find_all("link", href=True):
                total += 1
                if self._is_internal_resource(link["href"]):
                    internal += 1

            for script in self.soup.find_all("script", src=True):
                total += 1
                if self._is_internal_resource(script["src"]):
                    internal += 1

            if total == 0:
                return 0

            percentage = internal / float(total) * 100
            if percentage < 17.0:
                return -1
            if percentage < 81.0:
                return 0
            return 1
        except Exception:
            return 0

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1

            for form in forms:
                action = form["action"].strip().lower()
                if action in {"", "about:blank"}:
                    return -1
                if not self._is_internal_resource(action):
                    return 0
            return 1
        except Exception:
            return 0

    def InfoEmail(self):
        try:
            return -1 if re.findall(r"mailto:|mail\(", self.response.text.lower()) else 1
        except Exception:
            return 0

    def AbnormalURL(self):
        try:
            final_host = urlparse(self.response.url).netloc
            if final_host and self._host_name() and self._host_name() in final_host.lower():
                return 1
            return 0
        except Exception:
            return 0

    def WebsiteForwarding(self):
        try:
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            if redirects <= 4:
                return 0
            return -1
        except Exception:
            return 0

    def StatusBarCust(self):
        try:
            return 1 if re.findall(r"<script>.+onmouseover.+</script>", self.response.text) else -1
        except Exception:
            return 0

    def DisableRightClick(self):
        try:
            return 1 if re.findall(r"event.button ?== ?2", self.response.text) else -1
        except Exception:
            return 0

    def UsingPopupWindow(self):
        try:
            return 1 if re.findall(r"alert\(", self.response.text) else -1
        except Exception:
            return 0

    def IframeRedirection(self):
        try:
            return -1 if re.findall(r"<iframe|<frameborder", self.response.text.lower()) else 1
        except Exception:
            return 0

    def AgeofDomain(self):
        try:
            creation_date = self._normalize_whois_date(self.whois_response.creation_date)
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except Exception:
            return 0

    def DNSRecording(self):
        try:
            creation_date = self._normalize_whois_date(self.whois_response.creation_date)
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except Exception:
            return 0

    def WebsiteTraffic(self):
        try:
            rank_page = urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + self.url,
                timeout=5,
            ).read()
            reach = BeautifulSoup(rank_page, "xml").find("REACH")
            rank = int(reach["RANK"])
            return 1 if rank < 100000 else 0
        except Exception:
            return 0

    def PageRank(self):
        try:
            rank_checker_response = requests.post(
                "https://www.checkpagerank.net/index.php",
                {"name": self.domain},
                timeout=10,
            )
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            return 1 if 0 < global_rank < 100000 else 0
        except Exception:
            return 0

    def GoogleIndex(self):
        try:
            results = list(search(self.url, 5))
            return 1 if results else 0
        except Exception:
            return 0

    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text.lower()))
            if number_of_links == 0:
                return 1
            if number_of_links <= 2:
                return 0
            return -1
        except Exception:
            return 0

    def StatsReport(self):
        try:
            url_match = re.search(
                r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
                self.url,
            )
            ip_address = socket.gethostbyname(self._host_name())
            ip_match = re.search(
                r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
                r"107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
                r"118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
                r"216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
                r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|"
                r"216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42",
                ip_address,
            )
            if url_match or ip_match:
                return -1
            return 1
        except Exception:
            return 0

    def getFeaturesList(self):
        return self.features
