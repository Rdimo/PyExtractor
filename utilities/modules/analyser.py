import re
import json
import pefile
import httpx
import threading
from os import pardir, path, stat, walk
from math import log2
from magic import from_file
from collections import Counter
from mimetypes import guess_type
from dataclasses import dataclass
from hashlib import md5, sha1, sha256
from utilities import printInfo, printErr, printErrStack, printNormal, Config
from utilities.common.logger import printSucc, printWarn


@dataclass
class Analyse(object):
    def __init__(self, _file):
        self.datastruct: dict = ...
        self.file = _file
        self.regex = {
            # love you https://regex101.com/
            'sus word': re.compile(r'(\btoken\b|grabber|stealer|steal|webhook|passwords|chrome|\bopera\b|opera gx|\bedge\b|brave|firefox|ipify|leveldb|appdata|localappdata|local storage|index.js|desktop-core|discord|discordcanary|discordptb)'),
            'url': re.compile(r'(http|https|ftp)\://([a-zA-Z0-9\-\.]+\.+[a-zA-Z]{2,3})(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~@]*)'),
            'discord webhook': re.compile(r'(https?):\/\/((?:ptb\.|canary\.)?discord(?:app)?\.com)\/api(?:\/)?(v\d{1,2})?\/webhooks\/(\d{17,19})\/([\w\-]{68})'),
            'discord invite': re.compile(r'(https?:\/\/)?(www\.)?((discordapp\.com/invite)|(discord\.gg))\/(\w+)'),
            'pastebin': re.compile(r'(https:\/\/pastebin\.com\/(:?raw\/)[a-z0-9]{8})'),
            'ip': re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        }
        self.found_sus_words = []
        self.found_links = []
        self.found_webhooks = []
        self.found_invites = []
        self.found_pastebins = []
        self.found_ips = []

    def start(self, folder=True):
        filename = path.basename(self.file)
        _path = path.abspath(path.join(path.abspath(
            path.join(path.dirname(__file__), pardir)), pardir))
        _folder = path.join(_path, filename)
        jsonfile = path.join(_folder, filename + '.json')
        printInfo(f'Fetching general info about {filename} (might take some time)')
        self.get_detailes()
        self.get_sections()

        if Config.get_setting('detailed_logs'):
            printInfo('General info:')
            for key, value in self.datastruct.get('General').items():
                printNormal(f"  {key}: {value}")

            printInfo('File Section info:')
            for key, value in self.datastruct.get('Sections').items():
                printNormal(f" {key}:")
                for k, v in value.items():
                    printNormal(f"  {k}: {v}")
                printInfo('')

        if not folder:
            self.search_files(self.file, False)
        else:
            self.search_files(_folder)
        req = self.malware_recognizer()
        if req:
            self.datastruct.update(req)
        try:
            with open(jsonfile, 'w', errors="ignore") as f:
                json.dump(
                    self.datastruct, f,
                    ensure_ascii=False,
                    indent=4,
                    sort_keys=True
                )
        except FileNotFoundError:
            open(jsonfile, "w").close()

        if self.found_sus_words:
            printErr(f'Suspiciou{"s" if len(self.found_sus_words) > 1 else ""} words found!:')
            for item in self.found_sus_words:
                printWarn(f"  {item}")

        if self.found_links:
            printErr(f'Url{"s" if len(self.found_links) > 1 else ""} found!:')
            for item in self.found_links:
                printWarn(f"  {item}")

        if self.found_ips:
            printErr(f'IP{"s" if len(self.found_ips) > 1 else ""} found!:')
            for item in self.found_ips:
                printWarn(f"  {item}")

        if self.found_invites:
            printErr(f'Discord invite{"s" if len(self.found_invites) > 1 else ""} found!:')
            for item in self.found_invites:
                printWarn(f"  {item}")

        if self.found_pastebins:
            printErr(f'Pastebin{"s" if len(self.found_pastebins) > 1 else ""} found!:')
            for item in self.found_pastebins:
                printWarn(f"  {item}")

        if self.found_webhooks:
            printErr(f'Discord webhook{"s" if len(self.found_webhooks) > 1 else ""} found!:')
            for item in self.found_webhooks:
                printWarn(f"  {item}")

        printInfo(f'Dumped file structure --> {jsonfile}')

    def search_files(self, loc, is_folder=True):
        def search(_path):
            with open(_path, 'r', errors="ignore") as f:
                content = f.read()
            for _type, regex in self.regex.items():
                results = regex.finditer(content, re.IGNORECASE)
                for match in results:
                    obj = match.group()
                    if _type == "sus word":
                        if obj not in self.found_sus_words:
                            self.found_sus_words.append(obj)
                    elif _type == 'url':
                        if obj not in self.found_links:
                            self.found_links.append(obj)
                    elif _type == 'discord webhook':
                        if obj not in self.found_webhooks:
                            self.found_webhooks.append(obj)
                    elif _type == 'discord invite':
                        if obj not in self.found_invites:
                            self.found_invites.append(obj)
                    elif _type == 'pastebin':
                        if obj not in self.found_pastebins:
                            self.found_pastebins.append(obj)
                    elif _type == 'ip':
                        if obj not in self.found_ips:
                            self.found_ips.append(obj)

        if Config.get_setting('analyse_file'):
            if is_folder and path.isdir(loc):
                for _, __, files in walk(loc):
                    for _path in files:
                        if not path.exists(_path):
                            continue
                        threading.Thread(target=search, args=(_path, ), daemon=True).start()
            else:
                threading.Thread(target=search, args=(loc, ), daemon=True).start()
            for t in threading.enumerate():
                try:
                    t.join()
                except RuntimeError:
                    continue

    def malware_recognizer(self):
        if Config.get_setting('malware_recognize'):
            url = "https://mb-api.abuse.ch/api/v1/"
            _hash = self.datastruct.get('General')['sha256']
            # a177de2527c8fd59a34636c57c4e2c7fae771a03333f2a7a31c4c1ceb88fdba8
            params = {"query": "get_info", "hash": _hash}
            req = httpx.post(url, data=params).json()
            resp = req.get('query_status')
            if resp != "ok":
                printWarn(f'Malware checker: {resp}')
                return
            printWarn('Malware Recognized!')
            return req

    @ staticmethod
    def convert_size(_size):
        for _unit in ['B', 'KB', 'MB', 'GB']:
            if _size < 1024.0:
                return "{:.2f}{}".format(_size, _unit)
            _size /= 1024.0
        return "file too big to convert"

    def get_entropy(self, data, buffer=False) -> str:
        if buffer:
            try:
                if not data:
                    return 0.0
                entropy = 0
                counter = Counter(data)
                temp_len = len(data)
                for count in counter.values():
                    temp_var = float(count) / temp_len
                    entropy += - temp_var * log2(temp_var)
                return entropy
            except Exception as e:
                printErr(
                    'Something wrong happend while trying to get the file entropy')
                printErrStack(e)
            return 0.0
        try:
            if not data:
                return "0.0 (Minimum: 0.0, Max: 8.0)"
            entropy = 0
            counter = Counter(data)
            temp_len = len(data)
            for count in counter.values():
                temp_var = float(count) / temp_len
                entropy += - temp_var * log2(temp_var)
            return f"{entropy} (Minimum: 0.0, Maximum: 8.0)"
        except Exception as e:
            printErr(
                'Something wrong happend while trying to get the file entropy')
            printErrStack(e)

    def get_detailes(self):
        _path = self.file
        size = stat(_path).st_size
        temp_f = open(_path, "rb").read()
        self.datastruct = {
            "General": {
                "Name": path.basename(_path).lower(),
                "md5": md5(temp_f).hexdigest(),
                "sha1": sha1(temp_f).hexdigest(),
                "sha256": sha256(temp_f).hexdigest(),
                "size": self.convert_size(size),
                "bytes": size,
                "mime": from_file(_path, mime=True),
                "extension": guess_type(_path)[0],
                "entropy": self.get_entropy(temp_f)
            }
        }

    def get_sections(self):
        pe_info = pefile.PE(self.file)
        self.datastruct.update({'Sections': {}})
        for section in pe_info.sections:
            is_sus = "No"
            entropy = self.get_entropy(section.get_data(), True)
            if entropy > 6 or (0 <= entropy <= 1):
                is_sus = f"True ({entropy})"
            elif section.SizeOfRawData == 0:
                is_sus = "True (section size 0)"
            self.datastruct.get('Sections').update({section.Name.decode("utf-8", errors="ignore").strip("\00"): {
                "Suspicious": is_sus,
                "Size": section.SizeOfRawData,
                "MD5": section.get_hash_md5(),
                "Entropy": self.get_entropy(section.get_data()),
                "Description": ""
            }})
