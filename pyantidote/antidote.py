#!/usr/bin/env python

import os
import re
import time
import psutil
import hashlib
import sqlite3
import requests
import threading
from bs4 import BeautifulSoup

from binaryornot.check import is_binary

'''
commentary:
    - Your busywaiting loop could use some abstraction. I think modern Pythons even ship a thread pool
    - Your use of FileScanner as a context manager doesn't seem to be doing anything
'''

DEBUG = True

class DB(object):
    # TODO: Log the URLS it's grabbed hashes from
    # And check the logged urls and skip over logged urls
    # when calling the self.update() function
    def __init__(self, db_fp='data.db'):
        self.db_fp = db_fp
        self.conn = sqlite3.connect(db_fp)
        self.cur = self.conn.cursor()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __repr__(self):
        return "<SQLite3 Database: {}>".format(self.db_fp)

    def close(self):
        self.conn.commit()
        self.cur.close()
        self.conn.close()

    def create_tables(self):
        self.cur.execute('CREATE TABLE IF NOT EXISTS virus_md5_hashes(md5_hash TEXT NOT NULL UNIQUE)')
        self.cur.execute('CREATE TABLE IF NOT EXISTS processed_virusshare_urls(url TEXT NOT NULL UNIQUE)')
        self.cur.execute('CREATE TABLE IF NOT EXISTS high_risk_ips(ip TEXT NOT NULL UNIQUE)')
        self.conn.commit()

    def drop_tables(self):
        self.cur.execute('DROP TABLE IF EXISTS virus_md5_hashes')
        self.cur.execute('DROP TABLE IF EXISTS processed_virusshare_urls')
        self.cur.execute('DROP TABLE IF EXISTS high_risk_ips')
        self.conn.commit()

    def add(self, table, value):
        try:
            sql = f"INSERT INTO {table} VALUES (?)"
            self.cur.execute(sql, (value,))
        except sqlite3.IntegrityError as e:
            if 'UNIQUE' in str(e):
                pass # Do nothing if trying to add a duplicate value
            else:
                print(e)
                raise e

    def exists(self, vname, table, value):
        sql = f"SELECT {vname} FROM {table} WHERE {vname} = (?)"
        self.cur.execute(sql, (value,))
        return self.cur.fetchone() is not None

    def reset(self):
        '''
        reformats the database, think of it as a fresh-install
        '''
        # self.drop_tables()
        os.remove(self.db_fp)
        self.update()

    def update(self):
        self.create_tables()
        self.update_md5_hashes()
        self.update_high_risk_ips()

    def update_md5_hashes(self):
        '''
        updates the sqlite database of known virus md5 hashes
        '''
        urls = self.get_virusshare_urls()
        for n, url in enumerate(urls):
            reprint(f"Downloading known virus hashes {n+1}/{len(urls)}")
            if not self.exists('url', 'processed_virusshare_urls', url):
                for md5_hash in self.get_virusshare_hashes(url):
                    self.add('virus_md5_hashes', md5_hash)
                self.add('processed_virusshare_urls', url)
            self.conn.commit()
        print()

    def get_virusshare_urls(self) -> list:
        '''
        returns a list of virusshare.com urls containing md5 hashes
        '''
        r = requests.get('https://virusshare.com/hashes.4n6')
        soup = BeautifulSoup(r.content, 'html.parser')
        return ["https://virusshare.com/{}".format(a['href']) for a in soup.find_all('a')][6:-2]

    def get_virusshare_hashes(self, url) -> str:
        '''
        parses all the md5 hashes from a valid virusshare.com url
        '''
        r = requests.get(url)
        return r.text.splitlines()[6:]

    def update_high_risk_ips(self):
        sources = [
            'https://blocklist.greensnow.co/greensnow.txt',
            'https://cinsscore.com/list/ci-badguys.txt',
            'http://danger.rulez.sk/projects/bruteforceblocker/blist.php',
            'https://malc0de.com/bl/IP_Blacklist.txt',
            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
            'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',
            'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
            'https://hosts.ubuntu101.co.za/ips.list',
            'https://lists.blocklist.de/lists/all.txt',
            'https://myip.ms/files/blacklist/general/latest_blacklist.txt',
            'https://pgl.yoyo.org/adservers/iplist.php?format=&showintro=0',
            'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt',
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset',
            'https://www.dan.me.uk/torlist/?exit',
            'https://www.malwaredomainlist.com/hostslist/ip.txt',
            'https://www.maxmind.com/es/proxy-detection-sample-list',
            'https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1',
            'http://www.unsubscore.com/blacklist.txt',
        ]
        for n, source in enumerate(sources):
            reprint(f"Downloading ips list: {n+1}/{len(sources)}")
            r = requests.get(source)
            for ip in re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', r.text):
                self.add('high_risk_ips', ip)
        print()


class FileScanner(object):
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.bad_files = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass
        # self.stop()

    def __repr__(self):
        return "<FileScanner>"

    def get_binary_files_generator(self, folder) -> str:
        '''
        :param folder: directory to resursively check for binary files
        :return: generator of all binary files (str == full path)
        '''
        for folder_name, sub_folder, filenames in os.walk(folder):
            for f in filenames:
                f = f"{folder_name}/{f}"
                if is_binary(f):
                    yield os.path.abspath(f)

    def get_md5(self, fp) -> str:
        '''
        :param fp: full path to a file
        :return: the md5 hash of a file
        '''
        md5_hash = hashlib.md5()
        with open(fp, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def compare_against_database(self, fp):
        with DB() as db:
            md5_hash = self.get_md5(fp)
            if db.exists('md5_hash', 'virus_md5_hashes', md5_hash):
                self.bad_files.append(os.path.abspath(fp))

    def scan(self, folder):
        start_time = time.time()
        fp_gen = self.get_binary_files_generator(folder)
        count = 0
        try:
            while True:
                if threading.active_count() < self.max_threads:
                    t = threading.Thread(target=self.compare_against_database, args=(next(fp_gen), ))
                    t.start()
                    count += 1
                    reprint(f'Scanning Files - Threads: {threading.active_count()}    Files Scanned: {count}     ')
                else:
                    time.sleep(0.01)
        except StopIteration:
            end_time = time.time()
            print(f"scanned {count} files in {end_time - start_time} seconds")
            for f in self.bad_files:
                print(f"INFECTED - {f}")


# class NetworkScanner():
#     def __init__(self):
#         pass

#     def get_active_addrs(self):
#         # TODO: rewrite this
#         remote_addrs = []
#         for conn in psutil.net_connections():
#             try:
#                 remote_addrs.append(conn[3][0])
#             except IndexError:
#                 pass
#             try:
#                 remote_addrs.append(conn[4][0])
#             except IndexError:
#                 pass
#         return list(set(remote_addrs))


#     # def get_connection_obj_from_addr(self, ip):


#     def compare_against_database(self, ip):
#         with DB() as db:
#             if db.exists('ip', 'high_risk_ips', ip):
#                 pass


def reprint(s):
    print(s, end='')
    print('\r' * len(s), end='')


def Main():
    # Testing for now
    with DB() as db:
        db.update()
    # with FileScanner(20) as fsc:
    #     fsc.scan('/home/jack')
        # fsc.scan('/mnt/c/PHANTASYSTARONLINE2')
 

if __name__ == '__main__':
    Main()
