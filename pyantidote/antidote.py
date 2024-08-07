#!/usr/bin/env python

from collections.abc import Iterator
import os
import re
import time
import psutil
import hashlib
import sqlite3
import requests
import threading
from bs4 import BeautifulSoup
from argparse import ArgumentParser

# from binaryornot.check import is_binary

"""
commentary:
    - Your busywaiting loop could use some abstraction. I think modern Pythons even ship a thread pool
    - Your use of FileScanner as a context manager doesn't seem to be doing anything

    TODO: make a runtime check to verify database, fallback to updating the database if it fails
"""


class DB(object):
    # TODO: Log the URLS it's grabbed hashes from
    # And check the logged urls and skip over logged urls
    # when calling the self.update() function
    def __init__(self, db_fp="data.db"):
        self.db_fp = db_fp
        self.connect()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __repr__(self):
        return "<SQLite3 Database: {}>".format(self.db_fp)

    def connect(self):
        self.conn = sqlite3.connect(self.db_fp)
        self.cur = self.conn.cursor()

    def close(self):
        self.conn.commit()
        self.cur.close()
        self.conn.close()

    def create_tables(self):
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS virus_md5_hashes(md5_hash TEXT NOT NULL UNIQUE)"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS processed_virusshare_urls(url TEXT NOT NULL UNIQUE)"
        )
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS high_risk_ips(ip TEXT NOT NULL UNIQUE)"
        )
        self.conn.commit()

    def drop_tables(self):
        self.cur.execute("DROP TABLE IF EXISTS virus_md5_hashes")
        self.cur.execute("DROP TABLE IF EXISTS processed_virusshare_urls")
        self.cur.execute("DROP TABLE IF EXISTS high_risk_ips")
        self.conn.commit()

    def add(self, table, value):
        sql = f"INSERT OR IGNORE INTO {table} VALUES (?)"
        self.cur.execute(sql, (value,))

    def add_multiple(self, table, values):
        sql = f"INSERT OR IGNORE INTO {table} VALUES (?)"
        self.cur.executemany(sql, [(value,) for value in values])

    def exists(self, vname, table, value):
        # try:
        sql = f"SELECT {vname} FROM {table} WHERE {vname} = (?)"
        self.cur.execute(sql, (value,))
        return self.cur.fetchone() is not None
        # except sqlite3.OperationalError as e:
        #     print(f"[-] Database error {e}")
        #     print("Try updating the database")
        #     raise SystemExit

    def reset(self):
        """
        reformats the database, think of it as a fresh-install
        """
        # self.drop_tables() # This is soooo slow
        self.close()
        os.remove(self.db_fp)
        self.connect()
        self.update()

    def update(self):
        self.create_tables()
        self.update_md5_hashes()
        self.update_high_risk_ips()

    def update_md5_hashes(self):
        """
        updates the sqlite database of known virus md5 hashes
        """
        urls = self.get_virusshare_urls()
        for n, url in enumerate(urls):
            reprint(f"Downloading known virus hashes {n+1}/{len(urls)}")
            if not self.exists("url", "processed_virusshare_urls", url):
                self.add_multiple("virus_md5_hashes", self.get_virusshare_hashes(url))
                # for md5_hash in self.get_virusshare_hashes(url):
                # self.add('virus_md5_hashes', md5_hash)
                self.add("processed_virusshare_urls", url)
            self.conn.commit()
        print()

    def get_virusshare_urls(self) -> list:
        """
        returns a list of virusshare.com urls containing md5 hashes
        """
        r = requests.get("https://virusshare.com/hashes.4n6")
        soup = BeautifulSoup(r.content, "html.parser")
        return [
            "https://virusshare.com/{}".format(a["href"]) for a in soup.find_all("a")
        ][6:-2]

    def get_virusshare_hashes(self, url) -> str:
        """
        parses all the md5 hashes from a valid virusshare.com url
        """
        r = requests.get(url)
        return r.text.splitlines()[6:]

    def read_sources(self) -> list[str]:
        with open("sources.txt", "r") as f:
            return f.read().splitlines()

    def update_high_risk_ips(self):
        sources = self.read_sources()
        for n, source in enumerate(sources):
            reprint(f"Downloading ips list: {n+1}/{len(sources)}")
            try:
                r = requests.get(source)
                if r.ok:
                    self.add_multiple(
                        "high_risk_ips",
                        re.findall(
                            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", r.text
                        ),
                    )
            except requests.exceptions.RequestException:
                print(f"Exception at {source}")
        self.conn.commit()
        print()


class FileScanner(object):
    def __init__(self):
        self._bad_files = []

    def get_files(self, folder) -> Iterator[str]:
        """
        :param folder: directory to recursively check for binary files
        :return: generator of all binary files (str == full path)
        """
        for folder_name, sub_folder, filenames in os.walk(folder):
            for f in filenames:
                f = f"{folder_name}/{f}"
                yield f

    def get_md5(self, fp) -> str:
        """
        :param fp: full path to a file
        :return: the md5 hash of a file
        """
        md5_hash = hashlib.md5()
        with open(fp, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def compare_against_database(self, fp):
        if is_binary(fp):
            with DB() as db:  # db connection has to be called within the same thread accessing the db uhg.jpg
                md5_hash = self.get_md5(fp)
                if db.exists("md5_hash", "virus_md5_hashes", md5_hash):
                    self._bad_files.append(fp)

    def scan(self, folder, max_threads=10):
        s = "UNDEFINED"
        fp = "UNDEFINED"

        start_time = time.time()
        fp_gen = self.get_files(folder)
        count = 0
        try:
            while True:
                if threading.active_count() < max_threads:
                    fp = next(fp_gen)
                    t = threading.Thread(
                        target=self.compare_against_database, args=(fp,)
                    )
                    t.start()
                    count += 1
                    s = f"Scanning Files - Threads: {threading.active_count()}    Files Scanned: {count}     "
                    reprint(s)
                else:
                    time.sleep(0.01)
        except OSError:
            print(f"OSError: Bad file descriptor: {fp} {' ' * len(fp)}")
        except StopIteration:
            end_time = time.time()
            reprint(" " * len(s))
            print(f"scanned {count} files in {round(end_time - start_time, 2)} seconds")
            for f in self._bad_files:
                print(f"INFECTED - {f}")


class NetworkScanner(threading.Thread):
    def __init__(self, timer=1):
        self._timer = timer
        self._running = True
        self.update_current_connections()
        self._displayed_notifications = []
        threading.Thread.__init__(self)

    def update_current_connections(self):
        self._current_connections = psutil.net_connections()

    def scan(self):
        with DB() as db:
            for conn in self._current_connections:
                if conn.status != "NONE" or conn.status != "CLOSE_WAIT":
                    if db.exists("ip", "high_risk_ips", conn.laddr.ip):
                        self.notify(conn.laddr.ip, conn.laddr.port, conn.pid)
                    if conn.raddr:
                        if db.exists("ip", "high_risk_ips", conn.raddr.ip):
                            self.notify(conn.raddr.ip, conn.raddr.port, conn.pid)

    def notify(self, ip, port, pid, duration=10):
        title, body = (
            "High Risk Connection",
            f"{psutil.Process(pid).name()}\n{ip}:{port} - {pid}",
        )
        if body not in self._displayed_notifications:
            print("{} {}".format(title, body))
            self._displayed_notifications.append(body)

    def run(self):
        print("[+] Network Scanner Initialized")
        while self._running:
            self.update_current_connections()
            self.scan()
            time.sleep(self._timer)

    def stop(self):
        print("[-] Network Scanner Stopping")
        self._running = False


def is_binary(fp, chunksize=1024) -> bool:
    """Return true if the given filename is binary.
    @raise EnvironmentError: if the file does not exist or cannot be accessed.
    @attention: found @ http://bytes.com/topic/python/answers/21222-determine-file-type-binary-text on 6/08/2010
    @author: Trent Mick <TrentM@ActiveState.com>
    @author: Jorge Orpinel <jorge@orpinel.com>"""
    try:
        with open(fp, "rb") as f:
            while True:
                chunk = f.read(chunksize)
                if b"\0" in chunk:  # found null byte
                    return True
                if len(chunk) < chunksize:
                    break
    except PermissionError:
        print(f"Permission Error: {fp} {' ' * len(fp)}")
    return False


def reprint(s):
    print(s, end="")
    print("\r" * len(s), end="")


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("path", default=os.getcwd(), type=str, help="path to scan")
    parser.add_argument(
        "-u",
        "--update",
        action="store_true",
        default=False,
        help="updates database of virus definitions & high risk IP's",
    )
    parser.add_argument(
        "-t", "--threads", default=20, type=int, help="max threads for file scanner"
    )
    return parser.parse_args()


def Main():
    # Testing for now
    args = parse_args()
    if args.update:
        with DB() as db:
            print("[+] Updating database")
            db.update()
    nsc = NetworkScanner()
    nsc.start()
    FileScanner().scan(args.path, args.threads)
    nsc.stop()


if __name__ == "__main__":
    Main()
