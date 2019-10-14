#!/usr/bin/env python

import os
import hashlib
import sqlite3
import requests
from bs4 import BeautifulSoup

from progressbar import progressbar
from binaryornot.check import is_binary

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
        self.cur.execute('CREATE TABLE IF NOT EXISTS virus_hashes(hash TEXT NOT NULL UNIQUE)')
        self.cur.execute('CREATE TABLE IF NOT EXISTS processed_urls(url TEXT NOT NULL UNIQUE)')
        self.conn.commit()

    def drop_tables(self):
        self.cur.execute('DROP TABLE IF EXISTS virus_hashes')
        self.cur.execute('DROP TABLE IF EXISTS processed_urls')
        self.conn.commit()

    def add_hash(self, hash):
        '''
        adds hash to the database of known virus hashes
        '''
        try:
            self.cur.execute('INSERT INTO virus_hashes VALUES (?)', (hash,))
        except sqlite3.IntegrityError as e:
            if 'UNIQUE' in str(e):
                pass # Do nothing if trying to add a hash that already exists in the db
            else:
                print(e)
                raise sqlite3.IntegrityError

    def add_processed_url(self, url):
        '''
        adds a url to the database of processed urls (url containing a list of known virus hashes)
        '''
        self.cur.execute('INSERT INTO processed_urls VALUES (?)', (url,))

    def is_known_hash(self, hash) -> bool:
        '''
        checks hash against the db to determine if the hash is a known virus hash
        '''
        # TODO: TESTME
        self.cur.execute('SELECT hash FROM virus_hashes WHERE hash = (?)', (hash,))
        if self.cur.fetchone() is None:
            return False
        return True

    def is_processed_url(self, url) -> bool:
        # TODO: TESTME
        self.cur.execute('SELECT url FROM processed_urls WHERE url = (?)', (url,))
        if self.cur.fetchone() is None:
            return False
        return True

    def reformat(self):
        self.drop_tables()
        self.create_tables()
        self.update()

    def update(self):
        urls = self.get_virusshare_urls()
        for url in progressbar(urls, prefix="Updating Virus Definitions  "):
            if not self.is_processed_url(url):
                hash_gen = self.get_virusshare_hashes(url)
                while True:
                    try:
                        hash = next(hash_gen)
                        self.add_hash(hash)
                    except StopIteration:
                        break
                self.add_processed_url(url)
            self.conn.commit()

    def get_virusshare_urls(self) -> list:
        r = requests.get('https://virusshare.com/hashes.4n6')
        soup = BeautifulSoup(r.content, 'html.parser')
        return ["https://virusshare.com/{}".format(a['href']) for a in soup.find_all('a')][6:-2]

    def get_virusshare_hashes(self, url) -> str:
        '''
        Gets all the hashes from virusshare.com
        '''
        r = requests.get(url)
        for md5_hash in r.text.splitlines()[6:]:
            yield md5_hash


class FileScanner(object):
    def __init__(self, dir):
        self.dir = dir
        self.running = False
        self.files_to_scan = []
        self.bad_files = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def get_files_to_scan(self, dir) -> list:
        for subdirs, dirs, files in os.walk(dir):
            for f in files:
                if not self.is_directory(f) and is_binary(f):
                    self.files_to_scan.append(os.path.abspath(f))

    def get_md5(self, fp) -> str:
        hash_md5 = hashlib.md5()
        with open(fp, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def compare_against_database(self, fp, db):
        md5 = self.get_md5(fp)
        if db.is_known_hash(md5):
            self.bad_files.append(os.path.abspath(fp))

    def is_directory(self, fp) -> bool:
        return os.path.isdir(fp)

    def stop(self):
        self.running = False
        self.db.close()

    def start(self):
        self.running = True
        self.db = DB()
        self.get_files_to_scan(self.dir)
        for fp in self.files_to_scan:
            self.compare_against_database(fp, db)

    def run(self):
        self.start()


if __name__ == '__main__':
    # Testing for now
    with DB() as db:
        db.update()

