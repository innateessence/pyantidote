#!/usr/bin/env python

from antidote import DB

def test_known_hash():
    print("[T] db.exists: ", end='')
    known_hashes = ['781770fda3bd3236d0ab8274577dddde', '86b6c59aa48a69e16d3313d982791398', '42914d6d213a20a2684064be5c80ffa9']
    unknown_hashes = ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'ccccccccccccccccccccccccccccccc']
    with DB() as db:
        for known_hash in known_hashes:
            assert db.exists('md5_hash', 'virus_md5_hashes', known_hash) is True
        for unknown_hash in unknown_hashes:
            assert db.exists('md5_hash', 'virus_md5_hashes', unknown_hash) is False
    print("Success")


test_known_hash()
