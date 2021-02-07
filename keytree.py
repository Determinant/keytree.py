#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2020 Ted Yin <tederminant@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# This little script offers decryption and verification of the existing
# Ethereum wallets, as well as generation of a new wallet. You can use any
# utf-8 string as the password, which could provide with better security
# against the brute-force attack.

# Use at your own risk.
#
# Example:
# python3 ./keytree.py

import os
import sys
if sys.version_info[1] < 7:
    sys.write("Python should be >= 3.7")
    sys.exit(1)
basedir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, basedir + "/frozen_deps")

import re
import argparse
import hashlib
import hmac
import unicodedata
import json
from getpass import getpass

import bech32
import mnemonic
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.ecdsa import generator_secp256k1
from ecdsa.ellipticcurve import INFINITY
from base58 import b58encode, b58decode
from sha3 import keccak_256
from Cryptodome.Cipher import AES


def sha256(data):
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


class KeytreeError(Exception):
    pass


class BIP32Error(KeytreeError):
    pass


# point(p): returns the coordinate pair resulting from EC point multiplication
# (repeated application of the EC group operation) of the secp256k1 base point
# with the integer p.
def point(p):
    return generator_secp256k1 * p


# ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most
# significant byte first.
def ser32(i):
    return i.to_bytes(4, byteorder='big')


# ser256(p): serializes the integer p as a 32-byte sequence, most significant
# byte first.
def ser256(p):
    return p.to_bytes(32, byteorder='big')


# serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using
# SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte
# depends on the parity of the omitted y coordinate.
def serP(P):
    if P.y() & 1 == 0:
        parity = b'\x02'
    else:
        parity = b'\x03'
    return parity + ser256(P.x())


def is_infinity(P):
    return P == INFINITY


# parse256(p): interprets a 32-byte sequence as a 256-bit number, most
# significant byte first.
def parse256(p):
    assert(len(p) == 32)
    return int.from_bytes(p, byteorder='big')


def iH(x):
    return x + (1 << 31)


n = generator_secp256k1.order()
rformat = re.compile(r"^[0-9]+'?$")


def ckd_pub(K_par, c_par, i):
    if i >= 1 << 31:
        raise BIP32Error("the child is a hardended key")
    I = hmac.digest(
        c_par, serP(K_par) + ser32(i), 'sha512')
    I_L, I_R = I[:32], I[32:]
    K_i = point(parse256(I_L)) + K_par
    c_i = I_R
    if parse256(I_L) >= n or is_infinity(K_i):
        raise BIP32Error("invalid i")
    return K_i, c_i

def ckd_prv(k_par, c_par, i):
    if i >= 1 << 31:
        I = hmac.digest(
            c_par, b'\x00' + ser256(k_par) + ser32(i), 'sha512')
    else:
        I = hmac.digest(
            c_par, serP(point(k_par)) + ser32(i), 'sha512')
    I_L, I_R = I[:32], I[32:]
    k_i = (parse256(I_L) + k_par) % n
    c_i = I_R
    if parse256(I_L) >= n or k_i == 0:
        raise BIP32Error("invalid i")
    return k_i, c_i

class BIP32:
    path_error = BIP32Error("unsupported BIP32 path format")

    def __init__(self, seed, key="Bitcoin seed"):
        I = hmac.digest(b"Bitcoin seed", seed, 'sha512')
        I_L, I_R = I[:32], I[32:]
        self.m = parse256(I_L)
        self.M = SigningKey.from_string(I_L, curve=SECP256k1) \
            .get_verifying_key().pubkey.point
        self.c = I_R

    def derive(self, path="m"):
        tokens = path.split('/')
        if tokens[0] == "m":
            k = self.m
            c = self.c
            for r in tokens[1:]:
                if not rformat.match(r):
                    raise self.path_error
                if r[-1] == "'":
                    i = iH(int(r[:-1]))
                else:
                    i = int(r)
                k, c = ckd_prv(k, c, i)
            return SigningKey.from_string(k.to_bytes(32, byteorder='big'), curve=SECP256k1)
        elif tokens[0] == "M":
            K = self.M
            c = self.c
            for r in tokens[1:]:
                if not rformat.match(r):
                    raise self.path_error
                if r[-1] == "'":
                    i = iH(int(r[:-1]))
                else:
                    i = int(r)
                K, c = ckd_pub(K, c, i)
            return VerifyingKey.from_public_point(K, curve=SECP256k1)
        else:
            raise self.path_error

def get_eth_addr(pk):
    pub_key = pk.to_string()
    m = keccak_256()
    m.update(pub_key)
    return m.hexdigest()[24:]

def get_privkey_btc(sk):
    priv_key = b'\x80' + sk.to_string()
    checksum = sha256(sha256(priv_key))[:4]
    return b58encode(priv_key + checksum).decode("utf-8")

def get_btc_addr(pk):
    h = b'\x00' + ripemd160(sha256(b'\x04' + pk.to_string()))
    checksum = sha256(sha256(h))[:4]
    h += checksum
    return b58encode(h).decode("utf-8")

def load_from_keystore(filename):
    try:
        with open(filename, "r") as f:
            try:
                parsed = json.load(f)
                ciphertext = b58decode(parsed['keys'][0]['key'])[:-4]
                iv = b58decode(parsed['keys'][0]['iv'])[:-4]
                salt = b58decode(parsed['salt'])[:-4]
                tag = b58decode(parsed['pass_hash'])[:-4]
                passwd = getpass('Enter the password to unlock keystore: ').encode('utf-8')
                key = hashlib.pbkdf2_hmac(
                        'sha256',
                        sha256(passwd + salt), salt, 200000)
                a = AES.new(key,
                              mode=AES.MODE_GCM,
                              nonce=iv).update(salt)
                if tag != sha256(passwd + sha256(passwd + salt)):
                    raise KeytreeError("incorrect keystore password")
                return a.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:]).decode('utf-8')
            except KeytreeError as e:
                raise e
            except:
                raise KeytreeError("invalid or corrupted keystore file")
    except FileNotFoundError:
        raise KeytreeError("failed to open file")


def cb58encode(raw):
    checksum = sha256(raw)[-4:]
    return b58encode(raw + checksum).decode('utf-8')


def save_to_keystore(filename, words):
    try:
        with open(filename, "w") as f:
            passwd = getpass('Enter the password for saving (utf-8): ').encode('utf-8')
            passwd2 = getpass('Enter the password again (utf-8): ').encode('utf-8')
            if passwd != passwd2:
                raise KeytreeError("mismatching passwords")
            iv = os.urandom(12)
            salt = os.urandom(16)
            pass_hash = sha256(passwd + sha256(passwd + salt))
            key = hashlib.pbkdf2_hmac(
                    'sha256',
                    sha256(passwd + salt), salt, 200000)
            a = AES.new(key,
                          mode=AES.MODE_GCM,
                          nonce=iv).update(salt)
            (c, t) = a.encrypt_and_digest(words.encode('utf-8'))
            ciphertext = c + t
            json.dump({
                'version': "5.0",
                'keys': [
                    {'key': cb58encode(ciphertext), 'iv': cb58encode(iv)}],
                'salt': cb58encode(salt),
                'pass_hash': cb58encode(pass_hash)
            }, f)
    except FileNotFoundError:
        raise KeytreeError("failed while saving")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Derive BIP32 key pairs from BIP39 mnemonic')
    parser.add_argument('--load-keystore', type=str, default=None, help='load mnemonic from a keystore file (AVAX Wallet compatible)')
    parser.add_argument('--save-keystore', type=str, default=None, help='save mnemonic to a keystore file (AVAX Wallet compatible)')
    parser.add_argument('--show-private', action='store_true', default=False, help='also show private keys and the mnemonic')
    parser.add_argument('--custom-words', action='store_true', default=False, help='use an arbitrary word combination as mnemonic')
    parser.add_argument('--account-path', default="44'/9000'/0'/0", help="path prefix for key deriving (e.g. \"0/1'/2\")")
    parser.add_argument('--gen-mnemonic', action='store_true', default=False, help='generate a mnemonic (instead of taking an input)')
    parser.add_argument('--lang', type=str, default="english", help='language for mnemonic words')
    parser.add_argument('--start-idx', type=int, default=0, help='the start index for keys')
    parser.add_argument('--end-idx', type=int, default=1, help='the end index for keys (exclusive)')
    parser.add_argument('--hrp', type=str, default="avax", help='HRP (Human Readable Prefix, defined by Bech32)')

    args, _ = parser.parse_known_args()
    

    try:
        try:
            if args.gen_mnemonic:
                mgen = mnemonic.Mnemonic(args.lang)
                words = mgen.generate(256)
            else:
                if args.load_keystore:
                    words = load_from_keystore(args.load_keystore)
                else:
                    words = getpass('Enter the mnemonic: ').strip()
                    if not args.custom_words:
                        mchecker = mnemonic.Mnemonic(args.lang)
                        if not mchecker.check(words):
                            raise KeytreeError("invalid mnemonic")
        except FileNotFoundError:
            raise KeytreeError("invalid language")
        if args.show_private or args.gen_mnemonic:
            print("KEEP THIS PRIVATE: {}".format(words))
        seed = hashlib.pbkdf2_hmac('sha512', unicodedata.normalize('NFKD', words).encode("utf-8"), b"mnemonic", 2048)
        gen = BIP32(seed)
        if args.start_idx < 0 or args.end_idx < 0:
            raise KeytreeError("invalid start/end index")
        for i in range(args.start_idx, args.end_idx):
            path = "m/{}/{}".format(args.account_path, i)
            priv = gen.derive(path)
            pub = priv.get_verifying_key()
            cpub = pub.to_string(encoding="compressed")
            if args.show_private:
                print("{}.priv(raw/ETH) 0x{}".format(i, priv.to_string().hex()))
                print("{}.priv(BTC) {}".format(i, get_privkey_btc(priv)))
            print("{}.addr(AVAX) X-{}".format(i, bech32.bech32_encode(args.hrp, bech32.convertbits(ripemd160(sha256(cpub)), 8, 5))))
            print("{}.addr(BTC) {}".format(i, get_btc_addr(pub)))
            print("{}.addr(ETH) {}".format(i, get_eth_addr(pub)))
        if args.save_keystore:
            save_to_keystore(args.save_keystore, words)
            print("Saved to keystore file: {}".format(args.save_keystore))
    except KeytreeError as e:
        sys.stderr.write("error: {}\n".format(str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
