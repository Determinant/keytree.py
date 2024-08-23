#!/usr/bin/env python3.10
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
from getpass import getpass as _getpass
from itertools import zip_longest

import bech32
import mnemonic
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.ecdsa import generator_secp256k1
from ecdsa.ellipticcurve import INFINITY
from base58 import b58encode, b58decode
from sha3 import keccak_256
from uuid import uuid4
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import shamir


def getpass(prompt):
    if sys.stdin.isatty():
        return _getpass(prompt)
    else:
        return sys.stdin.readline()


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
    assert len(p) == 32
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
                version = parsed['version']
                try:
                    if parsed['keys'][0]['type'] != 'mnemonic':
                        raise KeytreeError("not a mnemonic keystore file")
                except KeyError:
                    pass
                ciphertext = b58decode(parsed['keys'][0]['key'])[:-4]
                iv = b58decode(parsed['keys'][0]['iv'])[:-4]
                salt = b58decode(parsed['salt'])[:-4]
                passwd = getpass('Enter the password to unlock keystore: ').encode('utf-8')
                key = hashlib.pbkdf2_hmac(
                        'sha256',
                        sha256(passwd + salt), salt, 200000)
                a = AES.new(key,
                              mode=AES.MODE_GCM,
                              nonce=iv).update(salt)
                if version == '5.0':
                    tag = b58decode(parsed['pass_hash'])[:-4]
                    if tag != sha256(passwd + sha256(passwd + salt)):
                        raise KeytreeError("incorrect keystore password")
                try:
                    return a.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:]).decode('utf-8')
                except:
                    raise KeytreeError("incorrect keystore password")
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
            # pass_hash = sha256(passwd + sha256(passwd + salt))
            key = hashlib.pbkdf2_hmac(
                    'sha256',
                    sha256(passwd + salt), salt, 200000)
            a = AES.new(key,
                          mode=AES.MODE_GCM,
                          nonce=iv).update(salt)
            (c, t) = a.encrypt_and_digest(words.encode('utf-8'))
            ciphertext = c + t
            json.dump({
                'version': "6.0",
                'activeIndex': 0,
                'keys': [
                    {
                        'key': cb58encode(ciphertext),
                        'iv': cb58encode(iv),
                        'type': 'mnemonic'
                    }],
                'salt': cb58encode(salt),
                # 'pass_hash': cb58encode(pass_hash)
            }, f)
    except FileNotFoundError:
        raise KeytreeError("failed while saving")


# MEW keystore format (version 3.0)
def save_to_mew(priv_keys, n=1 << 18, p=1, r=8, dklen=32):
    try:
        passwd = getpass('Enter the password for saving (utf-8): ').encode('utf-8')
        passwd2 = getpass('Enter the password again (utf-8): ').encode('utf-8')
        if passwd != passwd2:
            raise KeytreeError("mismatching passwords")

        for priv_key in priv_keys:
            addr = get_eth_addr(priv_key.get_verifying_key())
            priv_key = priv_key.to_string()
            with open("mew-{}.json".format(addr), "w") as f:
                iv = os.urandom(16)
                salt = os.urandom(16)

                m = 128 * r * (n + p + 2)
                dk = hashlib.scrypt(passwd, salt=salt,
                                    n=n, r=r, p=p, dklen=dklen, maxmem=m)
                obj = AES.new(dk[:dklen >> 1],
                              mode=AES.MODE_CTR,
                              counter=Counter.new(
                                    128,
                                    initial_value=int.from_bytes(iv, 'big')))
                enc_pk = obj.encrypt(priv_key)

                # generate MAC
                h = keccak_256()
                h.update(dk[len(dk) >> 1:])
                h.update(enc_pk)
                mac = h.digest()

                crypto = {
                    'ciphertext': enc_pk.hex(),
                    'cipherparams': {'iv': iv.hex()},
                    'cipher': 'aes-128-ctr',
                    'kdf': 'scrypt',
                    'kdfparams': {'dklen': dklen,
                                  'salt': salt.hex(),
                                  'n': n,
                                  'r': r,
                                  'p': p},
                    'mac': mac.hex()}
                json.dump({
                    'version': 3,
                    'id': str(uuid4()),
                    'address': addr,
                    'Crypto': crypto}, f)
    except FileNotFoundError:
        raise KeytreeError("failed while saving")


def to_chunks(n, iterable):
    return zip_longest(*[iter(iterable)]*n, fillvalue=0)

def shamir256_split(secret, t, n):
    shares = [bytearray() for i in range(n)]
    for chunk in to_chunks(32, secret):
        secret = int.from_bytes(chunk, 'big')
        while True:
            points = shamir.split(secret, t, n)
            good = True
            for p in points:
                if p.bit_length() > 256:
                    good = False
                    break
            if good:
                # all shares are within 256 bits
                for (p, s) in zip(points, shares):
                    s.extend(p.to_bytes(32, 'big'))
                break
    return shares


def shamir256_combine(shares):
    result = bytearray()
    for shares in zip(*[[(i, g) for g in to_chunks(32, s)] for (i, s) in shares]):
        shares = [(i, int.from_bytes(bytearray(p), 'big')) for (i, p) in shares]
        try:
            secret = shamir.combine(shares)
        except ValueError:
            raise KeytreeError("invalid Shamir recovery input")
        if secret.bit_length() > 256:
            raise KeytreeError("Shamir result is too long")
        result.extend(secret.to_bytes(32, 'big'))
    return result


metamask_path = r"44'/60'/0'/0"
avax_path = r"44'/9000'/0'/0"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Derive BIP32 key pairs from BIP39 mnemonic')
    parser.add_argument('--load', type=str, default=None, help='load mnemonic from a file (AVAX Wallet compatible)')
    parser.add_argument('--save', type=str, default=None, help='save mnemonic to a file (AVAX Wallet compatible)')
    parser.add_argument('--export-mew', action='store_true', default=False, help='export keys to MEW keystore files (mnemonic is NOT saved, only keys are saved)')
    parser.add_argument('--show-private', action='store_true', default=False, help='also show private keys and the mnemonic')
    parser.add_argument('--gen-shamir', action='store_true', default=False, help='generate Shamir\'s secret shares')
    parser.add_argument('--shamir-threshold', type=int, default=2, help='Shamir\'s secret sharing threshold (number of shares to decode)')
    parser.add_argument('--shamir-num', type=int, default=3, help='Shamir\'s secret sharing number (total number of shares)')
    parser.add_argument('--recover-shamir', type=str, default=None, help='recover the secret from Shamir shares')
    parser.add_argument('--custom', action='store_true', default=False, help='use an arbitrary word combination as mnemonic')
    parser.add_argument('--seed', action='store_true', default=False, help='load mnemonic from seed')
    parser.add_argument('--path', default=avax_path, help="path prefix for key deriving (e.g. \"{}\" for Metamask)".format(metamask_path))
    parser.add_argument('--metamask', action='store_true', default=False, help="use metamask path for key deriving (synonym to `--path \"{}\"`)".format(metamask_path))
    parser.add_argument('--gen-mnemonic', action='store_true', default=False, help='generate a mnemonic (instead of taking an input)')
    parser.add_argument('--lang', type=str, default="english", help='language for mnemonic words')
    parser.add_argument('--start-idx', type=int, default=0, help='the start index for keys')
    parser.add_argument('--end-idx', type=int, default=1, help='the end index for keys (exclusive)')
    parser.add_argument('--hrp', type=str, default="avax", help='HRP (Human Readable Prefix, defined by Bech32)')

    args, unknown = parser.parse_known_args()

    try:
        for arg in unknown:
            if len(arg) > 0:
                raise KeytreeError("invalid argument: `{}`".format(arg))
        mgen = mnemonic.Mnemonic(args.lang)
        words = None
        seed = None
        # here, we check the flags to see how to obtain the mnemonic phrase or just the derived seed of it:
        if args.gen_mnemonic:
            # generate a new mnemonic
            words = mgen.generate(256)
        elif args.load:
            # load from a JSON keystore file
            try:
                words = load_from_keystore(args.load)
            except FileNotFoundError:
                raise KeytreeError("invalid language")
        elif args.recover_shamir:
            # recover from a previously set up Shamir's secret sharing
            try:
                idxes = [int(i) for i in args.recover_shamir.split(',')]
            except ValueError:
                raise KeytreeError("invalid Shamir sharing spec, should be something like \"1,2\"")
            custom_mnemonic = None
            shares = []
            for idx in idxes:
                swords = getpass('Enter the mnemonic for Shamir share #{}: '.format(idx)).split()
                try:
                    if len(swords) == 48:
                        if custom_mnemonic == False:
                            raise KeytreeError("invalid Shamir share format")
                        custom_mnemonic = True
                        share = mgen.to_entropy(' '.join(swords[:24])) + mgen.to_entropy(' '.join(swords[24:]))
                    else:
                        if custom_mnemonic == True:
                            raise KeytreeError("invalid Shamir share format")
                        custom_mnemonic = False
                        share = mgen.to_entropy(' '.join(swords))
                except (ValueError, LookupError):
                    raise KeytreeError('invalid mnemonic')
                shares.append((idx, share))
            if custom_mnemonic:
                seed = shamir256_combine(shares)
            else:
                words = mgen.to_mnemonic(shamir256_combine(shares))
        elif args.seed:
            seedstr = getpass('Enter the seed: ').strip()
            try:
                seed = bytes.fromhex(seedstr)
                if len(seed) != 64:
                    raise ValueError
            except ValueError:
                raise KeytreeError("invalid seed")
        else:
            words = getpass('Enter the mnemonic: ').strip()
            if not args.custom:
                mchecker = mnemonic.Mnemonic(args.lang)
                if not mchecker.check(words):
                    raise KeytreeError("invalid mnemonic")

        if seed is None:
            seed = hashlib.pbkdf2_hmac('sha512', unicodedata.normalize('NFKD', words).encode("utf-8"), b"mnemonic", 2048)

        if args.end_idx < args.start_idx:
            args.end_idx = args.start_idx + 1

        if args.show_private or args.gen_mnemonic:
            if words is not None:
                print("KEEP THIS PRIVATE (mnemonic): {}".format(words))
            print("KEEP THIS PRIVATE (seed): {}".format(seed.hex()))

        # generate Shamir shares if the user says so

        if args.shamir_threshold:
            if args.shamir_num > 20:
                raise KeytreeError('Shamir threshold should be <= 20')
            if args.shamir_threshold < 2 or args.shamir_threshold > args.shamir_num:
                raise KeytreeError('Shamir threshold should be (2, N]')

        if args.gen_shamir:
            try:
                entropy = mgen.to_entropy(words)
            except (ValueError, LookupError):
                # not a standard BIP mnemonic, let's fallback to seed mode
                entropy = None
            if entropy:
                shares = shamir256_split(mgen.to_entropy(words), args.shamir_threshold, args.shamir_num)
                for idx, share in enumerate(shares):
                    print("KEEP THIS PRIVATE (share) #{} {}".format(idx + 1, mgen.to_mnemonic(share)))
            else:
                shares = shamir256_split(seed, args.shamir_threshold, args.shamir_num)
                for idx, share in enumerate(shares):
                    words = mgen.to_mnemonic(share[:32]) + ' ' + mgen.to_mnemonic(share[32:])
                    print("KEEP THIS PRIVATE (share) #{} {}".format(idx + 1, words))

        # derive the keys at the requested paths

        gen = BIP32(seed)
        if args.start_idx < 0 or args.end_idx < 0:
            raise KeytreeError("invalid start/end index")
        keys = []
        for i in range(args.start_idx, args.end_idx):
            path = "m/{}/{}".format(metamask_path if args.metamask else args.path, i)
            priv = gen.derive(path)
            keys.append(priv)
            pub = priv.get_verifying_key()
            cpub = pub.to_string(encoding="compressed")
            if args.show_private:
                print("{}.priv(raw/ETH/AVAX-X) 0x{}".format(i, priv.to_string().hex()))
                print("{}.priv(BTC) {}".format(i, get_privkey_btc(priv)))
            print("{}.addr(AVAX-X/P) {}".format(i, bech32.bech32_encode(args.hrp, bech32.convertbits(ripemd160(sha256(cpub)), 8, 5))))

            path2 = "m/{}/{}".format(metamask_path, i)
            priv2 = gen.derive(path2)
            pub2 = priv2.get_verifying_key()
            if args.show_private:
                print("{}.priv(AVAX-C) 0x{}".format(i, priv2.to_string().hex()))
            print("{}.addr(AVAX-C) 0x{}".format(i, get_eth_addr(pub2)))

            print("{}.addr(BTC) {}".format(i, get_btc_addr(pub)))
            print("{}.addr(ETH) 0x{}".format(i, get_eth_addr(pub)))
        if args.export_mew:
            save_to_mew(keys)
        if args.save:
            save_to_keystore(args.save, words)
            print("Saved to keystore file: {}".format(args.save))
    except KeytreeError as e:
        sys.stderr.write("error: {}\n".format(str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
