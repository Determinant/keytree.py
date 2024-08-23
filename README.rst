keytree.py
==========

- Make sure you have Python = 3.10
- CD into the cloned repo

Examples
--------
- Derive 10 keys from a given mnemonic: ``./keytree.py --end-idx 10``
- Generate a new mnemonic, print 10 derived addresses from it, then also save the mnemonic to an encrypted keystore file: ``./keytree.py --end-idx 10 --gen-mnemonic --save mykeystore.json``
- Load the mnemonic from an existing keystore file: ``./keytree.py --load mykeystore.json``
- To see all private keys and the mnemonic phrase, use ``--show-private`` (only
  use it after you look around and ensure there is no one else looking at your
  screen)
- Use arbitrary UTF-8 string as your mnemonic ``./keytree.py --custom --save mykeystore.json``
- Show Fuji testnet address format ``./keytree.py <your options> --hrp fuji``
- Generate a new mnemonic and also use a 2/3 Shamir's secret sharing (3 shares, recoverable with any 2 of them): ``./keytree.py --gen-mnemonic --gen-shamir --shamir-threshold 2 --shamir-num 3``
- Recover a new mnemonic from the previous example and save it to a keystore file: ``./keytree.py --recover-shamir --shamir-threshold 2 --shamir-num 3 --save mykeystore.json``


Caveat
------
The above instructions use a frozen, full clone of all dependencies that is
shipped in this repo (more secure, recommended, only works on x86-64 Linux).
If you instead do a normal pip install (``pip3 install --user .``) and use
``keytree.py`` (without ``./`` prefix), it will use the latest deps fetched by
pip.

Security
--------

- The script was written with minimalist design (short, easy to check the code)
  . But you should use at your own risk and on an OS/platform/machine that you
  can trust. There is NO side-channel attack prevention or special treatment of
  the memory.

- The dependencies should be safe (but do your own check!) because the part under ``frozen_deps/`` only contains:

  - Some standard AES provided by ``pycryptodomex``
  - Curve manipulation provided by ``ecdsa``
  - Base58 encoding provided by ``base58``
  - Python 2 and 3 compatibility library ``six``
  - SHA3 calcuation provided by ``pysha3``

  Whereas web3-specific modules are pretty short:

  - ``mnemonic.py``: 284 lines, to generate/manipulate mnemonics
  - ``bech32.py``: 123 lines,  to Bech32-format addresses (for AVAX addresses)
  - ``shamir.py``: 113 lines, to implement a minimalist Shamir's secret sharing that's compatible with Ava Labs' implementation (https://github.com/ava-labs/mnemonic-shamir-secret-sharing-cli)

Portable Binary
---------------

Use ``./keytree-0.1.2-x86_64.AppImage`` in place of ``./keytree.py``.
