keytree.py
==========

- Make sure you have Python = 3.9
- CD into the cloned repo

Examples
--------
- Derive 10 keys from a given mnemonic: ``./keytree.py --end-idx 10``
- Generate a new mnemonic, print 10 derived addresses from it, then also save the mnemonic to an encrypted keystore file: ``./keytree.py --end-idx 10 --gen-mnemonic --save-keystore mykeystore.json``
- Load the mnemonic from an existing keystore file: ``./keytree.py --load-keystore mykeystore.json``
- To see all private keys and the mnemonic phrase, use ``--show-private`` (only
  use it after you look around and ensure there is no one else looking at your
  screen)
- Use arbitrary UTF-8 string as your mnemonic ``./keytree.py --custom-words --save-keystore mykeystore.json``

Caveat
------
The above instructions use a frozen, full clone of all dependencies that is
shipped in this repo (more secure, recommended, only works on x86-64 Linux).
If you instead do a normal pip install (``pip3 install --user .``) and use
``keytree.py`` (without ``./`` prefix), it will use the latest deps fetched by
pip.
