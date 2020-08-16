keytree
=======

- CD into the cloned repo
- Derive 10 keys from the given mnemonic: ``./keytree.py --end-idx 10``
- Generate a new mnemonic and derive 10 keys from it: ``./keytree.py --end-idx 10 --gen-mnemonic``
- Caveat: if you instead do a normal pip install and use ``keytree.py``, it will use the latest deps fetched by pip.
