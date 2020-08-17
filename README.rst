keytree.py
==========

- Make sure you have Python >= 3.7
- CD into the cloned repo
- Derive 10 keys from the given mnemonic: ``./keytree.py --end-idx 10``
- Generate a new mnemonic and derive 10 keys from it: ``./keytree.py --end-idx 10 --gen-mnemonic``
- Caveat: the above instructions use a freezed, full clone of all dependencies
  (recommended).  If you instead do a normal pip install and use
  ``keytree.py`` (without ``./`` prefix), it will use the latest deps fetched
  by pip.
