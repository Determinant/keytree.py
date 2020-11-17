keytree.py
==========

- Make sure you have Python >= 3.7
- CD into the cloned repo
- Make sure dependencies are installed: ``pip3 install --user .``
- Derive 10 keys from the given mnemonic: ``./keytree.py --end-idx 10``
- Generate a new mnemonic and derive 10 keys from it: ``./keytree.py --end-idx 10 --gen-mnemonic``
- You can also load the mnemonic from an existing JSON keystore file (generated
  by the official AVAX Wallet): ``./keytree.py --from-avax-keystore``.
- To see all private keys and the mnemonic phrase, use ``--show-private`` (only
  use it after you look around and ensure there is no one else looking at your
  screen).
- Caveat: the above instructions use a frozen, full clone of all dependencies
  (recommended).  If you instead do a normal pip install and use
  ``keytree.py`` (without ``./`` prefix), it will use the latest deps fetched
  by pip.
