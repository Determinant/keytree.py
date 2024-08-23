from setuptools import setup

setup(name='keytree.py',
      version='0.2',
      description='Derive BIP32 key pairs from BIP39 mnemonic',
      url='http://github.com/Determinant/keytree.py',
      author='Ted Yin',
      author_email='tederminant@gmail.com',
      license='MIT',
      scripts=['keytree.py'],
      py_modules=['bech32', 'mnemonic', 'shamir'],
      install_requires=['ecdsa', 'base58', 'pysha3', 'pycryptodomex'])
