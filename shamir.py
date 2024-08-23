# Code modified from https://github.com/kurtbrose/shamir/tree/master (under CC0
# license, so we took liberty to refactor it here)

import secrets

# use the prime to be compatible with the Shamir tool developed by Ava Labs:
# https://github.com/ava-labs/mnemonic-shamir-secret-sharing-cli/tree/main
# This is a 257-bit prime, so the returned points could be either 256-bit or
# (infrequently) 257-bit.
_PRIME = 187110422339161656731757292403725394067928975545356095774785896842956550853219
# Other good choices:
# 12th Mersenne Prime is 2**127 - 1
# 13th Mersenne Prime is 2**521 - 1


def split(secret, minimum, shares, prime=_PRIME):
    def y(poly, x, prime):
        # evaluate polynomial (coefficient tuple) at x
        accum = 0
        for coeff in reversed(poly):
            accum *= x
            accum += coeff
            accum %= prime
        return accum

    if minimum > shares:
        raise ValueError("pool secret would be irrecoverable")
    poly = [secrets.randbelow(prime) for i in range(minimum - 1)]
    poly.insert(0, secret)
    return [y(poly, i, prime) for i in range(1, shares + 1)]


# division in integers modulus p means finding the inverse of the denominator
# modulo p and then multiplying the numerator by this inverse
# (Note: inverse of A is B such that A*B % p == 1)
# this can be computed via extended euclidean algorithm
# http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
def _extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b,  a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod(num, den, p):
    '''
    compute num / den modulo prime p
    To explain what this means, the return
    value will be such that the following is true:
    den * _divmod(num, den, p) % p == num
    '''
    inv, _ = _extended_gcd(den, p)
    return num * inv


def _lagrange_interpolate(x, x_s, y_s, p):
    '''
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order
    '''
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"

    def prod(vals):  # product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(prod(x - o for o in others))
        dens.append(prod(cur - o for o in others))
    den = prod(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p


def combine(shares, prime=_PRIME):
    '''
    Recover the secret from share points
    (shares contain (x, y) as points on the polynomial)
    '''
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)
