#coding: utf8

# some code copy from https://github.com/ifduyue/xxtea

def btea(v, n, k):
    if not isinstance(v, list) or \
        not isinstance(n, int) or \
        not isinstance(k, (list, tuple)):
        return False

    MX = lambda: ((z>>5)^(y<<2)) + ((y>>3)^(z<<4))^(sum^y) + (k[(p & 3)^e]^z)
    u32 = lambda x: x & 0xffffffff

    y = v[0]
    sum = 0
    DELTA = 0x9e3779b9
    if n > 1:
        z = v[n-1]
        q = 6 + 52 / n
        while q > 0:
            q -= 1
            sum = u32(sum + DELTA)
            e = u32(sum >> 2) & 3
            p = 0
            while p < n - 1:
                y = v[p+1]
                z = v[p] = u32(v[p] + MX())
                p += 1
            y = v[0]
            z = v[n-1] = u32(v[n-1] + MX())
        return True
    elif n < -1:
        n = -n
        q = 6 + 52 / n
        sum = u32(q * DELTA)
        while sum != 0:
            e = u32(sum >> 2) & 3
            p = n - 1
            while p > 0:
                z = v[p-1]
                y = v[p] = u32(v[p] - MX())
                p -= 1
            z = v[n-1]
            y = v[0] = u32(v[0] - MX())
            sum = u32(sum - DELTA)
        return True
    return False


def str2longs(s):
    length = (len(s) + 3) / 4
    result = []
    for i in xrange(length):
        j = 0
        j |= ord(s[i*4])
        j |= ord(s[i*4+1])<<8
        j |= ord(s[i*4+2])<<16
        j |= ord(s[i*4+3])<<24
        result.append(j)
    return result

def longs2str(s):
    result = ""
    for c in s:
        result += chr(c&0xFF) + chr(c>>8&0xFF)\
               + chr(c>>16&0xFF) + chr(c>>24&0xFF)
    return result

def pkcs5_padding(text, blocksize = 4):
    if len(text) < 8 and blocksize != 8:
        return pkcs5_padding(text, 8)
    padding = blocksize - len(text) % blocksize
    return text + chr(padding) * padding

def pkcs5_unpadding(text):
    length = len(text)
    unpadding = ord(text[-1])
    return text[:length - unpadding]

def encrypt(text, key):
    assert len(key) == 16
    text = str2longs(pkcs5_padding(v))
    btea(text, len(text), str2longs(key))
    return longs2str(text)

def decrypt(text, key):
    assert len(key) == 16
    text = str2longs(text)
    btea(text, -len(text), str2longs(key))
    return pkcs5_unpadding(longs2str(text))


if __name__ == '__main__':
    k = '1234567890123456'
    v = "hello"
    t = encrypt(v, k)
    for i in t:
        print ord(i)
    print t
    v = decrypt(t, k)
    print v
