import base64
from bisect import bisect_left
from Crypto.Cipher import AES
from Crypto import Random

from .key import Key


class Vault:
    def __init__(self, keys, current):
        self.current_prefix = [key.prefix for key in keys if key.uid == current][0]
        self.keys = {key.prefix: key for key in keys}
        self.random = Random.new()

    def _key(self):
        return self.keys[self.current_prefix]

    def _getKey(self, prefix):
        try:
            return self.keys[prefix]
        except:
            raise ValueError('Unknown key')

    def _encrypt(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.encrypt(data)

    def _decrypt(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)

    def put(self, raw: bytes):
        key = self._key()
        iv = self.random.read(AES.block_size)
        return key.prefix + iv + self._encrypt(key.key, iv, raw)

    def get(self, token):
        prefix = token[:Key.PREFIX_SIZE]
        key = self._getKey(prefix)

        iv = token[Key.PREFIX_SIZE:Key.PREFIX_SIZE + AES.block_size]
        data = token[Key.PREFIX_SIZE + AES.block_size:]

        return self._decrypt(key.key, iv, data)

    def putInterned(self, raw: bytes):
        key = self._key()
        return key.prefix + self._encrypt(key.key, key.internedIV, raw)

    def putInternedAll(self, raw: bytes):
        result = []
        for key in self.keys.values():
            result.append(key.prefix + self._encrypt(key.key, key.internedIV, raw))
        return result

    def getInterned(self, token: bytes):
        prefix = token[:Key.PREFIX_SIZE]
        key = self._getKey(prefix)
        data = token[Key.PREFIX_SIZE:]
        return self._decrypt(key.key, key.internedIV, data)

    def putPAN(self, pan: str):
        if len(pan) % 2 == 1:
            pan += 'f'
        raw = bytes.fromhex(pan)
        token = self.putInterned(raw)
        return base64.b64encode(token).decode('utf-8')

    # FIXME: needs a better name
    def putAllPAN(self, pan: str):
        if len(pan) % 2 == 1:
            pan += 'f'
        raw = bytes.fromhex(pan)
        tokens = self.putInternedAll(raw)
        return [base64.b64encode(token).decode('utf-8') for token in tokens]

    def getPAN(self, token: str):
        raw_token = base64.b64decode(token)
        raw = self.getInterned(raw_token)
        pan = raw.hex()
        if pan[-1].lower() == 'f':
            return pan[:-1]
        return pan

    def putString(self, s: str):
        raw = s.encode('utf-8')
        token = self.put(raw)
        return base64.b64encode(token).decode('utf-8')

    def getString(self, token: str):
        raw_token = base64.b64decode(token)
        raw = self.get(raw_token)
        return raw.decode('utf-8')
