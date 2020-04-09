import base64
import datetime
from bisect import bisect_left
from Crypto.Cipher import AES
from Crypto import Random

from .key import Key

class Vault:
    def __init__(self, keys):

        self.prefix_lookup = {key.prefix: key for key in keys}
        self.keys = sorted(keys, key=lambda key: key.start_at)
        self.key_lookup = [key.start_at for key in self.keys]
        self.random = Random.new()

    def _currentKey(self):
        now = datetime.datetime.now()
        i = bisect_left(self.key_lookup, now)
        if i:
            return self.keys[i - 1]
        raise ValueError('No key is currently active')
    def _getKey(self, prefix):
        try:
            return self.prefix_lookup[prefix]
        except:
            raise ValueError('Unknown key')

    def _encrypt(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.encrypt(data)

    def _decrypt(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)

    def put(self, raw):
        key = self._currentKey()
        iv = self.random.read(AES.block_size)
        return key.prefix + iv + self._encrypt(key.key, iv, raw)

    def get(self, token):
        prefix = token[:Key.PREFIX_SIZE]
        key = self._getKey(prefix)

        iv = token[Key.PREFIX_SIZE:Key.PREFIX_SIZE + AES.block_size]
        data = token[Key.PREFIX_SIZE + AES.block_size:]

        return self._decrypt(key.key, iv, data)

    def putInterned(self, raw):
        key = self._currentKey()
        return key.prefix + self._encrypt(key.key, key.internedIV, raw)

    def getInterned(self, token):
        prefix = token[:Key.PREFIX_SIZE]
        key = self._getKey(prefix)
        data = token[Key.PREFIX_SIZE:]
        return self._decrypt(key.key, key.internedIV, data)

    def putPAN(self, pan):
        if len(pan) % 2 == 1:
            pan += 'f'
        raw = bytes.fromhex(pan)
        token = self.putInterned(raw)
        return base64.b64encode(token).decode('utf-8')

    def getPAN(self, token):
        raw_token =  base64.b64decode(token)
        raw = self.getInterned(raw_token)
        pan = raw.hex()
        if pan[-1].lower() == 'f':
            return pan[:-1]
        return pan
            
    def putString(self, s):
        raw = s.encode('utf-8')
        token = self.put(raw)
        return base64.b64encode(token).decode('utf-8')

    def getString(self, token):
        raw_token =  base64.b64decode(token)
        raw = self.get(raw_token)
        return raw.decode('utf-8')
