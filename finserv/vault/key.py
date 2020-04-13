import hashlib

class Key:
    MAX_UID = pow(2, 3 * 8) - 1
    PREFIX_SIZE = 3

    def __init__(self, uid: int, key: bytes):
        if not (0 <= uid <= self.MAX_UID):
            raise ValueError('Key UID must be [0..{}]'.format(self.MAX_UID))
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long!')

        self.prefix = uid.to_bytes(3, 'big')

        self.uid = uid
        self.key = key
        self.internedIV = hashlib.sha256(self.prefix + self.key).digest()[:16]


class PasswordKey(Key):
    def __init__(self, uid: int, password: str):
        super().__init__(uid, key=hashlib.sha256(password.encode('utf-8')).digest())
