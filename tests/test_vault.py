from datetime import datetime
from finserv.vault import Vault, PasswordKey

keys = [
    PasswordKey(1, datetime.strptime(
        '2010-01-01 00:00:00', '%Y-%m-%d %H:%M:%S'), 'Secret')
]
vault = Vault(keys)
timestamp = datetime.now()


def test_vault_bytes():
    assert vault.get(vault.put(b'Hello world!', timestamp)) == b'Hello world!'
    assert vault.put(b'Hello world!', timestamp) != vault.put(
        b'Hello world!', timestamp)
    assert vault.putInterned(
        b'Hello world!', timestamp) == vault.putInterned(b'Hello world!', timestamp)


def test_vault_string():
    assert vault.getString(vault.putString(
        'Hello world!', timestamp)) == 'Hello world!'
    assert vault.putString('Hello world!', timestamp) != vault.putString(
        'Hello world!', timestamp)


def test_vault_PAN():
    assert vault.getPAN(vault.putPAN('123456789012345',
                                     timestamp)) == '123456789012345'
    assert vault.putPAN('123456789012345', timestamp) == vault.putPAN(
        '123456789012345', timestamp)
    assert vault.putPAN('123456789012345', timestamp) != vault.putPAN(
        '543210987654321', timestamp)
