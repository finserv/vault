from finserv.vault import Vault, PasswordKey

keys = [
    PasswordKey(1, 'Secret')
]
vault = Vault(keys, current=1)


def test_vault_bytes():
    assert vault.get(vault.put(b'Hello world!')) == b'Hello world!'
    assert vault.put(b'Hello world!') != vault.put(b'Hello world!')
    assert vault.putInterned(
        b'Hello world!') == vault.putInterned(b'Hello world!')


def test_vault_string():
    assert vault.getString(vault.putString('Hello world!')) == 'Hello world!'
    assert vault.putString('Hello world!') != vault.putString('Hello world!')


def test_vault_PAN():
    assert vault.getPAN(vault.putPAN('123456789012345')) == '123456789012345'
    assert vault.putPAN('123456789012345') == vault.putPAN('123456789012345')
    assert vault.putPAN('123456789012345') != vault.putPAN('543210987654321')
