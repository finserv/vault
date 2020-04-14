from finserv.vault import Vault, PasswordKey

keys = [
    PasswordKey(1, 'Secret#1'),
    PasswordKey(2, 'Secret#2'),
    PasswordKey(3, 'Secret#3'),
]
vault = Vault(keys, current=3)


def test_vault_bytes():
    assert vault.get(vault.put(b'Hello world!')) == b'Hello world!'
    # Random IV
    assert vault.put(b'Hello world!') != vault.put(b'Hello world!')
    # Fixed IV for key
    assert vault.putInterned(
        b'Hello world!') == vault.putInterned(b'Hello world!')


def test_vault_string():
    assert vault.getString(vault.putString('Hello world!')) == 'Hello world!'
    assert vault.putString('Hello world!') != vault.putString('Hello world!')


def test_vault_PAN():
    assert vault.getPAN(vault.putPAN('123456789012345')) == '123456789012345'
    assert vault.putPAN('123456789012345') == vault.putPAN('123456789012345')
    assert vault.putPAN('123456789012345') != vault.putPAN('543210987654321')


def test_vault_PAN_lookup():
    clearPAN = '123456789012345'

    vault.useKey(1)
    pan1 = vault.putPAN(clearPAN)
    vault.useKey(2)
    pan2 = vault.putPAN(clearPAN)
    vault.useKey(3)
    pan3 = vault.putPAN(clearPAN)

    assert pan1 != pan2
    assert pan1 != pan3
    assert pan2 != pan3

    history = [pan1, pan2, pan3]
    lookup = vault.allPAN(clearPAN)
    assert len(lookup) == len(keys)

    # SELECT ... FROM ... WHERE pan IN (?, ?, ?)
    for v in history:
        assert v in lookup

    assert pan1 in vault.allPAN(clearPAN)
    assert pan2 in vault.allPAN(clearPAN)
    assert pan3 in vault.allPAN(clearPAN)

    assert vault.getPAN(pan1) == clearPAN
    assert vault.getPAN(pan2) == clearPAN
    assert vault.getPAN(pan3) == clearPAN


def test_vault_PAN_reencrypt():
    clearPAN = '123456789012345'

    vault.useKey(1)
    pan1 = vault.putPAN(clearPAN)
    vault.useKey(2)
    pan2 = vault.putPAN(clearPAN)
    vault.useKey(3)
    pan3 = vault.putPAN(clearPAN)

    history = [pan1, pan2, pan3]

    vault.useKey(3)
    currentPrefix = vault.prefixPAN()

    # SELECT ... FROM ... WHERE pan NOT LIKE ?%
    for i, v in enumerate(history):
        if not v.startswith(currentPrefix):
            # UPDATE ... SET pan = ? WHERE ...
            history[i] = vault.putPAN(vault.getPAN(v))

    assert len(set(history)) == 1
    assert history[0] == vault.putPAN(clearPAN)
