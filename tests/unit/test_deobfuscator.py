"""
Unit tests for the recursive de-obfuscation engine.
"""

from atlas.detectors.deobfuscator import RecursiveDeobfuscator


def test_url_decoding():
    deob = RecursiveDeobfuscator()
    obfuscated = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    res = deob.normalize(obfuscated)
    assert res.is_obfuscated is True
    assert "../../etc/passwd" in res.normalized_text


def test_hex_decoding():
    deob = RecursiveDeobfuscator()
    obfuscated = "\\x2e\\x2e\\x2f\\x2e\\x2e\\x2fid_rsa"
    res = deob.normalize(obfuscated)
    assert res.is_obfuscated is True
    assert "../../id_rsa" in res.normalized_text


def test_base64_embedded_decoding():
    deob = RecursiveDeobfuscator()
    # cm0gLXJmIC8= is "rm -rf /"
    obfuscated = "echo cm0gLXJmIC8= | base64 -d"
    res = deob.normalize(obfuscated)
    assert res.is_obfuscated is True
    assert "rm -rf /" in res.normalized_text


def test_clean_input_no_mutation():
    deob = RecursiveDeobfuscator()
    clean = "SELECT id, name FROM users WHERE active = true"
    res = deob.normalize(clean)
    assert res.is_obfuscated is False
    assert res.normalized_text == clean
