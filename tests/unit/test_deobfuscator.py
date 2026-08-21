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


def test_base64_decoding_without_padding_or_keyword_hint():
    """A base64 payload whose byte length is a multiple of 3 needs no '=' padding,
    and an attacker simply won't include the literal word "base64"/"b64"/"decode" --
    both were previously required for decoding to trigger at all, so a payload like
    this sailed through completely undecoded."""
    deob = RecursiveDeobfuscator()
    # "Y2F0IC9ldGMvc2hhZG93" is "cat /etc/shadow" -- 15 bytes (a multiple of 3), so
    # no padding is needed, and the surrounding text has no base64/b64/decode hint.
    obfuscated = "Y2F0IC9ldGMvc2hhZG93"
    res = deob.normalize(obfuscated)
    assert res.is_obfuscated is True
    assert "cat /etc/shadow" in res.normalized_text


def test_clean_input_no_mutation():
    deob = RecursiveDeobfuscator()
    clean = "SELECT id, name FROM users WHERE active = true"
    res = deob.normalize(clean)
    assert res.is_obfuscated is False
    assert res.normalized_text == clean
