from proton_clean.totp import code_from, totp

# RFC 6238 test vectors for the 8-digit/SHA1 cases use this base32 secret:
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # "12345678901234567890"


def test_rfc6238_vectors():
    assert totp(SECRET, digits=8, t=59) == "94287082"
    assert totp(SECRET, digits=8, t=1111111109) == "07081804"
    assert totp(SECRET, digits=8, t=1234567890) == "89005924"


def test_six_digit_default():
    code = totp(SECRET, t=1_700_000_000)
    assert len(code) == 6 and code.isdigit()


def test_otpauth_uri():
    uri = ("otpauth://totp/Proton:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
           "&digits=8&period=30")
    assert code_from(uri, t=59) == "94287082"


def test_spaces_and_case_folding():
    assert totp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", t=59,
                digits=8) == "94287082"
