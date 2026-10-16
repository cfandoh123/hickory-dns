# Authenticated DoT test credentials

These credentials are public test data for `recursor::tests::authenticated_dot`.
Never deploy the server key or install these CAs in a system trust store.

`generate.py` creates two test CAs and four server certificates using Python's
`cryptography` package. CA signing keys are discarded. All server certificates
deliberately share the checked-in test key, so every test server can complete a
real handshake when its certificate is accepted.

- `valid.pem`: expected DNS SAN, trusted issuer, valid from 2020 through 2100.
- `wrong-name.pem`: trusted issuer and valid dates, different DNS SAN.
- `untrusted.pem`: expected DNS SAN and valid dates, issuer is `rogue-ca.pem`.
- `expired.pem`: expected DNS SAN and trusted issuer, expired in 2001.

The broad dates make regression tests independent of the Docker lab's short-lived
certificates. They are not a model for production certificate lifetimes.

Regenerate deliberately with `python3 tests/test-data/authenticated-dot/generate.py`
from the workspace root. This replaces only these test credentials.
