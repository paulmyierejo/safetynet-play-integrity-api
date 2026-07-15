# SafetyNet & Play Integrity API Reference Implementation

A complete, production-ready reference implementation for Google's Android device
integrity attestation APIs: SafetyNet (deprecated) and Play Integrity API.

## Features

- **SafetyNet Attestation Client** — `src/safetynet_client.py`
  Full JWT-based client for the SafetyNet Attestation API with nonce generation,
  retry logic, batch attestation, and structured response parsing.

- **Play Integrity API Client** — `src/integrity_client.py`
  Modern replacement for SafetyNet with device/app/account integrity verdicts,
  nonce generation, token decoding, and comprehensive integrity checks.

- **Server-side Verifier** — `src/verifier.py`
  Backend JWT verification with nonce validation, certificate chain checking,
  timestamp freshness checks, and rate limiting.

- **Local Pre-Checker** — `src/local_checker.py`
  Device-side pre-flight checks (root detection, bootloader status, emulator
  detection, SELinux enforcement, dm-verity status) to avoid wasting API quota.

- **Android Integration Examples** — `examples/android_app/`
  - `MainActivity.java` — SafetyNet API integration (Java)
  - `IntegrityActivity.kt` — Play Integrity API integration (Kotlin)

## Quick Start

### Python Dependencies

```bash
pip install requests
```

### SafetyNet Client

```python
from src.safetynet_client import SafetyNetClient

client = SafetyNetClient(api_key="YOUR_GOOGLE_API_KEY")
result = client.attest(nonce=b"16-byte-nonce")

print(result.is_valid_cts_profile)   # True = genuine device
print(result.is_valid_basic_integrity) # Basic integrity check
print(result.evaluation_type)          # BASIC or HARDWARE_BACKED
```

### Play Integrity Client

```python
from src.integrity_client import PlayIntegrityClient

client = PlayIntegrityClient(package_name="com.yourcompany.yourapp")

# After receiving token from Android app:
verdict = client.decode_and_verify(
    token="<token_from_android>",
    expected_nonce="<your_server_nonce>",
    expected_package="com.yourcompany.yourapp",
)
print(verdict.is_device_recognized)
print(verdict.is_app_integrity_satisfied)
```

### Server-side Verification

```python
from src.verifier import IntegrityVerifier, Verdict

verifier = IntegrityVerifier(nonce_secret="your-secret-key")

# Verify token from Android app
result = verifier.verify_play_integrity(
    token=token_from_app,
    expected_nonce=nonce_sent_to_app,
    expected_package="com.yourcompany.yourapp",
)

if result.is_trusted:
    grant_access()
else:
    deny_access(result.message)
```

### Local Pre-Check

```python
from src.local_checker import DevicePreChecker

checker = DevicePreChecker()
report = checker.run_all_checks()

print(f"Risk: {report['summary']['overall_risk']}")
print(f"Recommendation: {report['summary']['recommended_action']}")
```

### CLI Usage

```bash
# SafetyNet attestation
python -m src.safetynet_client --api-key KEY --nonce "BASE64_NONCE"

# Play Integrity decode
python -m src.integrity_client decode --token "TOKEN"

# Server-side verification
python -m src.verifier --token "TOKEN" --api playintegrity --secret SECRET

# Device pre-check
python -m src.local_checker --json
```

## API Migration Guide: SafetyNet → Play Integrity

| Aspect | SafetyNet (deprecated) | Play Integrity |
|---|---|---|
| API | `SafetyNet.AttestationClient` | `IntegrityManager` |
| Verdict | `ctsProfileMatch`, `basicIntegrity` | `MEETS_DEVICE_INTEGRITY`, `PLAY_RECOGNIZED` |
| App check | `apkPackageName`, `apkDigestSha256` | `appIntegrityVerdict` |
| Device check | `deviceCategory` | `deviceRecognitionVerdict` |
| Rate limit | 10 req/min per key | Varies by tier |
| Availability | Jan 2022 sunset | Active |

## Architecture

```
┌──────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│   Android App    │──────▶│   Your Server    │──────▶│  Google Servers  │
│                  │ nonce │                  │ token │                  │
│  IntegrityManager│◀──────│  Verifier (this) │◀──────│  Play Integrity  │
│  AttestationClient│      │                  │       │                  │
└──────────────────┘       └──────────────────┘       └──────────────────┘
         │                           ▲
         │ local pre-check            │ decode & verify
         ▼                           │
┌──────────────────┐       ┌─────────┴──────────┐
│ LocalPreChecker   │       │  IntegrityVerifier │
│ local_checker.py │       │   src/verifier.py   │
└──────────────────┘       └────────────────────┘
```

## Security Notes

- **Never make security decisions client-side.** All critical verification
  (signature, nonce, package name) must happen on your server.
- **Nonce must be server-generated.** Client-side nonces are trivially
  bypassed.
- **Token expiry.** Play Integrity tokens expire after 5 minutes. Do not
  cache or replay tokens.
- **TLS everywhere.** All API calls must use HTTPS.

## Google Documentation

- [Play Integrity API](https://developer.android.com/google/play/integrity)
- [Migration from SafetyNet](https://developer.android.com/google/play/integrity/migrate)
- [SafetyNet API (archived)](https://developer.android.com/training/safetynet/attestation)

## Contact & Support

- **Website:** [qtphone.com](https://qtphone.com)
- **GitHub Issues:** Open an issue in this repository
- **Email:** contact@qtphone.com

## License

MIT License
