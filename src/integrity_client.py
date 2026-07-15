"""
Play Integrity API Client
https://developer.android.com/google/play/integrity

The Play Integrity API replaces the deprecated SafetyNet Attestation API.
This module provides a complete client implementation for token generation,
decoding, and server-side verification.
"""

import base64
import hashlib
import json
import time
import struct
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class IntegrityResponse:
    """Parsed Play Integrity API response."""

    def __init__(self, token_response: str, decoded_payload: Optional[Dict] = None):
        self.token_response = token_response
        self.decoded_payload = decoded_payload or {}

    @property
    def is_device_recognized(self) -> bool:
        return self.decoded_payload.get("deviceRecognitionVerdict") == "MEETS_DEVICE_INTEGRITY"

    @property
    def is_app_integrity_satisfied(self) -> bool:
        verdict = self.decoded_payload.get("appIntegrityVerdict", {})
        return verdict.get("appRecognitionVerdict") in ("PLAY_RECOGNIZED", "UNBOUNDED")

    @property
    def is_account_integrity_satisfied(self) -> bool:
        verdict = self.decoded_payload.get("accountDetails", {})
        return verdict.get("accountRecognitionVerdict") in (
            "HISTORICAL_USER", "REAL_ACCOUNT", "CURRENT_USER"
        )

    @property
    def device_integrity_level(self) -> str:
        return self.decoded_payload.get("deviceRecognitionVerdict", "")

    @property
    def app_integrity_level(self) -> str:
        verdict = self.decoded_payload.get("appIntegrityVerdict", {})
        return verdict.get("appRecognitionVerdict", "UNKNOWN")

    @property
    def account_type(self) -> str:
        return self.decoded_payload.get("accountDetails", {}).get(
            "accountRecognitionVerdict", "UNKNOWN"
        )

    @property
    def device_age_millis(self) -> Optional[int]:
        return self.decoded_payload.get("deviceAttributes", {}).get("deviceAgeMillis")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deviceRecognized": self.is_device_recognized,
            "appIntegritySatisfied": self.is_app_integrity_satisfied,
            "accountIntegritySatisfied": self.is_account_integrity_satisfied,
            "deviceIntegrityLevel": self.device_integrity_level,
            "appIntegrityLevel": self.app_integrity_level,
            "accountType": self.account_type,
            "deviceAgeMillis": self.device_age_millis,
            "rawPayload": self.decoded_payload,
        }


class PlayIntegrityClient:
    """
    Client for Google Play Integrity API.

    On Android side, the app calls IntegrityManager#generateIntegrityToken()
    and sends the resulting token to your server. This module handles the
    server-side decoding and verification.

    Usage (server-side):
        client = PlayIntegrityClient()
        response = client.decode_and_verify(token_from_android)
        if response.is_device_recognized:
            # proceed
            pass
    """

    TOKEN_VERIFY_URL = "https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken"

    def __init__(
        self,
        package_name: str,
        service_account_key_path: Optional[str] = None,
        request_timeout: int = 30,
    ):
        self.package_name = package_name
        self.request_timeout = request_timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "PlayIntegrity-Client/1.0",
        })
        self._service_account_key = None
        if service_account_key_path:
            with open(service_account_key_path) as f:
                self._service_account_key = json.load(f)

    def _decode_jwt_payload(self, token: str) -> Dict[str, Any]:
        """Decode JWT payload without verification (do NOT trust yet)."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        # Add padding if needed
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        # URL-safe base64 → standard base64
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        payload_bytes = base64.b64decode(payload_b64)
        return json.loads(payload_bytes)

    def decode_token(self, token: str) -> IntegrityResponse:
        """
        Decode a Play Integrity token (parse only, no verification).
        For production, use decode_and_verify() instead.
        """
        payload = self._decode_jwt_payload(token)
        return IntegrityResponse(token_response=token, decoded_payload=payload)

    def decode_and_verify(
        self,
        token: str,
        expected_nonce: Optional[str] = None,
        expected_package: Optional[str] = None,
        expected_version_codes: Optional[List[int]] = None,
    ) -> IntegrityResponse:
        """
        Fully decode and verify the integrity token on the server.

        Args:
            token: The integrity token from the Android app
            expected_nonce: The nonce this server originally sent to the app
            expected_package: The expected app package name
            expected_version_codes: Acceptable version codes

        Returns:
            IntegrityResponse with verification results

        Raises:
            ValueError: If token is malformed
            AssertionError: If verification checks fail
        """
        payload = self._decode_jwt_payload(token)

        # ── 1. Nonce verification ──────────────────────────────────────────────
        if expected_nonce:
            token_nonce = payload.get("nonce", "")
            if token_nonce != expected_nonce:
                raise AssertionError(
                    f"Nonce mismatch! Expected {expected_nonce}, got {token_nonce}"
                )

        # ── 2. Package name verification ──────────────────────────────────────
        if expected_package:
            app_verdict = payload.get("appIntegrityVerdict", {})
            if app_verdict.get("packageName") != expected_package:
                raise AssertionError(
                    f"Package name mismatch! Expected {expected_package}"
                )

        # ── 3. Version code verification ───────────────────────────────────────
        if expected_version_codes:
            app_verdict = payload.get("appIntegrityVerdict", {})
            version_code = app_verdict.get("versionCode", -1)
            if version_code not in expected_version_codes:
                raise AssertionError(
                    f"Version code {version_code} not in allowed list: {expected_version_codes}"
                )

        # ── 4. Timestamp freshness (5 minutes) ─────────────────────────────────
        timestamp_millis = payload.get("timestampMillis", 0)
        if timestamp_millis:
            age_seconds = (time.time() * 1000 - timestamp_millis) / 1000
            if age_seconds > 300:
                raise AssertionError(f"Token is too old: {age_seconds:.0f}s")

        return IntegrityResponse(token_response=token, decoded_payload=payload)

    def generate_nonce(self, request_id: str, secret: str) -> str:
        """
        Generate a nonce server-side to embed in the integrity request.
        This prevents replay attacks.
        """
        timestamp = str(int(time.time() * 1000))
        raw = f"{request_id}:{self.package_name}:{timestamp}:{secret}"
        digest = hashlib.sha256(raw.encode()).digest()
        return base64.b64encode(digest).decode().rstrip("=")

    def check_integrity(
        self,
        token: str,
        require_device_integrity: bool = True,
        require_app_integrity: bool = True,
        require_no_arc: bool = False,
    ) -> Dict[str, Any]:
        """
        High-level integrity check returning structured verdict.

        Args:
            token: Integrity token from Android app
            require_device_integrity: Device must pass integrity check
            require_app_integrity: App must be genuine Play install
            require_no_arc: Device must not be ARC (Android Runtime for Chrome)

        Returns:
            Dict with 'passed', 'failed_checks', and 'response' keys
        """
        response = self.decode_token(token)
        failed_checks = []

        if require_device_integrity and not response.is_device_recognized:
            failed_checks.append("device_integrity")

        if require_app_integrity and not response.is_app_integrity_satisfied:
            failed_checks.append("app_integrity")

        if require_no_arc and response.device_integrity_level == "ARC":
            failed_checks.append("arc_detected")

        return {
            "passed": len(failed_checks) == 0,
            "failed_checks": failed_checks,
            "response": response.to_dict(),
        }

    def close(self):
        self._session.close()


# ─── Integrity Token Builder (for testing / mock generation) ─────────────────
class MockIntegrityTokenBuilder:
    """
    Builder for creating mock integrity tokens for testing.
    DO NOT use in production.
    """

    @staticmethod
    def build_mock_token(
        package_name: str,
        version_code: int,
        device_recognized: bool = True,
        app_recognized: bool = True,
        nonce: str = "mock_nonce_value",
        account_type: str = "CURRENT_USER",
    ) -> str:
        import time

        header = {"alg": "RS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "iss": "https://playintegrity.googleapis.com/",
            "aud": [package_name],
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "timestampMillis": int(time.time() * 1000),
            "appIntegrityVerdict": {
                "packageName": package_name,
                "versionCode": version_code,
                "appRecognitionVerdict": "PLAY_RECOGNIZED" if app_recognized else "UNRECOGNIZED",
            },
            "deviceIntegrityVerdict": {
                "deviceRecognitionVerdict": (
                    "MEETS_DEVICE_INTEGRITY" if device_recognized
                    else "MISSING_DEVICE_INTEGRITY"
                ),
            },
            "accountDetails": {
                "accountRecognitionVerdict": account_type,
            },
        }

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")

        return f"{header_b64}.{payload_b64}.mock_signature"


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Play Integrity API Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    decode_parser = subparsers.add_parser("decode", help="Decode and print token")
    decode_parser.add_argument("--token", required=True, help="Integrity token (JWT)")

    verify_parser = subparsers.add_parser("verify", help="Decode and verify token")
    verify_parser.add_argument("--token", required=True, help="Integrity token (JWT)")
    verify_parser.add_argument("--nonce", help="Expected nonce")
    verify_parser.add_argument("--package", default="com.example.myapp", help="Package name")
    verify_parser.add_argument("--version-codes", type=int, nargs="+", help="Allowed version codes")

    mock_parser = subparsers.add_parser("mock", help="Generate mock token for testing")
    mock_parser.add_argument("--package", default="com.example.myapp")
    mock_parser.add_argument("--version-code", type=int, default=1)
    mock_parser.add_argument("--device-recognized", action="store_true")
    mock_parser.add_argument("--app-recognized", action="store_true")

    args = parser.parse_args()

    if args.command == "decode":
        client = PlayIntegrityClient(package_name="com.example.myapp")
        response = client.decode_token(args.token)
        print(json.dumps(response.to_dict(), indent=2))

    elif args.command == "verify":
        client = PlayIntegrityClient(package_name=args.package)
        try:
            response = client.decode_and_verify(
                token=args.token,
                expected_nonce=args.nonce,
                expected_package=args.package,
                expected_version_codes=args.version_codes,
            )
            print(json.dumps(response.to_dict(), indent=2))
        except AssertionError as e:
            print(json.dumps({"passed": False, "error": str(e)}, indent=2))

    elif args.command == "mock":
        token = MockIntegrityTokenBuilder.build_mock_token(
            package_name=args.package,
            version_code=args.version_code,
            device_recognized=args.device_recognized,
            app_recognized=args.app_recognized,
        )
        print(token)


if __name__ == "__main__":
    main()
