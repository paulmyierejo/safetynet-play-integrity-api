"""
SafetyNet Attestation API Client
https://developer.android.com/training/safetynet/attestation

This module provides a Python client for interacting with Google's SafetyNet Attestation API.
Note: SafetyNet Attestation API was deprecated in 2022; migrate to Play Integrity API.
"""

import base64
import hashlib
import hmac
import json
import time
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class SafetyNetError(Exception):
    """Base exception for SafetyNet client errors."""
    pass


class NetworkError(SafetyNetError):
    """Raised when network communication fails."""
    pass


class AttestationResponse:
    """Represents the parsed SafetyNet Attestation response."""

    def __init__(self, response_data: Dict[str, Any]):
        self.raw = response_data
        self.success = response_data.get("success", False)
        self.error = response_data.get("error", {})
        self.timestamp = response_data.get("timestampMs", 0)
        self.raw_jwt = response_data.get("jwsResult", "")

        # JWS header & payload (base64 decoded)
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature_valid = False

        if self.raw_jwt:
            parts = self.raw_jwt.split(".")
            if len(parts) == 3:
                try:
                    self.header = json.loads(base64.urlsafe_b64decode(
                        parts[0] + "=="))
                    self.payload = json.loads(base64.urlsafe_b64decode(
                        parts[1] + "=="))
                except Exception:
                    pass

    @property
    def is_valid_basic_integrity(self) -> bool:
        return self.payload.get("basicIntegrity", False)

    @property
    def is_valid_cts_profile(self) -> bool:
        return self.payload.get("ctsProfileMatch", False)

    @property
    def evaluation_type(self) -> str:
        return self.payload.get("evaluationType", "BASIC")

    @property
    def apk_package_name(self) -> str:
        return self.payload.get("apkPackageName", "")

    @property
    def apk_digest_sha256(self) -> str:
        return self.payload.get("apkDigestSha256", "")

    @property
    def device_category(self) -> str:
        return self.payload.get("deviceCategory", "UNKNOWN")

    def parse_advice(self) -> List[str]:
        advice_raw = self.payload.get("advice", "")
        if advice_raw:
            return advice_raw.split(";")
        return []


class SafetyNetClient:
    """
    Python client for SafetyNet Attestation API.

    Usage:
        client = SafetyNetClient(api_key="YOUR_API_KEY")
        result = client.attest(nonce=b"your-16-byte-nonce", salt=b"additional-salt")
        print(result.is_valid_cts_profile)
    """

    BASE_URL = "https://www.googleapis.com/androidantiabuse/v1alpha/attestation"

    def __init__(
        self,
        api_key: str,
        request_timeout: int = 30,
        retry_count: int = 3,
    ):
        self.api_key = api_key
        self.request_timeout = request_timeout
        self.retry_count = retry_count
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Android-SafetyNet-Client/1.0",
        })

    def _generate_nonce(self, salt: bytes) -> bytes:
        """
        Generate a 16-byte nonce for attestation.
        The nonce should be unique per request and include server-side data.
        """
        timestamp = str(int(time.time() * 1000)).encode()
        combined = salt + timestamp
        digest = hashlib.sha256(combined).digest()
        return digest[:16]

    def attest(
        self,
        nonce: Optional[bytes] = None,
        salt: Optional[bytes] = None,
    ) -> AttestationResponse:
        """
        Perform SafetyNet attestation.

        Args:
            nonce: 16-byte nonce (or None to auto-generate)
            salt: Additional entropy for nonce generation

        Returns:
            AttestationResponse with parsed results

        Raises:
            NetworkError: On network failure
            SafetyNetError: On API-level errors
        """
        if nonce is None:
            nonce = self._generate_nonce(salt or b"default-salt")

        nonce_b64 = base64.urlsafe_b64encode(nonce).decode().rstrip("=")

        payload = {
            "nonce": nonce_b64,
            "deviceLanguageCode": "en-US",
            "sdkVersion": 33,
        }

        last_error = None
        for attempt in range(self.retry_count):
            try:
                response = self._session.post(
                    f"{self.BASE_URL}/attest",
                    params={"key": self.api_key},
                    json=payload,
                    timeout=self.request_timeout,
                )

                if response.status_code == 200:
                    data = response.json()
                    if "error" in data and "message" in data["error"]:
                        raise SafetyNetError(
                            f"API Error: {data['error']['message']} "
                            f"(code: {data['error'].get('code', 'unknown')})"
                        )
                    return AttestationResponse(data)

                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    time.sleep(retry_after)
                    continue

                else:
                    raise SafetyNetError(
                        f"HTTP {response.status_code}: {response.text}"
                    )

            except requests.RequestException as e:
                last_error = e
                if attempt < self.retry_count - 1:
                    time.sleep(2 ** attempt)

        raise NetworkError(f"Failed after {self.retry_count} attempts: {last_error}")

    def batch_attest(
        self,
        nonces: List[bytes],
        salt: Optional[bytes] = None,
    ) -> List[AttestationResponse]:
        """Attest multiple nonces in sequence."""
        results = []
        for nonce in nonces:
            try:
                result = self.attest(nonce=nonce, salt=salt)
                results.append(result)
            except SafetyNetError as e:
                results.append(AttestationResponse({"success": False, "error": str(e)}))
            time.sleep(0.5)  # Rate limiting
        return results

    def close(self):
        self._session.close()


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="SafetyNet Attestation Client")
    parser.add_argument("--api-key", required=True, help="Google API key")
    parser.add_argument("--nonce", help="Base64-encoded nonce (optional)")
    parser.add_argument("--salt", default="changeme", help="Salt for nonce generation")
    args = parser.parse_args()

    nonce = None
    if args.nonce:
        nonce = base64.urlsafe_b64decode(args.nonce)

    client = SafetyNetClient(api_key=args.api_key)
    try:
        result = client.attest(nonce=nonce, salt=args.salt.encode())
        print(json.dumps({
            "success": result.success,
            "ctsProfileMatch": result.is_valid_cts_profile,
            "basicIntegrity": result.is_valid_basic_integrity,
            "evaluationType": result.evaluation_type,
            "apkPackageName": result.apk_package_name,
            "deviceCategory": result.device_category,
            "advice": result.parse_advice(),
            "timestamp": datetime.fromtimestamp(result.timestamp / 1000).isoformat(),
        }, indent=2))
    finally:
        client.close()


if __name__ == "__main__":
    main()
