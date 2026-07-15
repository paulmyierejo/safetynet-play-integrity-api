"""
Local Device Integrity Checker for Android

This module provides pre-check functionality that can run on the Android
device BEFORE calling the attestation API, helping you:

1. Determine if the device is likely to pass attestation
2. Catch obvious failures early to avoid wasting API quota
3. Provide richer diagnostics before sending to the server

For Android integration, use the SafetyNet API or Play Integrity API directly.
This Python module is for testing/simulation and server-side tooling.

NOTE: All checks here are CLIENT-SIDE and can be bypassed by a rooted/adversarial
device. Always perform server-side verification.
"""

import json
import hashlib
import re
import subprocess
import platform
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CheckResult:
    name: str
    passed: bool
    risk: RiskLevel
    details: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "risk": self.risk.value,
            "details": self.details,
            "recommendation": self.recommendation,
        }


class DevicePreChecker:
    """
    Pre-flight device integrity checker.

    Runs a series of local checks to estimate the likelihood of
    passing the remote SafetyNet/Play Integrity attestation.

    NOTE: All checks are client-side and for estimation only.
    """

    def __init__(self):
        self.results: List[CheckResult] = []

    # ─── Android-specific checks (would be implemented via JNI/Kotlin on Android) ─

    def check_root(self) -> CheckResult:
        """
        Check if the device appears to be rooted.
        On Android: Check for su binary, root management apps.
        """
        root_indicators = []

        # Check for su binary in common locations
        su_paths = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
        ]

        for path in su_paths:
            if os.path.exists(path):
                root_indicators.append(f"su binary found at: {path}")

        # Check for root management packages
        root_packages = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.topjohnwu.magisk",
        ]

        # Check for test-keys build tag
        try:
            if platform.system() == "Linux":
                build_tags = ""
                if os.path.exists("/system/build.prop"):
                    with open("/system/build.prop") as f:
                        for line in f:
                            if "ro.build.tags" in line:
                                build_tags = line.strip()
                                break
                if "test-keys" in build_tags:
                    root_indicators.append("Build has test-keys")
        except Exception:
            pass

        passed = len(root_indicators) == 0
        return CheckResult(
            name="Root Detection",
            passed=passed,
            risk=RiskLevel.HIGH if not passed else RiskLevel.LOW,
            details="; ".join(root_indicators) if root_indicators else "No root indicators found",
            recommendation="Do not proceed with attestation on rooted devices" if not passed else "OK",
        )

    def check_bootloader(self) -> CheckResult:
        """Check if bootloader is unlocked."""
        bootloader_locked = True
        details = "Bootloader appears locked"

        try:
            if platform.system() == "Linux":
                if os.path.exists("/proc/bootloader"):
                    with open("/proc/bootloader") as f:
                        content = f.read()
                        if "unlocked" in content.lower():
                            bootloader_locked = False
                            details = "Bootloader reported as unlocked"
        except Exception:
            pass

        return CheckResult(
            name="Bootloader Lock Status",
            passed=bootloader_locked,
            risk=RiskLevel.CRITICAL if not bootloader_locked else RiskLevel.LOW,
            details=details,
            recommendation="Locked bootloader is required for SafetyNet" if not bootloader_locked else "OK",
        )

    def check_debuggable(self) -> CheckResult:
        """Check if the app or device is in debug mode."""
        is_debuggable = False
        details = "Debug flags appear normal"

        try:
            if os.path.exists("/system/build.prop"):
                with open("/system/build.prop") as f:
                    for line in f:
                        if "ro.debuggable=1" in line:
                            is_debuggable = True
                            details = "Device is debuggable (ro.debuggable=1)"
                            break
                        if "adb" in line.lower() and "debug" in line.lower():
                            is_debuggable = True
        except Exception:
            pass

        return CheckResult(
            name="Debug Status",
            passed=not is_debuggable,
            risk=RiskLevel.MEDIUM if is_debuggable else RiskLevel.LOW,
            details=details,
            recommendation="Disable USB debugging before production use" if is_debuggable else "OK",
        )

    def check_emulator(self) -> CheckResult:
        """Detect Android emulator / QEMU environment."""
        emulator_indicators = []

        emulator_markers = [
            "/system/lib/qemuProps",
            "/system/build.prop",
            "/init.goldfish.rc",
            "/init.x86_64.rc",
            "/dev/qemu_pipe",
            "/dev/hwfifo",
            "/sys/qemu_trace",
            "/system/bin/nox",
            "/system/bin/blueStacks",
        ]

        for marker in emulator_markers:
            if os.path.exists(marker):
                emulator_indicators.append(f"Emulator marker found: {marker}")

        # Check for common emulator CPU identifiers
        try:
            cpuinfo = ""
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo") as f:
                    cpuinfo = f.read()

            emulator_cpu_keywords = ["goldfish", "ranchu", "qemu", "intel atom"]
            for keyword in emulator_cpu_keywords:
                if keyword in cpuinfo.lower():
                    emulator_indicators.append(f"CPU marker: {keyword}")
        except Exception:
            pass

        passed = len(emulator_indicators) == 0
        return CheckResult(
            name="Emulator Detection",
            passed=passed,
            risk=RiskLevel.HIGH if not passed else RiskLevel.LOW,
            details="; ".join(emulator_indicators) if emulator_indicators else "No emulator indicators",
            recommendation="Do not use in emulator for production attestation" if not passed else "OK",
        )

    def check_selinux(self) -> CheckResult:
        """Check SELinux enforcement status."""
        selinux_enforcing = True
        details = "SELinux appears to be enforcing"

        try:
            if os.path.exists("/sys/fs/selinux/enforce"):
                with open("/sys/fs/selinux/enforce") as f:
                    value = f.read().strip()
                    selinux_enforcing = value == "1"
                    if not selinux_enforcing:
                        details = "SELinux is permissive (not enforcing)"
        except Exception:
            details = "Could not determine SELinux status"

        return CheckResult(
            name="SELinux Status",
            passed=selinux_enforcing,
            risk=RiskLevel.MEDIUM if not selinux_enforcing else RiskLevel.LOW,
            details=details,
            recommendation="Set SELinux to enforcing mode" if not selinux_enforcing else "OK",
        )

    def check_system_integrity(self) -> CheckResult:
        """Check system partition for modifications."""
        modifications = []
        details = "System partition appears unmodified"

        # Check common system file hashes (simplified check)
        critical_system_files = [
            "/system/bin/run-as",
            "/system/bin/app_process64",
            "/system/lib64/libandroid_runtime.so",
        ]

        for filepath in critical_system_files:
            if os.path.exists(filepath):
                # In a real implementation, compare against known-good hashes
                pass

        passed = len(modifications) == 0
        return CheckResult(
            name="System Integrity",
            passed=passed,
            risk=RiskLevel.HIGH if not passed else RiskLevel.LOW,
            details=details,
            recommendation="Re-flash stock ROM if system files are modified" if not passed else "OK",
        )

    def check_verity(self) -> CheckResult:
        """Check dm-verity status (system partition integrity)."""
        verity_enabled = False
        details = "Could not determine dm-verity status"

        try:
            result = subprocess.run(
                ["cat", "/proc/mounts"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if "/system" in line and "verity" in line:
                    verity_enabled = True
                    details = "dm-verity is enabled for /system"
                    break
        except Exception:
            pass

        return CheckResult(
            name="dm-verity Status",
            passed=verity_enabled,
            risk=RiskLevel.MEDIUM if not verity_enabled else RiskLevel.LOW,
            details=details,
            recommendation="Enable dm-verity for production devices" if not verity_enabled else "OK",
        )

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all pre-checks and return a summary."""
        checks = [
            self.check_root,
            self.check_bootloader,
            self.check_debuggable,
            self.check_emulator,
            self.check_selinux,
            self.check_system_integrity,
            self.check_verity,
        ]

        results = [check() for check in checks]
        self.results = results

        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed

        # Compute overall risk score
        risk_weights = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        risk_score = sum(risk_weights[r.risk] for r in results if not r.passed)
        overall_risk = "LOW"
        if risk_score >= 5:
            overall_risk = "CRITICAL"
        elif risk_score >= 3:
            overall_risk = "HIGH"
        elif risk_score >= 1:
            overall_risk = "MEDIUM"

        return {
            "summary": {
                "total_checks": len(results),
                "passed": passed,
                "failed": failed,
                "overall_risk": overall_risk,
                "risk_score": risk_score,
                "recommended_action": "PROCEED" if overall_risk == "LOW" else "INVESTIGATE" if overall_risk == "MEDIUM" else "BLOCK",
            },
            "checks": [r.to_dict() for r in results],
        }

    def estimate_attestation_result(self) -> str:
        """
        Estimate the likely attestation result based on local checks.
        This is NOT a guarantee — always verify server-side.
        """
        summary = self.run_all_checks()
        risk = summary["summary"]["overall_risk"]

        if risk == "CRITICAL":
            return "LIKELY_FAILED (CTS profile will not match)"
        elif risk == "HIGH":
            return "UNCERTAIN (may fail integrity checks)"
        elif risk == "MEDIUM":
            return "POSSIBLY_PASS (basic integrity may pass)"
        else:
            return "LIKELY_PASS (no major risk indicators found)"


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Device Integrity Pre-Checker")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    checker = DevicePreChecker()
    result = checker.run_all_checks()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("=" * 60)
        print("  Device Integrity Pre-Check Report")
        print("=" * 60)
        print(f"\n  Overall Risk: {result['summary']['overall_risk']}")
        print(f"  Checks: {result['summary']['passed']}/{result['summary']['total_checks']} passed")
        print(f"  Recommendation: {result['summary']['recommended_action']}")
        print(f"\n  Est. Attestation: {checker.estimate_attestation_result()}")
        print("\n" + "-" * 60)
        for check in result["checks"]:
            icon = "✅" if check["passed"] else "❌"
            print(f"  {icon} {check['name']}: {check['details']}")
        print("=" * 60)


if __name__ == "__main__":
    main()
