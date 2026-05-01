"""
IoT Security Detection Actions for NeMo-Guardrails
====================================================
Custom action implementations for IoT-specific threat detection.
These actions are called from Colang flows defined in flows.co.
"""

import re
import logging
from typing import Optional
from nemoguardrails.actions import action

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Compiled regex patterns — built once at module import time
# ---------------------------------------------------------------------------

# MQTT and CoAP protocol abuse
_MQTT_WILDCARD_RE = re.compile(
    r"mqtt\W*(subscribe|sub|topic)\W*#|topic\W*[\"']?#[\"']?",
    re.IGNORECASE,
)
_MQTT_BRUTE_RE = re.compile(
    r"mqtt\W*(brute.?force|credential.?stuff|bypass.?auth|flood|dos|storm)",
    re.IGNORECASE,
)
_MQTT_CMD_RE = re.compile(
    r"mqtt\W*(publish|pub)\W*(command|cmd|exec|shell|bash|system)",
    re.IGNORECASE,
)
_COAP_ABUSE_RE = re.compile(
    r"coap\W*(amplif|reflect|flood|spoof|manipulate)",
    re.IGNORECASE,
)

# IoT credential extraction
_IOT_CRED_RE = re.compile(
    r"(tuya|shelly|tasmota|esphome|homeassistant)\W*(client.?id|secret|access.?key|token)"
    r"|\b(mqtt|device|sensor|gateway)\W*(user(name)?|pass(word)?|token|key)\s*[:='\"]",
    re.IGNORECASE,
)
_RTSP_CRED_RE = re.compile(r"rtsp://[^:]+:[^@]+@", re.IGNORECASE)
_HARDCODED_RE = re.compile(
    r"(hardcoded|baked.in|embedded)\W*(password|credential|key|secret)",
    re.IGNORECASE,
)

# ICS/SCADA system attacks
_ICS_ATTACK_RE = re.compile(
    r"(plc|hmi|scada|dcs|rtu)\W*(attack|exploit|compromise|manipulate|takeover|reprogram)"
    r"|(modbus|dnp3|profinet|ethernet.?ip)\W*(spoof|replay|inject|attack|override)"
    r"|(triton|trisis|xenotime|industroyer|crashoverride)",
    re.IGNORECASE,
)
_SAFETY_SYSTEM_RE = re.compile(
    r"(safety.?(instrumented.?system|controller|relay)|sis)\W*(bypass|disable|override|inhibit)",
    re.IGNORECASE,
)

# IoT firmware exploitation
_FIRMWARE_RE = re.compile(
    r"(firmware|flash)\W*(dump|extract|pull)\W*(jtag|uart|spi|i2c)"
    r"|(bootloader|u.boot)\W*(bypass|unlock|jailbreak|exploit)"
    r"|secure.?boot\W*(bypass|disable|defeat|circumvent)",
    re.IGNORECASE,
)

# Smart home device compromise
_SMART_HOME_RE = re.compile(
    r"(smart.?lock|door.?lock)\W*(bypass|unlock|clone|replay|brute)"
    r"|(ip.?cam(era)?|cctv|onvif)\W*(default.?pass|credentials|exploit)"
    r"|(alexa|google.?home|siri)\W*(inject|spoof|ultrasound|laser)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _check_patterns(text: str, *patterns: re.Pattern) -> bool:
    """Return True if any pattern matches the given text."""
    for pat in patterns:
        if pat.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Registered Actions
# ---------------------------------------------------------------------------

@action(is_system_action=True)
async def IoTCommandInjectionAction(context: Optional[dict] = None) -> bool:
    """
    Detect prompts attempting to inject malicious commands into IoT/embedded
    device interfaces via MQTT, CoAP, or direct API manipulation.

    Returns True if a threat is detected.
    """
    user_message: str = (context or {}).get("user_message", "")
    detected = _check_patterns(
        user_message,
        _MQTT_WILDCARD_RE,
        _MQTT_BRUTE_RE,
        _MQTT_CMD_RE,
        _COAP_ABUSE_RE,
    )
    if detected:
        log.warning("[IoT Security] Command injection attempt detected.")
    return detected


@action(is_system_action=True)
async def IoTCredentialLeakAction(context: Optional[dict] = None) -> bool:
    """
    Detect prompts or responses that reference IoT platform credentials,
    RTSP stream credentials, or hardcoded device secrets.

    Returns True if a credential leak risk is detected.
    """
    user_message: str = (context or {}).get("user_message", "")
    bot_response: str = (context or {}).get("bot_message", "")
    combined = f"{user_message}\n{bot_response}"
    detected = _check_patterns(combined, _IOT_CRED_RE, _RTSP_CRED_RE, _HARDCODED_RE)
    if detected:
        log.warning("[IoT Security] Credential leak risk detected.")
    return detected


@action(is_system_action=True)
async def ICSAttackDetectionAction(context: Optional[dict] = None) -> bool:
    """
    Detect prompts targeting industrial control systems (PLC, SCADA, HMI)
    or industrial protocols (Modbus, DNP3, PROFINET, EtherNet/IP).
    Safety-system bypass attempts are considered CRITICAL severity.

    Returns True if an ICS threat is detected.
    """
    user_message: str = (context or {}).get("user_message", "")
    detected = _check_patterns(user_message, _ICS_ATTACK_RE, _SAFETY_SYSTEM_RE)
    if detected:
        log.critical("[IoT Security] ICS/SCADA attack attempt detected!")
    return detected


@action(is_system_action=True)
async def IoTFirmwareExploitAction(context: Optional[dict] = None) -> bool:
    """
    Detect prompts seeking to extract, modify, or exploit IoT device firmware
    via JTAG/UART interfaces or bootloader manipulation.

    Returns True if a firmware attack pattern is found.
    """
    user_message: str = (context or {}).get("user_message", "")
    detected = _check_patterns(user_message, _FIRMWARE_RE)
    if detected:
        log.warning("[IoT Security] Firmware exploitation attempt detected.")
    return detected


@action(is_system_action=True)
async def SmartDeviceExploitAction(context: Optional[dict] = None) -> bool:
    """
    Detect prompts targeting smart home devices: smart locks, IP cameras,
    voice assistants, or smart lighting systems.

    Returns True if a smart device attack pattern is found.
    """
    user_message: str = (context or {}).get("user_message", "")
    detected = _check_patterns(user_message, _SMART_HOME_RE)
    if detected:
        log.warning("[IoT Security] Smart home device exploitation attempt detected.")
    return detected
