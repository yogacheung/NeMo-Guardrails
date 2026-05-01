"""
IoT Security Library for NeMo-Guardrails
=========================================
Pre-built security rails for applications interfacing with IoT devices,
industrial control systems, and MQTT/CoAP-based infrastructure.

Provided rails:
  - iot_command_injection_detection:  Blocks attempts to inject commands into IoT endpoints.
  - iot_credential_leak_detection:    Prevents LLM responses from leaking IoT credentials.
  - ics_attack_detection:             Blocks queries targeting ICS/SCADA infrastructure.
  - mqtt_topic_abuse_detection:       Detects MQTT wildcard and broker-takeover patterns.
  - smart_device_exploit_detection:   Guards against smart home exploitation prompts.
"""
