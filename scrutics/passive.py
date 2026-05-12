"""
Scrutics Passive Enforcement
============================
Patches every Scapy transmit function with a hard-raising stub.
Call enforce_passive() once before any capture begins.
"""

import os
import sys
import traceback
import datetime
import logging

AUDIT_LOG_PATH = os.path.join("output", "scrutics_passive_audit.log")
_enforced = False
logger = logging.getLogger("scrutics.passive")

_SEND_FUNCTIONS = [
    "send", "sendp", "sendpfast",
    "sr", "sr1", "srp", "srp1",
    "srloop", "srploop", "srflood", "srpflood", "sndrcv",
]
_SEND_MODULES = ["scapy.sendrecv", "scapy.all"]


def _violation_handler(fn_name: str):
    def _blocked(*args, **kwargs):
        timestamp = datetime.datetime.now().isoformat()
        stack = "".join(traceback.format_stack())
        msg = (
            f"\n{'='*60}\n"
            f"SCRUTICS PASSIVE VIOLATION BLOCKED\n"
            f"Timestamp : {timestamp}\n"
            f"Function  : scapy.{fn_name}\n"
            f"Stack:\n{stack}"
            f"{'='*60}\n"
        )
        try:
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(msg)
        except Exception:
            pass
        print(msg, file=sys.stderr)
        raise PermissionError(
            f"[SCRUTICS] Passive violation blocked: scapy.{fn_name}() called. "
            f"This tool never transmits packets. See {AUDIT_LOG_PATH}."
        )
    _blocked.__name__ = f"_blocked_{fn_name}"
    return _blocked


def enforce_passive() -> None:
    global _enforced
    if _enforced:
        return
    patched = []
    for module_name in _SEND_MODULES:
        try:
            module = sys.modules.get(module_name)
            if module is None:
                try:
                    import importlib
                    module = importlib.import_module(module_name)
                except Exception:
                    continue
        except Exception:
            continue
        for fn_name in _SEND_FUNCTIONS:
            if hasattr(module, fn_name):
                original = getattr(module, fn_name)
                if getattr(original, "__name__", "").startswith("_blocked_"):
                    continue
                setattr(module, fn_name, _violation_handler(fn_name))
                patched.append(f"{module_name}.{fn_name}")
    try:
        import scapy.sendrecv as sendrecv
        for fn_name in _SEND_FUNCTIONS:
            if hasattr(sendrecv, fn_name):
                original = getattr(sendrecv, fn_name)
                if not getattr(original, "__name__", "").startswith("_blocked_"):
                    setattr(sendrecv, fn_name, _violation_handler(fn_name))
    except Exception:
        pass
    _enforced = True


def is_enforced() -> bool:
    return _enforced


def verify_passive() -> list:
    violations = []
    for module_name in _SEND_MODULES:
        module = sys.modules.get(module_name)
        if not module:
            continue
        for fn_name in _SEND_FUNCTIONS:
            fn = getattr(module, fn_name, None)
            if fn and not getattr(fn, "__name__", "").startswith("_blocked_"):
                violations.append(f"{module_name}.{fn_name}")
    return violations
