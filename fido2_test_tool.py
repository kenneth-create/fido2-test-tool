
#!/usr/bin/env python3
"""
FIDO2 Credential Test Tool

Formål:
- Liste FIDO2-enheder via HID og PCSC
- Liste smartcard readers
- Teste kortkontakt og ATR
- Oprette FIDO2 credential
- Teste assertion
- Gemme lokal credential-historik
- Probe FIDO/U2F applets
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import platform
import os
import shutil
import sys
import uuid

from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Iterable, Optional, Tuple, Any

from fido2.client import (
    DefaultClientDataCollector,
    Fido2Client,
    UserInteraction,
)

from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server

try:
    from fido2.pcsc import CtapPcscDevice
except Exception:
    CtapPcscDevice = None

try:
    from fido2.client.windows import WindowsClient
except Exception:
    WindowsClient = None

try:
    from smartcard.System import readers as pcsc_readers
    from smartcard.util import toHexString
    from smartcard.CardConnection import CardConnection
except Exception:
    pcsc_readers = None
    toHexString = None
    CardConnection = None


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class CliInteraction(UserInteraction):

    def __init__(self):
        self._pin: Optional[str] = None

    def prompt_up(self):
        print("\nRør ved kort/læser eller godkend på authenticatoren.\n")

    def request_pin(self, permissions, rp_id):
        if self._pin is None:
            self._pin = getpass(
                f"Indtast FIDO2 PIN for RP '{rp_id}': "
            )
        return self._pin.encode('utf-8')

    def request_uv(self, permissions, rp_id):
        print(f"User Verification kræves for RP '{rp_id}'.")
        return True


@dataclass
class DeviceRef:
    source: str
    name: str
    device: Any


def is_windows_non_admin() -> bool:

    if platform.system().lower() != "windows":
        return False

    try:
        return not bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------
# ENUMERATION
# ---------------------------------------------------------

def enumerate_hid_devices() -> Iterable[DeviceRef]:

    try:
        for dev in CtapHidDevice.list_devices():
            yield DeviceRef("hid", str(dev), dev)

    except Exception as e:
        print(
            f"ADVARSEL: kunne ikke liste HID-enheder: {e}",
            file=sys.stderr,
        )


def enumerate_pcsc_devices() -> Iterable[DeviceRef]:

    if CtapPcscDevice is None:
        print(
            "ADVARSEL: PC/SC er ikke tilgængelig.",
            file=sys.stderr,
        )
        return

    try:
        for dev in CtapPcscDevice.list_devices():
            yield DeviceRef("pcsc", str(dev), dev)

    except Exception as e:
        print(
            f"ADVARSEL: kunne ikke liste PC/SC-enheder: {e}",
            file=sys.stderr,
        )


def enumerate_devices(
    transport: str = "auto"
) -> list[DeviceRef]:

    devices: list[DeviceRef] = []

    if transport in ("auto", "hid"):
        devices.extend(list(enumerate_hid_devices()))

    if transport in ("auto", "pcsc"):
        devices.extend(list(enumerate_pcsc_devices()))

    return devices


# ---------------------------------------------------------
# CLIENT
# ---------------------------------------------------------

def select_client(
    transport: str,
    origin: str,
    device_index: int = 0,
    use_windows_webauthn: bool = False,
) -> Tuple[Any, Any, str]:

    collector = DefaultClientDataCollector(origin)

    if use_windows_webauthn:

        if WindowsClient is None or not WindowsClient.is_available():
            raise RuntimeError(
                "Windows WebAuthn API er ikke tilgængelig."
            )

        client = WindowsClient(collector)

        return client, None, "windows-webauthn"

    devices = enumerate_devices(transport)

    if not devices:
        raise RuntimeError(
            "Ingen FIDO2-enhed fundet."
        )

    if device_index < 0 or device_index >= len(devices):
        raise RuntimeError(
            f"Ugyldigt device-index {device_index}."
        )

    devref = devices[device_index]

    client = Fido2Client(
        devref.device,
        client_data_collector=collector,
        user_interaction=CliInteraction(),
    )

    info = getattr(client, "info", None)

    return client, info, f"{devref.source}:{devref.name}"



# ---------------------------------------------------------
# DOCTOR / ENVIRONMENT CHECK
# ---------------------------------------------------------

def command_doctor(args) -> int:

    print("Miljøcheck for FIDO2 testværktøj")
    print("=" * 50)
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    print(f"Working dir: {Path.cwd()}")
    print()

    checks_ok = True

    def check(name: str, ok: bool, detail: str = ""):
        nonlocal checks_ok
        status = "OK" if ok else "FEJL"
        print(f"{status:4} {name}{(' - ' + detail) if detail else ''}")
        if not ok:
            checks_ok = False

    check("fido2 import", True)
    check("pyscard/smartcard import", pcsc_readers is not None)
    check("PC/SC FIDO2 transport", CtapPcscDevice is not None)
    check("HID transport", CtapHidDevice is not None)

    if platform.system().lower() == "darwin":
        check("macOS pcscd", shutil.which("pcsctest") is not None or Path("/System/Library/Frameworks/PCSC.framework").exists(), "PC/SC framework findes")
        print("\nmacOS note: NFC/smartcard går typisk via --transport pcsc. USB security keys kan ofte ses via --transport hid.")

    print("\nScanner PC/SC readers...")
    if pcsc_readers is None:
        print("  pyscard mangler, så smartcard readers kan ikke listes.")
    else:
        try:
            available_readers = pcsc_readers()
            if available_readers:
                for i, reader in enumerate(available_readers):
                    print(f"  [{i}] {reader}")
            else:
                print("  Ingen PC/SC readers fundet.")
        except Exception as e:
            checks_ok = False
            print(f"  FEJL ved læsning af PC/SC readers: {e}")

    print("\nScanner FIDO2 devices...")
    try:
        devices = enumerate_devices(args.transport)
        if devices:
            for i, d in enumerate(devices):
                print(f"  [{i}] source={d.source} name={d.name}")
        else:
            print("  Ingen FIDO2 devices fundet.")
    except Exception as e:
        checks_ok = False
        print(f"  FEJL ved FIDO2 scanning: {e}")

    print()
    if checks_ok:
        print("Miljøcheck gennemført. Se ovenstående for om reader/kort blev fundet.")
        return 0

    print("Miljøcheck fandt fejl. Ret afhængigheder/reader og kør igen.")
    return 1

# ---------------------------------------------------------
# READERS
# ---------------------------------------------------------

def card_connection_protocol(protocol: str) -> Optional[int]:
    if protocol == "t0":
        return getattr(CardConnection, "T0_protocol", None)
    if protocol == "t1":
        return getattr(CardConnection, "T1_protocol", None)
    return None


def command_readers(args) -> int:

    print("Scanner efter PC/SC smartcard readers...\n")

    if pcsc_readers is None:
        print("FEJL: pyscard ikke installeret.")
        return 1

    available_readers = pcsc_readers()

    if not available_readers:
        print("Ingen PC/SC readers fundet.")
        return 2

    for i, reader in enumerate(available_readers):

        print(f"[{i}] {reader}")

        if args.test_card:

            try:

                print("    Tester kortkontakt...")

                connection = reader.createConnection()
                connect_protocol = card_connection_protocol(args.protocol)
                if connect_protocol is None:
                    connection.connect()
                else:
                    connection.connect(connect_protocol)

                atr = connection.getATR()
                atr_hex = " ".join(f"{b:02X}" for b in atr)

                print("    Kort fundet")
                print(f"    ATR: {atr_hex}")

                connection.disconnect()

            except Exception as e:

                print("    Kort kunne ikke læses")
                print(f"    Fejl: {e}")

    return 0


# ---------------------------------------------------------
# LIST FIDO2 DEVICES
# ---------------------------------------------------------

def command_list(args) -> int:

    print("Scanner efter FIDO2-enheder...\n")

    devices = enumerate_devices(args.transport)

    if not devices:

        print("Ingen FIDO2-enheder fundet.")
        print("- Prøv --transport pcsc")
        print("- Kontroller Smart Card service")
        print("- Installer pyscard")

        return 2

    for i, d in enumerate(devices):
        print(f"[{i}] source={d.source} name={d.name}")

    if WindowsClient and WindowsClient.is_available():

        print("\nWindows WebAuthn API er tilgængelig.")

        if is_windows_non_admin():
            print(
                "Bemærk: Windows WebAuthn bruges ofte automatisk."
            )

    return 0


# ---------------------------------------------------------
# ENROLL
# ---------------------------------------------------------

def command_enroll(args) -> int:

    rp = {
        "id": args.rp_id,
        "name": args.rp_name,
    }

    user_id = (
        args.user_id.encode("utf-8")
        if args.user_id
        else uuid.uuid4().bytes
    )

    user = {
        "id": user_id,
        "name": args.user_name,
        "displayName": args.display_name or args.user_name,
    }

    print("Starter enrollment / makeCredential")
    print(f"RP ID: {args.rp_id}")
    print(f"Origin: {args.origin}")
    print(f"User: {user['name']}")
    print(f"Transport: {args.transport}\n")

    client, info, device_name = select_client(
        transport=args.transport,
        origin=args.origin,
        device_index=args.device_index,
        use_windows_webauthn=args.use_windows_webauthn,
    )

    server = Fido2Server(
        rp,
        attestation=args.attestation,
    )

    create_options, state = server.register_begin(
        user,
        user_verification=args.user_verification,
        authenticator_attachment="cross-platform",
    )

    print(
        "Opretter credential. "
        "Indtast PIN og/eller rør ved kortet..."
    )

    result = client.make_credential(
        create_options["publicKey"]
    )

    auth_data = server.register_complete(state, result)

    credential_data = auth_data.credential_data

    print("\nCredential oprettet.")

    request_options, auth_state = server.authenticate_begin(
        [credential_data],
        user_verification=args.user_verification,
    )

    assertions = client.get_assertion(
        request_options["publicKey"]
    )

    assertion_response = assertions.get_response(0)

    server.authenticate_complete(
        auth_state,
        [credential_data],
        assertion_response,
    )

    print("Assertion-test bestået.")

    output = {
        "device": device_name,
        "rp_id": args.rp_id,
        "rp_name": args.rp_name,
        "origin": args.origin,
        "user_name": args.user_name,
        "user_display_name": user["displayName"],
        "user_id_base64url": b64url(user_id),
        "credential_id_base64url": b64url(
            credential_data.credential_id
        ),
        "credential_data": str(credential_data),
        "attestation_mode": args.attestation,
        "user_verification": args.user_verification,
    }

    out_path = Path(args.output)

    out_path.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    history_path = Path("credential-history.json")

    if history_path.exists():
        history = json.loads(
            history_path.read_text(encoding="utf-8")
        )
    else:
        history = []

    history.append(output)

    history_path.write_text(
        json.dumps(
            history,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"\nResultat gemt i: {out_path.resolve()}")
    print(f"Credential historik opdateret.")
    print(f"Antal credentials oprettet lokalt: {len(history)}")

    return 0


# ---------------------------------------------------------
# CREDENTIAL HISTORY
# ---------------------------------------------------------

def command_credential_history(args) -> int:

    history_path = Path("credential-history.json")

    if not history_path.exists():
        print("Ingen lokal credential historik fundet.")
        return 0

    history = json.loads(
        history_path.read_text(encoding="utf-8")
    )

    print("Lokal credential historik")
    print("=" * 50)

    print(
        f"Antal credentials oprettet lokalt: {len(history)}"
    )

    for i, item in enumerate(history, start=1):

        print()
        print(f"[{i}]")

        print(f"RP ID: {item.get('rp_id')}")
        print(f"User: {item.get('user_name')}")

        print(
            f"Credential ID: "
            f"{item.get('credential_id_base64url')}"
        )

    return 0


# ---------------------------------------------------------
# PROBE FIDO
# ---------------------------------------------------------

def command_probe_fido(args) -> int:

    print("Prober kort for FIDO/U2F applets...\n")

    if pcsc_readers is None:
        print("FEJL: pyscard ikke installeret.")
        return 1

    available_readers = pcsc_readers()

    if not available_readers:
        print("Ingen PC/SC readers fundet.")
        return 2

    for i, reader in enumerate(available_readers):
        print(f"[{i}] {reader}")

    if (
        args.reader_index < 0
        or args.reader_index >= len(available_readers)
    ):
        print("Ugyldigt reader-index.")
        return 3

    reader = available_readers[args.reader_index]

    print(f"\nBruger reader:\n{reader}\n")

    try:

        connection = reader.createConnection()
        connect_protocol = card_connection_protocol(args.protocol)
        if connect_protocol is None:
            connection.connect()
        else:
            connection.connect(connect_protocol)

        atr = connection.getATR()

        print("Kort fundet")
        print(
            f"ATR: {' '.join(f'{b:02X}' for b in atr)}"
        )

    except Exception as e:

        print("FEJL ved kortforbindelse.")
        print(e)

        return 4

    tests = [
        {
            "name": "FIDO/U2F",
            "aid": "A0000006472F0001",
        },
        {
            "name": "FIDO2",
            "aid": "A0000006472F0002",
        },
    ]

    for test in tests:

        aid = bytes.fromhex(test["aid"])

        apdu = (
            [0x00, 0xA4, 0x04, 0x00, len(aid)]
            + list(aid)
            + [0x00]
        )

        print("\n" + "=" * 60)

        print(f"Tester: {test['name']}")
        print(f"AID: {test['aid']}")

        try:

            response, sw1, sw2 = connection.transmit(apdu)

            print(
                f"Status: {sw1:02X}{sw2:02X}"
            )

            if sw1 == 0x90 and sw2 == 0x00:
                print("Applet fundet")

            else:
                print("Applet ikke fundet")

        except Exception as e:

            print("FEJL under APDU transmission")
            print(e)

    try:
        connection.disconnect()
    except Exception:
        pass

    return 0


# ---------------------------------------------------------
# ARGPARSE
# ---------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "FIDO2 testværktøj"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )


    # DOCTOR

    p_doctor = sub.add_parser(
        "doctor",
        help="Check macOS/VS Code miljø og afhængigheder",
    )

    p_doctor.add_argument(
        "--transport",
        choices=["auto", "hid", "pcsc"],
        default="auto",
    )

    p_doctor.set_defaults(
        func=command_doctor
    )

    # READERS

    p_readers = sub.add_parser(
        "readers",
        help="List smartcard readers",
    )

    p_readers.add_argument(
        "--test-card",
        action="store_true",
    )

    p_readers.add_argument(
        "--protocol",
        choices=["auto", "t0", "t1"],
        default="t0",
        help="Kortprotokol ved korttest (auto, t0, t1)",
    )

    p_readers.set_defaults(
        func=command_readers
    )

    # LIST

    p_list = sub.add_parser(
        "list",
        help="List FIDO2 devices",
    )

    p_list.add_argument(
        "--transport",
        choices=["auto", "hid", "pcsc"],
        default="auto",
    )

    p_list.set_defaults(
        func=command_list
    )

    # ENROLL

    p_enroll = sub.add_parser(
        "enroll",
        help="Opret credential",
    )

    p_enroll.add_argument(
        "--transport",
        choices=["auto", "hid", "pcsc"],
        default="pcsc",
    )

    p_enroll.add_argument(
        "--device-index",
        type=int,
        default=0,
    )

    p_enroll.add_argument(
        "--rp-id",
        default="localhost",
    )

    p_enroll.add_argument(
        "--rp-name",
        default="FIDO2 Test RP",
    )

    p_enroll.add_argument(
        "--origin",
        default="https://localhost",
    )

    p_enroll.add_argument(
        "--user-name",
        default="testuser@example.local",
    )

    p_enroll.add_argument(
        "--display-name",
        default="Test User",
    )

    p_enroll.add_argument(
        "--user-id",
        default=None,
    )

    p_enroll.add_argument(
        "--attestation",
        choices=["none", "direct", "indirect"],
        default="direct",
    )

    p_enroll.add_argument(
        "--user-verification",
        choices=[
            "required",
            "preferred",
            "discouraged",
        ],
        default="discouraged",
    )

    p_enroll.add_argument(
        "--output",
        default="credential-result.json",
    )

    p_enroll.add_argument(
        "--use-windows-webauthn",
        action="store_true",
    )

    p_enroll.set_defaults(
        func=command_enroll
    )

    # HISTORY

    p_history = sub.add_parser(
        "credential-history",
        help="Vis lokal credential historik",
    )

    p_history.set_defaults(
        func=command_credential_history
    )

    # PROBE

    p_probe = sub.add_parser(
        "probe-fido",
        help="Probe FIDO applets",
    )

    p_probe.add_argument(
        "--reader-index",
        type=int,
        default=1,
    )

    p_probe.add_argument(
        "--protocol",
        choices=["auto", "t0", "t1"],
        default="auto",
        help="Kortprotokol ved kortforbindelse (auto, t0, t1)",
    )

    p_probe.set_defaults(
        func=command_probe_fido
    )

    return parser


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main() -> int:

    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)

    except KeyboardInterrupt:

        print("\nAfbrudt af bruger.")
        return 130

    except Exception as e:

        print(f"\nFEJL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

