# FIDO2 Test Tool på macOS i Visual Studio Code

## 1. Forudsætninger

Installer Xcode Command Line Tools:

```bash
xcode-select --install
```

Installer Homebrew pakker, hvis de mangler:

```bash
brew install python swig pkg-config
```

## 2. Opret virtuelt Python miljø

Stå i projektmappen:

```bash
cd fido2_vscode_mac
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## 3. Vælg Python interpreter i VS Code

1. Åbn mappen `fido2_vscode_mac` i VS Code.
2. Kør `Python: Select Interpreter` fra Command Palette.
3. Vælg `.venv/bin/python`.
4. Installer VS Code extension `Python` fra Microsoft, hvis den ikke allerede er installeret.

## 4. Test fra terminal

```bash
python fido2_test_tool.py doctor
python fido2_test_tool.py readers --test-card
python fido2_test_tool.py list --transport pcsc
python fido2_test_tool.py probe-fido --reader-index 1
```

Enrollment:

```bash
python fido2_test_tool.py enroll \
  --transport pcsc \
  --device-index 0 \
  --rp-id localhost \
  --origin https://localhost \
  --user-name testuser@example.local \
  --display-name "Test User" \
  --attestation direct \
  --user-verification discouraged
```

## 5. Debug i VS Code

Brug Run and Debug og vælg en af disse profiler:

- FIDO2 doctor
- List FIDO2 devices PCSC
- List smartcard readers
- Probe FIDO applet
- Enroll credential PCSC

Alle profiler bruger `integratedTerminal`, så PIN prompt og kortberøring virker bedre end i Debug Console.

## 6. Typiske fejl

### `No module named smartcard`

Kør:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Ingen PC/SC readers fundet

Kontroller at readeren er tilsluttet, og prøv:

```bash
python fido2_test_tool.py readers --test-card
```

### FIDO2 enhed findes ikke med `pcsc`

Prøv HID transport, hvis det er en USB security key:

```bash
python fido2_test_tool.py list --transport hid
```

### PIN prompt virker ikke i VS Code

Sørg for at launch profilen bruger:

```json
"console": "integratedTerminal"
```
