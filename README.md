<p align="center"><img src="assets/icon_1024.png" width="128" alt=""></p>

# IPA Extractor

A desktop GUI for pulling IPA files off a jailbroken iPhone or iPad over Wi-Fi (SSH), in two ways:

- **Original IPA** – packs the installed app as-is. Executables stay FairPlay-encrypted, so the IPA installs only on devices using the purchasing Apple ID (or with AppSync). Needs nothing but SSH, and works for apps that can no longer launch, such as 32-bit apps on iOS 11+.
- **Decrypted IPA** – launches the app and dumps its decrypted executables with [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump). Needs `frida-server` on the device.

## Features

- Works with rootful and rootless jailbreaks.
- App list read over SSH with name, bundle ID, version, encryption state, 32/64-bit architecture, Team ID, signer and developer.
- Filters (user apps, non-Apple apps, encrypted apps), search, and checkboxes with bulk actions, including *Check failed apps*, *Check partially decrypted apps* and *Check unextracted apps*.
- Batch extraction with per-app status and an overall progress bar.
- Large decrypted batches stay stable: each launched app is closed after dumping, a stuck `frida-server` is detected, restarted and the app retried, and the batch pauses after repeated Frida failures.
- Configurable file names from `{name}`, `{bundle}`, `{version}`, `{build}` and `{type}`, with a preview and clash detection.
- Separate or shared output folders for decrypted and original IPAs.
- Frida is connected through the same SSH session (no `ssh -L` or `iproxy` needed).
- Built-in setup: downloads frida-ios-dump and installs the `frida` version that matches the device (or any other release you pick).
- Several `frida` versions side by side: each device gets the one matching its frida-server, so devices with different Frida major versions can be used one after another in the same window, without reinstalling or restarting.

## Requirements

**Device**

- A jailbroken iPhone or iPad, rootful (e.g. unc0ver, checkra1n, palera1n rootful) or rootless (e.g. Dopamine, palera1n rootless).
- An SSH server, on the same network as the computer.
- For decrypted IPAs: `frida-server` from the official Frida repository.

**Computer**

- Python 3.9 or later with tkinter. The Python packages the tool needs ([Paramiko](https://www.paramiko.org/), [cryptography](https://cryptography.io/), and [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) on Linux) are installed on first start, after asking.
- For decrypted IPAs: Node.js (`npm install` fetches `frida-objc-bridge` for frida-ios-dump) and a copy of frida-ios-dump; the tool can download it for you.

## Setting up the device

1. **Jailbreak** the device with a jailbreak that supports its iOS version and chip. It installs a package manager (Sileo, Zebra or Cydia).
2. **Install OpenSSH.** In the package manager, search for and install `OpenSSH`. It listens on port 22. (palera1n also ships its own dropbear SSH server on port 44.)
3. **Choose the SSH account and password.**
   - **Rootful:** log in as `root`. Many rootful jailbreaks leave the well-known default password `alpine`; change it right away with `passwd` (and `passwd mobile` for the mobile account).
   - **Rootless:** log in as `mobile`, with the password set for the mobile user (on Dopamine: *Settings → Change mobile password* in the Dopamine app; palera1n and the package managers ask for it when you first set up). The tool also gives this password to `sudo` when it needs to restart frida-server. Logging in as `root` works only after you give root its own password (`sudo passwd root`) and the SSH server allows root logins, so `mobile` is the simpler choice.
4. **Install frida-server** (decrypted IPAs only). Add the source `https://build.frida.re` in the package manager and install `Frida`; the package manager picks the rootful or rootless build. It starts automatically.
5. **Find the device IP** in *Settings → Wi-Fi → (i)* next to the network.

Check the connection from a terminal with `ssh root@<device IP>` (rootful) or `ssh mobile@<device IP>` (rootless) before using the tool.

The `frida` used on the computer must match the major version of frida-server on the device (e.g. 16.x with 16.x). The tool keeps each installed `frida` version in its own folder (`frida_versions/` next to the tool) and, on connecting, picks the device's exact version or else the newest one with the same major version. When none fits, it offers to install the device's version. *Settings → Frida → Install Frida dependencies* lists the installed versions, adds others and deletes them.

## Getting started

### Windows

1. Install Python from [python.org](https://www.python.org/downloads/) and tick *Add python.exe to PATH*.
2. Double-click `ipa_extractor.bat`. If `paramiko` is missing, the tool offers to install it (with `pip install --user`, so no administrator rights are needed).

### Linux

```sh
sudo apt install python3-tk python3-venv   # Debian/Ubuntu; Fedora: sudo dnf install python3-tkinter
./ipa_extractor.sh
```

On first start the tool offers to install its Python packages into `./.venv`, including [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) for a modern look. For Chinese, Japanese or Korean UI text, install a CJK font such as `fonts-noto-cjk`.

### macOS

```sh
brew install python python-tk   # or use the python.org installer, which includes Tk
./ipa_extractor.sh
```

`ipa_extractor.sh` keeps the tool's Python packages in `./.venv`, created on first run, so the system Python is never modified.

## Usage

1. Enter the device IP, SSH account (`root` or `mobile`, see above) and password, then click **Connect**. The app list loads over SSH; Frida connects as well when frida-ios-dump is set up.
2. Check the apps you want (click ☐, double-click a row, or select rows and press Space).
3. Click **Extract original IPA** or **Extract decrypted IPA**.

For decrypted IPAs, keep the device unlocked with the screen on. To set up decrypted extraction, open **Settings → Frida**: *Install frida-ios-dump* downloads the latest version from GitHub to a folder you choose, and *Install Frida dependencies* lets you add a `frida` version (the device's frida-server version is recommended), then runs `pip install --target` into that version's folder and `npm install`. No restart is needed.

## Settings

| Tab | Options |
| --- | --- |
| General | Language (*Automatic* follows the system), font (*Automatic* picks the best installed font for the language), text size |
| Extraction | File name templates (default `{name}_{bundle}_{version}_{type}`), separate output folders (default `output_decrypted` and `output_encrypted` next to the tool) |
| Frida | frida-ios-dump folder (*Install frida-ios-dump* downloads it when the folder is not set up), *Install Frida dependencies*, Frida port, restart frida-server and retry on errors, close each app after decrypting it |

Defaults: SSH port 22 with no account, Frida port 27042, output folders `output_decrypted` and `output_encrypted` next to the tool, frida-ios-dump in a `frida-ios-dump` folder beside the tool's folder, *Automatic* language and font, text size 10 (13 on macOS).

`{type}` is `encrypted` (original IPA) or `original` (original IPA whose executable was never encrypted). For decrypted IPAs it follows a check of every executable in the IPA (main app, frameworks, app extensions, Watch app), done on the computer after each extraction: `decrypted` (all decrypted), `partial-64bit-decrypted` (only 32-bit slices of fat binaries still encrypted; all 64-bit code is decrypted) or `partial-decrypted` (some 64-bit code is still encrypted; the log and the details pane list the files and why). *Check partially decrypted apps* selects these apps.

Installed `frida` versions are kept in `frida_versions/` next to the tool (`~/.ipa_extractor/frida_versions` when the tool's folder is read-only); a `frida` installed in Python's own site-packages by version 1.0 is no longer used.

Settings are stored in `settings.json` next to the tool, so they move with its folder; only values that differ from the defaults are written. If the tool's folder is read-only, `~/.ipa_extractor.json` (`%USERPROFILE%\.ipa_extractor.json` on Windows) is used instead. Delete the file to restore the defaults. *Remember password* stores the SSH password there in plain text.

## Limitations

- **App extensions are not decrypted.** frida-ios-dump decrypts only code loaded in the app's own process. Widgets, share extensions and other `.appex` bundles run as separate processes and stay encrypted, as can frameworks the app had not loaded yet. The main executable is always decrypted. [flexdecrypt](https://github.com/JohnCoates/flexdecrypt) can decrypt such files on the device afterwards.
- Offloaded apps (*Settings → General → iPhone Storage → Offload App*) keep only a placeholder on the device. They are marked in the list and skipped; reinstall them from the App Store first.
- Apps that cannot launch on the device (crashes, 32-bit apps on iOS 11+, invalid licences) cannot be decrypted; extract the original IPA instead.

## Adding a language

Each language is a JSON file in `locales/` named by its language tag, e.g. `ja.json`. Copy `en.json`, translate the values, and set `_name` (shown in the language list) and `_fonts` (preferred UI fonts, first installed one wins). Values are Python `str.format` templates: keep `{placeholders}` unchanged and double literal braces. Missing keys fall back to English; the tests check every file against `en.json`.

## Project layout

| File | Purpose |
| --- | --- |
| `ipa_extractor.py` | Tkinter GUI |
| `ipa_extractor.bat`, `ipa_extractor.sh` | Launchers for Windows and Linux/macOS |
| `device_apps.py` | Lists installed apps over SSH/SFTP with the names the Home screen shows |
| `ipa_extract.py` | Streams an installed bundle over SSH into an IPA without decrypting it |
| `app_info.py` | Reads Info.plist, encryption state and code signature; builds IPA file names |
| `dump_worker.py` | Runs frida-ios-dump's `dump.py` unchanged, reporting progress to the GUI |
| `remote.py` | Runs shell commands on the device |
| `i18n.py`, `locales/` | UI languages |
| `assets/` | App icon |
| `tests/` | Unit tests: `python -m unittest discover -s tests` |

## Third-party software

IPA Extractor does not bundle any of these; they are installed separately.

| Software | Used for | License |
| --- | --- | --- |
| [Paramiko](https://www.paramiko.org/) | SSH and SFTP | LGPL-2.1 |
| [cryptography](https://cryptography.io/) | Reading code signature certificates | Apache-2.0 or BSD-3-Clause |
| [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) | UI theme on Linux | MIT |
| [Frida](https://frida.re/) (`frida` Python package, `frida-server`) | Launching and decrypting apps | wxWindows Library Licence 3.1 |
| [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) | Dumping decrypted IPAs | MIT |
| [scp](https://github.com/jbardin/scp.py) | File transfer used by frida-ios-dump | LGPL-2.1-or-later |
| [frida-objc-bridge](https://github.com/frida/frida-objc-bridge) | Objective-C runtime access used by frida-ios-dump | LGPL-2.0 with wxWindows exception 3.1 |

## Disclaimer

Use this tool only with apps you are entitled to, for purposes such as backup, interoperability and security research, and in accordance with the laws and terms that apply to you. Decrypted IPAs must not be redistributed.

## License

[MIT](LICENSE)
