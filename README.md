<p align="center"><img src="assets/icon_1024.png" width="128" alt=""></p>

# IPA Extractor

A desktop GUI for pulling IPA files off a jailbroken iPhone or iPad over Wi-Fi (SSH), in two ways:

- **Original IPA** – packs the installed app as-is. Executables stay FairPlay-encrypted, so the IPA installs only on devices using the purchasing Apple ID (or with AppSync). Needs nothing but SSH, and works for apps that can no longer launch, such as 32-bit apps on iOS 11+.
- **Decrypted IPA** – an IPA with decrypted executables, made in one of two ways (*Settings → Decryption*): with two small helper programs run on the device, no Frida at all (*Native helper*, the default), or with Frida (*Frida*), which copies the installed app and decrypts its files on the device without running any of its code (*Direct decryption mode*) or launches the app and dumps it with [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) (*frida-ios-dump decryption mode*). Frida mode needs `frida-server` on the device.

## Features

- Works with rootful and rootless jailbreaks.
- App list read over SSH with name, bundle ID, version, encryption state, 32/64-bit architecture, Team ID, signer and developer.
- Filters (user apps, non-Apple apps, encrypted apps), search, and checkboxes with bulk actions, including *Check failed apps*, *Check partially decrypted apps* and *Check unextracted apps*.
- Batch extraction with per-app status and an overall progress bar.
- Every decrypted IPA is checked on the computer, executable by executable and slice by slice, and files still encrypted are decrypted on the device: with `mremap_encrypted` in frida-server's own process on iOS 15 and earlier, or on iOS 16 and later by having the system load the app and its extensions suspended (they never run) and reading the decrypted code from memory; encrypted frameworks are loaded into the app after letting it start without its UI.
- Large decrypted batches stay stable: each launched app is closed after dumping, a stuck `frida-server` is detected, restarted and the app retried, and the batch pauses after repeated Frida failures.
- Configurable file names from `{name}`, `{bundle}`, `{version}`, `{build}` and `{type}`, with a preview and clash detection.
- Separate or shared output folders for decrypted and original IPAs.
- Native helper needs no Frida: two arm64 programs (`helpers/`, with their source and the workflow that builds them) are put on the device over SSH and decrypt every file of an app, its extensions and frameworks included. They are chosen by iOS version, or by hand.
- Frida is connected through the same SSH session (no `ssh -L` or `iproxy` needed).
- Built-in setup: downloads frida-ios-dump and installs the `frida` version that matches the device (or any other release you pick).
- Several `frida` versions side by side: each device gets the one matching its frida-server, so devices with different Frida major versions can be used one after another in the same window, without reinstalling or restarting.

## Requirements

**Device**

- A jailbroken iPhone or iPad, rootful (e.g. unc0ver, checkra1n, palera1n rootful) or rootless (e.g. Dopamine, palera1n rootless).
- An SSH server, on the same network as the computer.
- For decrypted IPAs in *Frida*: `frida-server` from the official Frida repository.
- For decrypted IPAs in *Native helper* (the default): nothing but SSH, a jailbreak that runs ad-hoc signed (ldid) programs as root, and an arm64 device. `sudo` is used when you log in as `mobile`.

**Computer**

- Python 3.9 or later; the window needs its tkinter module, the command line does not. The Python packages the tool needs ([Paramiko](https://www.paramiko.org/), [cryptography](https://cryptography.io/), and [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) on Linux) are installed on first start, after asking.
- For decrypted IPAs made with frida-ios-dump: Node.js (`npm install` fetches `frida-objc-bridge` for frida-ios-dump) and a copy of frida-ios-dump; the tool can download it for you. *Direct decryption mode* and *Native helper* need neither.

## Setting up the device

1. **Jailbreak** the device with a jailbreak that supports its iOS version and chip. It installs a package manager (Sileo, Zebra or Cydia).
2. **Install OpenSSH.** In the package manager, search for and install `OpenSSH`. It listens on port 22. (palera1n also ships its own dropbear SSH server on port 44.)
3. **Choose the SSH account and password.**
   - **Rootful:** log in as `root`. Many rootful jailbreaks leave the well-known default password `alpine`; change it right away with `passwd` (and `passwd mobile` for the mobile account).
   - **Rootless:** log in as `mobile`, with the password set for the mobile user (on Dopamine: *Settings → Change mobile password* in the Dopamine app; palera1n and the package managers ask for it when you first set up). The tool also gives this password to `sudo` when it needs to restart frida-server. Logging in as `root` works only after you give root its own password (`sudo passwd root`) and the SSH server allows root logins, so `mobile` is the simpler choice.
4. **Install frida-server** (*Frida* only; the default *Native helper* does not need it). Add the source `https://build.frida.re` in the package manager and install `Frida`; the package manager picks the rootful or rootless build. It starts automatically.
5. **Find the device IP** in *Settings → Wi-Fi → (i)* next to the network.

Check the connection from a terminal with `ssh root@<device IP>` (rootful) or `ssh mobile@<device IP>` (rootless) before using the tool.

The `frida` used on the computer must match the major version of frida-server on the device (e.g. 16.x with 16.x). The tool keeps each installed `frida` version in its own folder (`frida_versions/` next to the tool) and, on connecting, picks the device's exact version or else the newest one with the same major version. When none fits, it offers to install the device's version. *Settings → Decryption → Install Frida dependencies* lists the installed versions, adds others and deletes them.

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

## GUI

### Usage

1. Enter the device IP, SSH account (`root` or `mobile`, see above) and password, then click **Connect**. The app list loads over SSH; Frida connects as well in *Frida* (with frida-ios-dump, once its folder is set up). The Frida status beside SSH is shown only then, not with *Native helper*.
2. Check the apps you want (click ☐, double-click a row, or select rows and press Space).
3. Click **Extract original IPA** or **Extract decrypted IPA**.

Decrypted IPAs are made without Frida by default (*Native helper*): nothing needs installing, on the computer or on the device. In **Settings → Decryption** leave the helper on *Automatic* (file mapping up to iOS 15, process memory from iOS 16) or force one of them. File mapping is refused by iOS 16 and later: if you chose it for such a device, the *Decrypted IPA* button explains that and does nothing.

To use Frida instead, open **Settings → Decryption**, choose *Frida* and click *Install Frida dependencies* to add a `frida` version (the device's frida-server version is recommended); it runs `pip install --target` into that version's folder. No restart is needed. To use frida-ios-dump, choose *frida-ios-dump decryption mode* under *Frida*: *Install frida-ios-dump* downloads the latest version from GitHub to a folder you choose, *Install Frida dependencies* also runs `npm install`, and the device must stay unlocked with the screen on.

### Settings

| Tab | Options |
| --- | --- |
| General | Language (*Automatic* follows the system), font (*Automatic* picks the best installed font for the language), text size, theme (*Follow system*, the default, picks light or dark when the tool starts; or *Light*, *Dark*, or *Black* with a pure black background). *Follow system* reads the setting of Windows, macOS, or GNOME and KDE on Linux, and uses light where it cannot tell |
| Output | File name templates (default `{name}_{bundle}_{version}_{type}`), separate output folders (default `output_decrypted` and `output_encrypted` next to the tool) |
| Decryption | Decryption mode, two kinds. *Native helper* (no Frida; the default) with its helper: *Automatic*, *File mapping* or *Process memory* (each has a tooltip). *Frida* with *Direct decryption mode* (the app's code never runs, except its initialization code when iOS 16 and later need it for encrypted frameworks) or *frida-ios-dump decryption mode* (runs the app) with its own options, greyed out with the other mode: its folder (*Install frida-ios-dump* downloads it when the folder is not set up), decrypt files frida-ios-dump left encrypted (on by default), close each app after decrypting it; and the settings of both Frida modes: restart frida-server and retry on errors, Frida port, *Install Frida dependencies*. What does not belong to the chosen kind is greyed out. |

Defaults: SSH port 22 with no account, *Native helper* with the helper on *Automatic* (and *Direct decryption mode* as the Frida mode to return to), Frida port 27042, output folders `output_decrypted` and `output_encrypted` next to the tool, frida-ios-dump in a `frida-ios-dump` folder beside the tool's folder, *Automatic* language and font, text size 10 (13 on macOS), *Light* theme.

`{type}` is `encrypted` (original IPA) or `original` (original IPA whose executable was never encrypted). For decrypted IPAs it follows a check of every executable in the IPA (main app, frameworks, app extensions, Watch app), done on the computer after each extraction: `decrypted` (all decrypted), `partial-decrypted-<architectures>` (some slices are still encrypted: the name lists the architectures of the main executable that are decrypted, e.g. `partial-decrypted-armv7` or `partial-decrypted-armv6-armv7`; the log and the details pane list the files and why) or `partial-decrypted` (no decrypted architecture to name). *Check partially decrypted apps* selects these apps.

Installed `frida` versions are kept in `frida_versions/` next to the tool (`~/.ipa_extractor/frida_versions` when the tool's folder is read-only); a `frida` installed in Python's own site-packages by version 1.0 is no longer used.

Settings are stored in `settings.json` next to the tool, so they move with its folder; only values that differ from the defaults are written. If the tool's folder is read-only, `~/.ipa_extractor.json` (`%USERPROFILE%\.ipa_extractor.json` on Windows) is used instead. Delete the file to restore the defaults. *Remember password* stores the SSH password there in plain text.

## CLI

Everything the window does is also available without it, for scripts and servers: `ipa_cli.py` (or any arguments to `ipa_extractor.py` / `ipa_extractor.sh`; it needs the same Python packages but neither tkinter nor a display). It reads the device and the options from `settings.json`, the file the window saves, and options given on the command line override it.

```
python ipa_cli.py apps -H 192.168.1.20 -u root          list the apps (add --json for scripts)
python ipa_cli.py extract com.example.app               original IPAs
python ipa_cli.py decrypt --all --non-apple             decrypted IPAs, every app the filters let through
python ipa_cli.py decrypt --mode frida-direct com.example.app
python ipa_cli.py verify some.ipa                       is it really decrypted?
python ipa_cli.py config show                           the settings; config set theme black, config reset theme
```

| Command | What it does |
| --- | --- |
| `apps` | Lists the apps with name, bundle ID, version, encryption, team, signer, developer. Filters as in the window: `--include-system`, `--non-apple`, `--encrypted-only`, `--search TEXT` (defaults from the settings) |
| `extract`, `decrypt` | Original or decrypted IPAs. Pick apps by bundle ID, `--all`, `--search`, `--unextracted` (no IPA in the output folders yet) or `--partial` (decrypted IPA still partly encrypted). `-o DIR`, `--name TEMPLATE`, `--overwrite`, `--skip-existing`, `--json` |
| `decrypt` options | `--mode native` / `frida-direct` / `frida-ios-dump`, `--helper auto` / `mremap` / `memory`, `--frida-port`, `--dump-dir`, `--install-frida`, `--repair` / `--no-repair`, `--close-after` / `--keep-open`, `--restart-frida` / `--no-restart-frida` (all default to the settings); `--helper mremap` is refused on iOS 16 and later |
| `verify` | Checks every executable of IPAs, like `ipa_verify.py` |
| `install-frida`, `install-frida-ios-dump` | What the window's *Install Frida dependencies* and *Install frida-ios-dump* buttons do |
| `config` | `show`, `set KEY VALUE`, `reset KEY...`, `keys`, `path`: the same settings as the window, including the theme |

The SSH password comes from `--password`, the `IPA_PASSWORD` variable, the saved one (*Remember password*), or a prompt. Progress goes to stderr, results to stdout. Files that exist are replaced only with `--overwrite` (or after asking in a terminal). Ctrl+C finishes the file in progress and stops; a second Ctrl+C quits at once. Exit status: 0 everything done, 1 something failed, 2 wrong usage or no connection, 3 done but some IPAs are partly encrypted, 130 cancelled. The messages of the extraction itself follow the language setting (`--lang` overrides it); the command line's own messages and help are English.

## Limitations

- **What iOS 16 and later can decrypt.** iOS 16 refuses `mremap_encrypted`, so only code the system itself loads on the device can be read: the app's executable and its extensions (each started suspended through a system process: SpringBoard, AuthenticationServicesAgent, Settings, which opens briefly, for Safari extensions, or, with frida-ios-dump, the running app itself). Encrypted frameworks are decrypted by loading them into the app: with *Direct decryption mode* the app is first let start with `UIApplicationMain` replaced, so it never shows its UI but its initialization code runs (the log says so), and an app that quits or crashes while starting keeps its frameworks encrypted. Watch apps, 32-bit slices and extensions that require a newer iOS stay encrypted. iOS 15 and earlier decrypt every file. Either way the app must have been installed with the device's own Apple ID; apps installed from an already decrypted or re-signed IPA have no key on the device. IPAs with files left encrypted are named `partial-decrypted`, and the log lists each file and why.
- **iOS 8 and other old devices (frida 12).** Old SSH servers that only offer an `ssh-rsa` host key are accepted. `frida-server` 12.x needs `frida` 12.x on the computer, which has no wheel for current Pythons: on Windows x64 the tool installs it (*Install Frida dependencies*, or when it offers to on connecting) together with its own embeddable Python 3.8, in that version's folder. Only *Direct decryption mode* works with it (*frida-ios-dump* needs frida 16 or later). iOS 8 decrypts one cputype per file, so each slice of a fat file is decrypted from a copy of its own made in the device's `/var/tmp` (removed afterwards); 32-bit slices that are not 16 KB aligned are decrypted in the spawned app, whose code does not run. A slice that is older than the one the device runs (armv6 or armv7 in a fat file, on a 64-bit device) is refused by the kernel and stays encrypted; the app still works. 64-bit slices are decrypted first, and a file that cannot be decrypted from its copy (errno 12, seen with some app extensions) is retried where it is installed.
- **Native helper.** The helpers are arm64 programs: devices that run only 32-bit code are not supported, and a 32-bit slice of an app is left encrypted. They need a jailbreak that accepts ad-hoc signed programs with entitlements (`task_for_pid-allow` and the like). *File mapping* (`mremap_decrypt`) covers every file of the app and starts nothing, but iOS 16 and later refuse it. *Process memory* (`memory_decrypt`) starts the app the way the system does, suspended (SpringBoard launches it; if that does not work an executable is started stopped at exec, which is the only way extensions are started), reads the main executable before any of its code runs, then lets the app run for a moment so dyld maps its frameworks (the app's initialization code runs) and reads those too; frameworks the app does not link are loaded into it with `dlopen`. Apps built for arm64e are not supported by that last step. A jailbreak that injects a library into every process (`DYLD_INSERT_LIBRARIES`) is worked around: the helper starts itself again without it. The tool uploads a helper under a name that contains its checksum and never writes over a file there (replacing a program in place made a jailbreak kill processes and panic the device); it does not compare the binaries with a list, so a helper you built yourself works too, and a helper that cannot be read or started shows a warning. See `helpers/README.md`.
- Offloaded apps (*Settings → General → iPhone Storage → Offload App*) keep only a placeholder on the device. They are marked in the list and skipped; reinstall them from the App Store first.
- Apps that crash on launch can only be decrypted with *Native helper* (file mapping) or *Direct decryption mode*; with frida-ios-dump, extract the original IPA instead.
- On iOS 16 and later, frida-server 17 sometimes crashes while it holds an extension suspended. With *Restart frida-server and retry on errors* the tool restarts it and tries the affected files again (up to three more times, while that gets further); either way it lets go of whatever the crashed frida-server held suspended. Killing or stopping frida-server by hand many times in a row has left a device unable to start services until it was restarted.

## Adding a language

Each language is a JSON file in `locales/` named by its language tag, e.g. `ja.json`. Copy `en.json`, translate the values, and set `_name` (shown in the language list) and `_fonts` (preferred UI fonts, first installed one wins). Values are Python `str.format` templates: keep `{placeholders}` unchanged and double literal braces. Missing keys fall back to English; the tests check every file against `en.json`.

## Project layout

| File | Purpose |
| --- | --- |
| `ipa_extractor.py` | Tkinter GUI |
| `engine.py` | What needs no window: settings, SSH, and the engine (`DumpEngine`) that copies and decrypts apps; shared by the GUI and the CLI, never imports tkinter |
| `ipa_cli.py` | Command line: the same features without the window |
| `ipa_extractor.bat`, `ipa_extractor.sh` | Launchers for Windows and Linux/macOS |
| `device_apps.py` | Lists installed apps over SSH/SFTP with the names the Home screen shows |
| `ipa_extract.py` | Streams an installed bundle over SSH into an IPA without decrypting it |
| `app_info.py` | Reads Info.plist, encryption state and code signature; builds IPA file names |
| `dump_worker.py` | Runs frida-ios-dump's `dump.py` unchanged, reporting progress to the GUI |
| `ipa_verify.py` | Checks every Mach-O slice of an IPA for encryption (also a command-line tool) |
| `ipa_repair.py` | Plans which files to decrypt on the device and patches the results into the IPA |
| `repair_worker.py`, `repair_agent.js` | Decrypt files on the device with Frida (`mremap_encrypted` or reading memory) |
| `native_decrypt.py` | The same without Frida: uploads and runs the helpers in `helpers/` over SSH |
| `helpers/` | The two device-side helper programs: `src/` (C source), `bin/` (the built, signed binaries), `README.md` |
| `.github/workflows/build-helpers.yml` | Builds the helpers from `helpers/src` on a macOS runner |
| `frida_versions.py` | Keeps several `frida` versions side by side and picks one per device |
| `frida_probe.py` | Checks the connection to frida-server with a given `frida` version |
| `remote.py` | Runs shell commands on the device |
| `i18n.py`, `locales/` | UI languages |
| `assets/` | App icon |
| `tests/` | Unit tests: `python -m unittest discover -s tests` |

## Third-party software

IPA Extractor does not bundle any of these (apart from its own helpers in `helpers/`); they are installed separately.

| Software | Used for | License |
| --- | --- | --- |
| [Paramiko](https://www.paramiko.org/) | SSH and SFTP | LGPL-2.1 |
| [cryptography](https://cryptography.io/) | Reading code signature certificates | Apache-2.0 or BSD-3-Clause |
| [sv-ttk](https://github.com/rdbende/Sun-Valley-ttk-theme) | UI theme on Linux | MIT |
| [Frida](https://frida.re/) (`frida` Python package, `frida-server`) | Launching and decrypting apps | wxWindows Library Licence 3.1 |
| [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) | Dumping decrypted IPAs | MIT |
| [scp](https://github.com/jbardin/scp.py) | File transfer used by frida-ios-dump | LGPL-2.1-or-later |
| [frida-objc-bridge](https://github.com/frida/frida-objc-bridge) | Objective-C runtime access used by frida-ios-dump | LGPL-2.0 with wxWindows exception 3.1 |

The helpers in `helpers/` are this project's own code (MIT). How `memory_decrypt` starts an app, reads its memory and calls `dlopen` in it was worked out with the help of the device-side code of [ipadecrypt](https://github.com/londek/ipadecrypt) (MIT), which solves the same problem; none of its code is copied.

## Disclaimer

Use this tool only with apps you are entitled to, for purposes such as backup, interoperability and security research, and in accordance with the laws and terms that apply to you. Decrypted IPAs must not be redistributed.

## License

[MIT](LICENSE)
