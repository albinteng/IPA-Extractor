# Device helpers

Two small arm64 programs the tool puts on a jailbroken device to decrypt apps without Frida (*Settings → Decryption →
Native helper mode*). They run as root, over the tool's SSH connection.

| Helper | What it does | iOS |
| --- | --- | --- |
| `mremap_decrypt` | Asks the kernel to decrypt the encrypted range of one slice of an installed file with `mremap_encrypted()`; nothing is started. Called once per slice, the range goes to standard output. | 15 and earlier (16 and later refuse it) |
| `memory_decrypt` | Starts the app the way the system does, reads the decrypted code from its memory, kills it. One call per app. See the comment at the top of `src/memory_decrypt.c`. | any that lets a root process get a task port (needed from 16) |

## Files

- `src/` – the C source and the entitlements each helper is signed with.
- `bin/` – the built and signed binaries the tool uploads, and `BUILD_INFO.txt` (compiler, SDK and commit they were
  built from, with their checksums).
- `../.github/workflows/build-helpers.yml` – builds both from `src/` on a macOS runner (Xcode's iOS SDK) and signs them
  with `ldid` (a fake signature that carries the entitlements; no Apple certificate is involved, a jailbreak accepts it).

## Rebuilding

Run the workflow (*Actions → build-helpers → Run workflow*, or push a change under `helpers/src`). It uploads the two
binaries and `BUILD_INFO.txt` as an artifact: copy them into `helpers/bin/`. The tool uses whatever binaries are
there (it does not compare checksums), so a build of your own works the same. The binaries are not bit-for-bit
reproducible across Xcode versions; `BUILD_INFO.txt` says what built them.

The deployment target is iOS 8.0 on purpose: with a newer one the binary has no `LC_DYLD_INFO` and the dyld of iOS 12
and earlier refuses to load it.

## How the tool runs them

`native_decrypt.py` uploads a helper to `/var/tmp/ipa_extractor_helpers` (or `/var/mobile/Media/ipa_extractor_helpers`
when it cannot run programs from there), under a name that contains its checksum (so a new build never replaces a file in use). It never writes over a file that is
there: replacing a program in place made a jailbreak (Substitute) kill processes and panic the device, so a
new version gets a new name and the old ones are deleted. A helper run without arguments exits with status 2; the tool
runs it once that way to be sure it starts.

`memory_decrypt dump [--ranges] [--bundle-id ID] <exec> <app folder> <output folder>` prints one line per image
(`OK`/`FAIL`/`SKIP`, tab separated) on standard output and diagnostics (`# ...`) on standard error. With `--ranges` it
writes only the decrypted ranges (`<relative path>.range`) instead of copies of the files.

## Known limits

- arm64 only. Slices for other architectures are not decrypted.
- `memory_decrypt` lets the app run for a moment so that dyld maps its frameworks, so the app's initialization code runs.
  The main executable and app extensions are read before any of their code runs.
- Frameworks the app does not link are loaded into it with `dlopen`; that is not supported for arm64e apps.
- A jailbreak that puts a library in `DYLD_INSERT_LIBRARIES` for every process (Substitute does) is worked around: the
  helper starts itself again without it, with a raw system call because the library hooks `execve`.
