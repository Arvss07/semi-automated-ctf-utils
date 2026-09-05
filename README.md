# CTF Toolkit

A set of 13 focused Python command-line tools that reduce common CTF crypto and forensics workflows to short, repeatable commands. The target environment is Kali Linux (or another Linux distribution with equivalent packages) and Python 3.10+.

## Quick start

```bash
cd /home/kali/Desktop/ctf-utils
python3 scripts/tool_check.py --profile core
python3 scripts/triage.py unknown_file
```

Check only the dependencies you need:

```bash
python3 scripts/tool_check.py --profile hash
python3 scripts/tool_check.py --profile stego
python3 scripts/tool_check.py --profile archive
python3 scripts/tool_check.py --profile pcap
python3 scripts/tool_check.py --profile audio
```

Profiles report missing requirements and return a nonzero status. Use `--profile all` for the complete environment.

## One-command hash cracking

`hash_wrapper.py` accepts either a raw hash or an existing file as its positional input:

```bash
# Raw hashes
python3 scripts/hash_wrapper.py 482c811da5d5b4bc6d497ffa98491e38 --john
python3 scripts/hash_wrapper.py b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3 --john
python3 scripts/hash_wrapper.py 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745 --john

# Existing hash file (the original one-command form)
python3 scripts/hash_wrapper.py temp.txt --john -w /usr/share/wordlists/rockyou.txt

# Explicit source forms when path/value intent must be unambiguous
python3 scripts/hash_wrapper.py --hash 482c811da5d5b4bc6d497ffa98491e38 --john
python3 scripts/hash_wrapper.py --file temp.txt --john
```

Important options:

```bash
# Auto-select a compatible tool; if hashcat cannot initialize, fall back to John
python3 scripts/hash_wrapper.py HASH --auto

# Save only recovered hash/password lines
python3 scripts/hash_wrapper.py HASH --john --output cracked.txt

# Named restorable session
python3 scripts/hash_wrapper.py HASH --session challenge-01

# Mask or incremental brute force
python3 scripts/hash_wrapper.py HASH --hashcat --attack mask --mask '?d?d?d?d' --increment
python3 scripts/hash_wrapper.py HASH --john --attack bruteforce

# Read an existing potfile result without cracking again
python3 scripts/hash_wrapper.py HASH --john --show
```

The default dictionary is `/usr/share/wordlists/rockyou.txt` when present. Detection is strict for common raw, crypt, and archive formats. A 32-character raw hexadecimal value defaults to MD5 because raw MD5 and NTLM are indistinguishable by shape; use `--type ntlm` when appropriate. Run with `-i`, or with no arguments in an interactive terminal, for prompts.

## Tools

| Script                | Purpose                                                                                   | Mutates/extracts by default?              |
| --------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------- |
| `tool_check.py`       | Profile-aware executable, file, and Python dependency checks                              | No                                        |
| `triage.py`           | File type, metadata, binwalk signatures, strings, flags, and runnable routing suggestions | No                                        |
| `batch_diff.py`       | Strict-majority SHA256/size outlier analysis                                              | No                                        |
| `stego_runner.py`     | steghide/stegseek extraction and zsteg analysis                                           | Yes, to an explicit/default payload path  |
| `encoding_decoder.py` | Strict Base64/Base32/hex/binary/URL decoding                                              | No                                        |
| `cipher_solver.py`    | Caesar, Vigenere, and substitution-frequency analysis                                     | No                                        |
| `xor_toolkit.py`      | Single/repeating XOR, key-length analysis, and phase-correct crib dragging                | No                                        |
| `rsa_solver.py`       | Exact-integer low-e, Fermat, Wiener, common-modulus, and known-key operations             | No                                        |
| `dh_solver.py`        | Diffie-Hellman shared-secret recovery (`pow(A,b,p)`/`pow(B,a,p)`) and XOR decryption      | No                                        |
| `hash_wrapper.py`     | hashcat/John command construction, execution, sessions, and result retrieval              | Cracker pot/session files only            |
| `archive_cracker.py`  | zip/rar/7z hash extraction, password cracking, or explicit unpacking                      | Crack: temporary files only; extract: yes |
| `pcap_forensics.py`   | tshark endpoints, conversations, credentials, streams, flags, and explicit HTTP export    | No; export requires `-x`                  |
| `audio_forensics.py`  | Metadata/strings plus explicit WAV spectrogram and wavsteg operations                     | No; optional operations are explicit      |

All 13 primary tools support `--output console` (default) or `--output PATH` for their text result/report. Extraction artifacts use separate options such as `--extract-to`, `--output-dir`, or `--wavsteg-output`.

## Recommended workflow

1. Check the relevant environment profile.
2. Use `archive_cracker.py` for an archive or `batch_diff.py` for a collection.
3. Run `triage.py` on an unknown individual file.
4. Copy the runnable command from triage's **Suggested next steps** section.
5. Move from representation to cryptanalysis: decoder → cipher/XOR/RSA/DH/hash tool.

`triage.py` is observational by default. It runs `binwalk` without extraction; only `--extract` enables `binwalk -e`.

## Command examples

### Triage

```bash
python3 scripts/triage.py unknown.bin
python3 scripts/triage.py unknown.bin --verbose --output triage.txt
python3 scripts/triage.py unknown.bin --extract   # explicitly allows binwalk extraction
```

Bare hash files are content-detected before generic ASCII routing and are sent to `hash_wrapper.py`.

### Batch outliers

```bash
python3 scripts/batch_diff.py directory/
python3 scripts/batch_diff.py file1.png file2.png file3.png
python3 scripts/batch_diff.py directory/ --method size --ext .png .jpg
```

The default `both` mode uses a strict hash majority. If hashes have no strict majority, it tries size. Ties are reported as ambiguous instead of arbitrarily choosing the first file.

### Encoding

```bash
python3 scripts/encoding_decoder.py encoded.txt --recursive
python3 scripts/encoding_decoder.py --text '666c6167' --decode hex
python3 scripts/encoding_decoder.py --file nested.txt --recursive --verbose
```

Auto mode only accepts a decoded layer when the result remains readable UTF-8. This prevents raw hashes from being decoded into binary garbage. Use an explicit `--decode` type when binary output is intentional; non-text bytes are rendered losslessly as hexadecimal.

### Classical ciphers

```bash
python3 scripts/cipher_solver.py cipher.txt --cipher-type caesar
python3 scripts/cipher_solver.py --text 'uryyb' --cipher-type caesar --caesar-shift 13
python3 scripts/cipher_solver.py cipher.txt --cipher-type vigenere --key-length 6
python3 scripts/cipher_solver.py cipher.txt --cipher-type vigenere --key SECRET
```

### XOR

```bash
python3 scripts/xor_toolkit.py encrypted.bin --mode single
python3 scripts/xor_toolkit.py encrypted.bin --mode detect
python3 scripts/xor_toolkit.py encrypted.bin --mode repeating --key KEY
python3 scripts/xor_toolkit.py --hex '00112233' --mode crib --key 'flag{' --key-length 3
```

Use `--key-hex` for arbitrary key/crib bytes. Crib mode rotates recovered bytes to their actual key positions and marks unknown key bytes rather than inventing them.

### RSA

Every numeric parameter accepts a direct decimal/`0x` value or a file containing one:

```bash
python3 scripts/rsa_solver.py -n 3233 -e 17 -c 2790 -p 61 -q 53
python3 scripts/rsa_solver.py -n n.txt -e e.txt -c c.txt -d d.txt
python3 scripts/rsa_solver.py -e 3 -c CIPHERTEXT --attack lowe
python3 scripts/rsa_solver.py -n MODULUS -e EXPONENT -c CIPHERTEXT --attack fermat
python3 scripts/rsa_solver.py -n MODULUS -e EXPONENT --attack wiener
python3 scripts/rsa_solver.py -n MODULUS -1 C1 -c C2 --e1 E1 --e2 E2 --attack commonmod
```

### DH

Params files use one `KEY = VALUE` line each (`g`, `p`, `A`/`B`/`a`/`b`, `enc` hex), as produced by `encryption.py`-style challenges. Every numeric parameter also accepts a direct decimal/`0x` value or a file containing one:

```bash
python3 scripts/dh_solver.py message.txt
python3 scripts/dh_solver.py --params message.txt --top 5
python3 scripts/dh_solver.py --g 2 --p p.txt --A A.txt --b b.txt --enc-hex ffe6ece0...
python3 scripts/dh_solver.py --g 2 --p 23 --a 6 --B 19 --enc-hex '...' --output dh-report.txt
```

`triage.py` routes `g/p/A/B/a/b + enc` params files to `dh_solver.py` automatically. The solver tries `shared%256` single-byte plus `BE/LE` and `SHA256/SHA1/MD5/SHA512`-derived repeating-XOR keys, ranks by English score with a flag-pattern bonus, and warns on weak params (even/composite/small `p`, trivial `A`/`B`, tiny-order `g`, degenerate `shared`).

### Steganography

```bash
python3 scripts/stego_runner.py image.jpg --passphrase secret --extract-to payload.bin
python3 scripts/stego_runner.py image.jpg --wordlist words.txt --extract-to payload.bin
python3 scripts/stego_runner.py image.png --tool zsteg --output zsteg-report.txt
python3 scripts/stego_runner.py image.jpg --extract-to payload.bin --force -v
```

Existing payloads are not overwritten unless `--force` is supplied. `--output` is the text report; `--extract-to` is the payload. Each extracted payload reports size, `file` type, raw flag search (`flag/CTF/picoCTF/H4G/...`), and snow-like whitespace-stego decoding (`space=0/tab=1` variants with escaped `cat -A` preview); `-v` lists every decode variant.

### Archives

```bash
python3 scripts/archive_cracker.py challenge.zip --wordlist words.txt
python3 scripts/archive_cracker.py challenge.zip --extract --output-dir extracted/
python3 scripts/archive_cracker.py challenge.zip --auto --output-dir extracted/
```

Crack mode uses a unique temporary hash file and succeeds only when `hash_wrapper.py` returns recovered lines. Plain extraction refuses a non-empty output directory unless `--force` is supplied.

### PCAP

```bash
python3 scripts/pcap_forensics.py capture.pcap
python3 scripts/pcap_forensics.py capture.pcap --stream 0
python3 scripts/pcap_forensics.py capture.pcap -x --directory http_objects/
```

Default analysis does not export objects. Flag search follows reassembled TCP streams (up to `--max-streams`, default 100). HTTP object export is explicit and rejects a non-empty destination unless `--force` is used.

### Audio

```bash
python3 scripts/audio_forensics.py audio.wav
python3 scripts/audio_forensics.py audio.wav --spectrogram spectrogram.png
python3 scripts/audio_forensics.py audio.wav --wavsteg --wavsteg-output payload.bin
python3 scripts/audio_forensics.py audio.mp3 --id3
```

Default analysis reads type/strings and does not create artifacts. Spectrogram generation currently supports WAV input; optional operations run only when requested (or via `--all`).

## Dependencies

Use `tool_check.py` for exact per-profile status. Common packages include:

```bash
sudo apt install file libimage-exiftool-perl binwalk binutils
sudo apt install hashcat john wordlists
sudo apt install unzip unrar p7zip-full
sudo apt install tshark
sudo apt install steghide
sudo apt install python3-numpy python3-scipy python3-matplotlib python3-mutagen
```

`zsteg` is installed with RubyGems (`gem install zsteg`). `stegseek` and `wavsteg` may require their upstream release packages, depending on the distribution.

## Exit and safety behavior

- `0`: requested operation completed and, for cracking/extraction commands, produced a result.
- Nonzero: invalid input, missing dependency, no crack/result, failed child process, or ambiguous operation that cannot be completed reliably.
- Child processes use argument arrays rather than shell command strings.
- Analysis commands avoid extraction by default.
- Output and payload paths are separated to prevent accidental report/payload collisions.
- Cracker and archive temporary files are unique and cleaned after use.

## Known limitations and next improvements

- Hash identification is format/shape based. Ambiguous or uncommon hashes still require `--type`; package-specific John/hashcat format names may differ across distributions.
- An installed hashcat executable still needs a working OpenCL/HIP/CUDA backend. Auto mode falls back to John on initialization failure; forced `--hashcat` correctly returns the backend error.
- Caesar/Vigenere/XOR solvers use statistical English scoring. Short, non-English, compressed, or binary plaintext can rank poorly and needs known keys/cribs or manual review.
- RSA support targets textbook CTF weaknesses. It does not attack secure padding, side channels, arbitrary lattice problems, or general large-number factorization. Fermat is bounded by `--max-iterations`.
- DH support targets supplied-private challenges (`pow(A,b,p)` / `pow(B,a,p)`) plus weak-param recovery. It does not solve large-prime discrete logs, full `p-1` factorization/Pohlig-Hellman, small-subgroup confinement beyond a bounded probe, or AES/HKDF-derived session keys (use Python `Crypto`/SageMath/openssl for those). Bounded DLP is capped by `--max-dlp-steps`; prime testing is probabilistic.
- tshark field availability varies by version and dissector. Unsupported credential fields are reported as warnings. Stream search is capped for runtime control.
- WAV spectrogram/wavsteg handling depends on local Python/tool versions; MP3 spectrogram conversion is not currently implemented.
- Archive extraction is delegated to installed extractors. Treat hostile archives as untrusted and extract inside a disposable directory/container; expanded-size quotas and universal cross-format traversal inspection are future work.
- Crib dragging can only fully decrypt when enough consistent key positions are known. Partial keys are deliberately shown with unknown bytes rather than guessed.

## Demo and verification

```bash
python3 scripts/demo_suite.py
python3 scripts/workflow_example.py
```

For any command's complete current interface:

```bash
python3 scripts/<script>.py --help
```

This toolkit is intended for authorized CTF and educational use.
