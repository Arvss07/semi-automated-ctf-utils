# Audio manual — Audacity-centered analysis

> Authorized CTF / educational use only. Work on a copy, never the original.
> Pairs with `audio_forensics.py` (read-only by default) and `encoding_decoder.py` (Morse/text layers).

## 1. Triage (read-only)

```bash
cp challenge.wav work.wav
python3 tool_check.py --profile audio   # file, strings, numpy/scipy/matplotlib, mutagen, wavsteg, audacity
python3 audio_forensics.py work.wav     # type + strings flag scan, creates nothing
python3 triage.py work.wav --verbose    # confirm routing
```

Import `work.wav` into Audacity (`File → Import → Audio`), listen once (`Space`). Note duration, gaps, loud/quiet shifts, speech vs tones vs noise, stereo vs mono. Won't play? It may be misnamed — trust `file` output over the extension.

Setup: `sudo apt install audacity`; `Quality → 44100 Hz / 32-bit float`. Keys: `Space` play, `Ctrl+F` fit, `Ctrl+1/2/3` zoom, drag to select (Selection Toolbar gives ms timestamps). `Split Stereo to Mono` to check channels separately. Export derivatives under new names (`slowed.wav`, `reversed.wav`) — never save over the challenge file.

## 2. Waveform pass

- `Ctrl+F`, zoom into anomalies. Flat silence → select, `Effect → Amplify` (no clipping) to reveal quiet hides. Brick-walled blocks → zoom to sample level (tone burst vs voice). One-channel energy → `Solo` each channel, export separately.
- Trailing silence often holds slowed speech/SSTV — compare Audacity duration vs `file`/`exiftool`.
- Reversed voice: `Ctrl+A → Effect → Reverse`, listen, `Ctrl+Z` (export if intelligible, don't keep reversed).
- Speed: `Effect → Change Speed` (pitch+tempo, tape-style) vs `Change Tempo` (tempo only, chipmunk-style). Try 50%/200% on a copy.
- Log timestamps (`0:42–0:55 tone burst, right only`) — these are your spectrogram/decode targets.

## 3. Spectrogram pass (hidden text, WAV)

Audacity is authoritative; `--spectrogram` is a quick second opinion.

1. Duplicate track (`Edit → Duplicate`); set one to Waveform, one to track-menu `▼ → Spectrogram`.
2. `Edit → Preferences → Spectrograms`: Scale **Log**, window **2048** (drop to 512 for Morse/DTMF timing, raise to 4096–8192 for SSTV/text frequency resolution), raise gain / narrow range for faint text. Check **0–4 kHz** then **16–20 kHz** separately.
3. Look for: block letters/flags (slow-scan image), paired horizontal lines (DTMF), single blinking band (Morse), 1–2 kHz chirps (SSTV header). Confirm tones with `Analyze → Plot Spectrum` on a tight selection.
4. Corroborate: `python3 audio_forensics.py work.wav --spectrogram spec.png` (view at 100%). MP3 → export to WAV first (`File → Export → Export as WAV`); toolkit spectrogram is WAV-only, and lossy MP3 destroys LSB anyway — prefer the WAV original for stego verdicts.

## 4. Encodings (manual — not in toolkit)

- **DTMF:** two-tone bursts. `multimon-ng -t wav -a DTMF work.wav`, map to keypad. Cross-check short digits against the DTMF table in Audacity.
- **SSTV:** modem-like warble, 5–120 s. Trim to warble on a copy, export `sstv.wav`, open in QSSTV (`Receive → Open file`, try Robot36/Martin-M1) or Robot36 phone app.
- **Morse:** single-frequency beeps. Measure dot unit in Selection Toolbar, transcribe `·/−`, then `python3 encoding_decoder.py --text '.... . .-..' --decode morse`.

## 5. LSB / metadata

```bash
strings work.wav | grep -Ei 'flag|ctf|pico|H4G|http|passw' | head -30
python3 audio_forensics.py work.wav --wavsteg --wavsteg-output payload.bin
python3 triage.py payload.bin --verbose   # always triage the payload
python3 audio_forensics.py work.mp3 --id3 # mutagen, exiftool fallback
exiftool work.mp3                          # encoder strings, cover art
python3 audio_forensics.py --folder wavs/ --all --spectrogram-dir specs/
```

Empty `wavsteg` = wrong carrier or no payload, not proof of clean. Don't run `wavsteg` by hand in the repo root (build reads `./enc_file.wav` / writes `./results/dec_msg.txt`; the wrapper stages this in temp). Single-file `--spectrogram` needs an existing parent dir; `--folder` creates `--spectrogram-dir`.

## 6. Pitfalls / evidence

Pitfalls: MP3 LSB loss; wrong spectrogram window hiding signals (try 512/2048/8192 + log scale before calling negative); stereo-only flags vanishing in mono mix; denoising/tempo on the only copy; encrypted payloads failing English scoring (use keys/cribs, not blind brute force).

Save per finding: `file` line + duration/rate, waveform + spectrogram screenshots (note scale/window/gain), exported derivatives with exact Effect + params, toolkit report + payload triage, DTMF/Morse transcript with timestamps/channel, and negatives tried (`log/2048+8192, multimon pass, wavsteg empty`).
