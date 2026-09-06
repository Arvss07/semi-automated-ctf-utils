# Wireshark manual — GUI analysis

> Pairs with `pcap_forensics.py` (tshark endpoints/conversations/credentials/streams/flags, explicit HTTP export). GUI finds, toolkit proves repeatably. Authorized captures only — no unauthorized sniffing.
> Not a capture (`file` says text/gzip/WAV)? Send to `triage.py`, don't force Wireshark.

## 1. First open

```bash
cp capture.pcap work.pcap
capinfos work.pcap   # snaplen, drops, interfaces, time range
python3 pcap_forensics.py work.pcap   # endpoints/conversations/creds + stream flag search (max 100)
```

`File → Open work.pcap`. Set `View → Time Display Format → UTC` before any beacon math. Small snaplen (96/128) or drop counters = payload verdicts suspect — note it now. Export only into a fresh `out/`.

## 2. Triage — five stops, in order

1. **`Statistics → Protocol Hierarchy`** — imbalance (90% DNS? ARP/USB/TLS surprise?). Right-click → `Apply as Filter`.
2. **`Statistics → Conversations`** — sort Bytes/Duration. Long-low flows = beacon; short-high = exfil. Right-click → `Apply as Filter → A ↔ B` → Follow stream.
3. **`Statistics → Endpoints`** — external hosts vs broadcast noise. Report IPs, not PTR guesses.
4. **`Analyze → Expert Information`** — Errors (malformed/truncation) before Warnings (retransmits). VM checksum errors ≈ NIC offload, not tampering.
5. **`Statistics → I/O Graph`** — combs = beacon, plateaus = exfil. Zoom packet list to one period.

Mirrors: `pcap_forensics.py work.pcap --endpoints` / `--conversations` (= `tshark -q -z endpoints,ip` / `conv,tcp`).

## 3. Display filters

Display filters hide rows; capture filters drop data — prefer display filters for CTFs.

```
http; http.request or http.response
http contains "flag" or tcp contains "flag" or dns contains "flag"
dns; dns.qry.name contains "exfil"; dns.qry.name.len > 40
tcp.port == 80 || tcp.port == 8080
tls.handshake.type == 1; tls.handshake.extensions_server_name contains "example"
ftp || telnet || smtp || imap || snmp
(http.authbasic or http.authorization) or ftp.request.command == "PASS"
tcp.flags.reset == 1; tcp.analysis.retransmission
usb || bluetooth || wpa-eapol; arp || icmp
```

`tcp contains` sees reassembly; chunked/gzip HTTP needs `File → Export Objects → HTTP` first, then grep the files. DNS-tunnel: long labels + high TXT rate, correlate with `Statistics → DNS` + I/O periodicity.

## 4. Tools + credential/flag pass

- **Follow stream** (right-click → `Follow → TCP/UDP/HTTP`): reassembled session. HTTP variant shows chunked decoding; `Raw/Hex → Save as` for exfil. Mirror: `pcap_forensics.py work.pcap --stream N`.
- **Export Objects** (`File → Export Objects → HTTP/SMB/DICOM`): mirrors `pcap_forensics.py work.pcap -x --directory out/` (both refuse non-empty dirs without `--force`). Then `file out/*` + `triage.py` each object. Never claim "no exfil" before this.
- **Graphs:** `Flow Graph`, `TCP Stream Graphs → Round Trip/Throughput` (beacon vs bulk). **Find:** `Edit → Find Packet` (string/regex `flag{|CTF{|Authorization:|PASS `). **Decode As:** force dissector on odd ports (HTTP/8081); note it in the report, `Reset` when done. **VoIP/WLAN:** `Telephony → VoIP/RTP` (export `.au` → audio manual), `Wireless → WLAN Traffic` (EAPOL).
- **Creds:** filter `ftp || telnet || http.authbasic || smtp || imap || snmp` → Follow each hit in context (banner + sequence). Toolkit covers FTP `USER/PASS`, HTTP Basic decode, POST `password=`, Telnet.
- **Flags:** Find `flag{`/`CTF{`/`picoCTF{`/`H4G{` + the `contains` filter above; on HTTP-heavy files export first, then `grep -rEi 'flag\{|CTF\{' out/`. Toolkit searches streams `0–99` (`--max-streams` to raise).
- **TLS without keys = metadata only** (SNI `tls.handshake.extensions_server_name`, cert, sizes, timing). Keylog loads via `Preferences → Protocols → TLS → (Pre-)Master-Secret log` — note the file.

## 5. Equivalence / pitfalls / evidence

| GUI | Command |
|---|---|
| Properties | `capinfos work.pcap` |
| Endpoints / Conversations | `pcap_forensics.py work.pcap --endpoints` / `--conversations` |
| Stream N | `pcap_forensics.py work.pcap --stream N` |
| Full report | `pcap_forensics.py work.pcap --output report.txt` |
| Export HTTP | `pcap_forensics.py work.pcap -x --directory out/` |

Pitfalls: truncated snaplen, time skew, reassembled-vs-packet-local mismatch, offload checksum noise, stale filter/`Decode As` hiding traffic, forcing over export dirs. Clear filter + `Decode As → Reset` before any "nothing found".

Save: `capinfos` + Hierarchy/Conversations screenshots (or `--output report.txt`), filter + packet nos. + Follow transcript, `out/` listing per exfil claim, cred packet no. + context, and negatives tried (`streams 0–99, HTTP export 0 objects, DNS pass clean`).
