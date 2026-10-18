# Sanitisation record — public release

Everything in this directory was written from the private incident notes with the
following identifiers removed or generalised. Nothing here links the incident to a
person, a network, or a specific host.

## Removed

| Category | Treatment |
|---|---|
| Plex account identity (username, e-mail, display name) | removed everywhere |
| `PlexOnlineToken`, `MachineIdentifier`, `ProcessedMachineIdentifier`, `AnonymousMachineIdentifier`, `CertificateUUID` | removed; the token alone is a live credential |
| Public IPv4 of the affected network | removed (was visible in the Plex and router logs) |
| Hostname and host model | replaced with "the host" / "the container" |
| LAN addressing (server, clients, router/IGD) and the mapped external port | removed; the README says "Plex's own UPnP mapping" without numbers |
| Router make/model and management address | removed |
| Local filesystem paths (`/home/<user>`, media/NAS mount points) | replaced with `<Plex config>`, `…/Codecs/<set-id>-…` |
| Media library names, a specific title used in a transcode argv, and the container/compose project name | removed |
| Exact internal container PIDs, uids and the local user name | removed; described as "container PID 1", "the configured PUID" |
| Plex file names of unrelated services on the same host | removed |

## Deliberately kept

- Plex versions (1.43.2.10687 vulnerable, 1.43.4.10903 after the fix) — needed for
  scoping by other admins.
- Plex's own codec-set directory name (`c75335c-…`): it is derived from the Plex build,
  identical on every host running that version, and tells readers which cache to inspect.
- Attacker infrastructure: IPs, ASNs, domain, URLs, hashes, operator tags. All of it is
  public/rented infrastructure, not personal data.
- The full process command lines of the dropper and the miner — that is the detection
  content.

## Not published

- Both binaries. Hashes, sizes, ELF metadata, section layout and YARA rules are here;
  the samples are available to the vendor and to AV researchers on request.
- The unredacted Plex log excerpt (it carries the affected network's public address).
  A redacted excerpt can be supplied to the vendor under the same terms.
- Any reproduction of the initial access step. It was not captured, and the patched
  version is the fix regardless.

## Check before you push

Run this from the repository root with your own values substituted; it must print
nothing:

```bash
grep -rInE '<plex-username>|<email-domain>|<public-ip>|<hostname>|/home/<user>|<mount-point>|<machine-identifier>|<plex-token>' .
git log -p | grep -inE '<plex-username>|<email-domain>|<public-ip>|<hostname>'
```

Check history too, not just the working tree: a value committed once stays in the
repository even after it is edited out.
