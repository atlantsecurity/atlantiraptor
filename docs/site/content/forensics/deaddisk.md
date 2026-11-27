---
title: Disk images and dead disks
description: Run Atlantiraptor artifacts against disk images (E01, VMDK, VHDX, raw) and mounted disks, as if they were live endpoints.
---

Sometimes all you have is a disk image: a laptop sent in for analysis, a
cloud VM snapshot, an acquisition from another tool. Atlantiraptor can run
its normal artifacts against an image by **remapping** its accessors:
`file`, `ntfs`, `registry` and the others read from the image instead of
the machine they run on. The same artifacts, the same parameters, the same
results, without changing anything.

## Supported images

| Format | Accessor |
|---|---|
| E01 / EWF | `ewf` |
| VMDK (VMware) | `vmdk` |
| VHDX (Hyper-V, Azure) | `vhdx` |
| Raw (`dd`) images | `file` with `offset` for partitions |
| NTFS, ext4 and FAT partitions inside them | `raw_ntfs`, `raw_ext4`, `fat` |
| A disk mounted read-only as a folder | `file` |

## The easy way: a virtual client

`Server.Utils.DeadDiskClient`, run under **Server collections**, does the
whole job:

1. Put the image somewhere the server can read it.
2. Collect `Server.Utils.DeadDiskClient` with **ImagePath** set to the
   image and **Hostname** set to a name for it.
3. It inspects the image, builds a remapping, and starts a **virtual
   client** on the server that reads from the image.

The virtual client appears in the client list like any other host. Collect
from it, hunt it, browse its files and registry. It stays up while the
collection runs (an hour by default; set a longer timeout under resources),
and cancelling the collection stops it.

## The command line way

Build a remapping configuration for an image or a mounted Windows folder:

```bash
atlantiraptor deaddisk --hostname WS-0142 \
    --add_windows_disk /evidence/ws-0142.E01 remap.yaml
```

Then use it with any command, for example to collect artifacts straight
into a zip:

```bash
atlantiraptor --remap remap.yaml artifacts collect \
    Windows.Forensics.Prefetch Windows.EventLogs.RDPAuth \
    --output ws-0142.zip
```

Or start a client with it (`atlantiraptor --remap remap.yaml --config
client.config.yaml client`) to make a virtual host on your server.

The resulting zip can be [imported](/offline/importing/) into the server.

## Remapping by hand

A remapping configuration lists, for each accessor the artifacts will use,
where the data really comes from. `Generic.Utils.DeadDiskRemapping` builds
one from an image, and `remap()` applies one inside a query. Write your own
when an image has an unusual layout, for example several partitions or a
BitLocker volume you decrypted elsewhere.

## Things that don't work on images

Anything that needs a running system: processes, network connections,
memory, live event monitoring, and running programs. Artifacts that check
the OS with `info()` see the remapped host name and OS, so OS-specific
artifacts run as expected.
