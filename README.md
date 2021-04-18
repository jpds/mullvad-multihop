# Mullvad Multihop config generator

This project simply takes a dump of Mullvad relay JSON and generates every
possible multihop configuration from it, as opposed to selectively creating
these in the web interface.

Note that you will need to have generated a single configuration from the
Mullvad accounts interface to have a WireGuard key and client IP address
registered with them.

This script does not use the Mullvad APIs or assume that there is an internet
connection available.

Once you have a key and client IP address, you can get download the Mullvad
relay JSON with:

```
$ curl https://api.mullvad.net/public/relays/wireguard/v1/ > mullvad-relays.json
```

And then use this script to generate all the configs:

```
$ mkdir -v configs
$ python mlvd-multihop.py --json mullvad-relays.json \
	--config-dir configs \
        --wg-key 'wg-key' \
	--wg-address 'clientips'
```

There's a very large number of multihop permutations available, so if you
simply want a random sample of them, use the following commands to move 100
configurations to a directory called `selection`:

```
mkdir -p selection/
find configs/ -mindepth 1 -maxdepth 1 ! -name '.*' -print0 |
  shuf -n 100 -z |
  xargs -r0 mv -t selection
```

This directory can then be moved to your `/etc/wireguard/` directory or zipped
up and moved to a mobile device. Once there, it can be imported within the
WireGuard app for use.

Please note that this Python script exists purely for convenience - it is not
in any way affiliated with either Mullvad or the WireGuard project.
