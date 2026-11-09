# TODO

Work left over from earlier phases. Phase numbers refer to the roadmap in
[VISION.md](VISION.md).

## Phase 7: offline file sharing

The code is on `main` (`core/offline`, `mobile/files.go`, the Android Files tab
and `WifiDirect.kt`). The flow (share, request, offer, join, fetch from several
devices) is tested in process (`core/offline`, `TestThreeDevices`), but not yet
on phones.

- [ ] **Run the milestone on phones.** Three phones in airplane mode, with
      Bluetooth and Wi-Fi turned back on. Alice shares a 50 MB file; Bob fetches
      it; Carol fetches it and her Files card shows "Received from 2 phones".
      The last build never reached a phone (the Motorola dropped off adb during
      the install).
- [ ] **Check Wi-Fi Direct on each phone model.** Group creation with a fixed
      name and passphrase needs Android 10+. Check that clients join without a
      prompt, that a client gets its address on the `p2p` interface within the
      10-second retry window, and that clients in one group can reach each
      other (Carol to Bob, not just to the group owner).
- [ ] **Bridging.** A phone with internet downloads a torrent or magnet link
      from the global swarm (trackers and DHT) and announces it on the mesh while
      it downloads, so offline phones nearby can fetch pieces it already has.
      Needs: a mobile entry point that starts an internet download, announcing
      the share before completion, and offers that work for partial swarms.
- [ ] **Groups across files.** A device is in one Wi-Fi Direct group at a time
      and declines offers for another group. Decide whether to leave a group
      that has no active transfers instead of declining.

## Phase 8: attack lab

- [ ] **Run the fake-announcement attack on phones.** It is covered by a Go
      test only; the Docker testbed has no Wi-Fi Direct.
- [ ] **Sign link setup.** A replayed announce with TTL 7 can get a
      neighbour's link closed once a minute (see attacks.md, "Known limits").
      A signed link handshake would close this; it changes the wire format.

## Phase 9: release

The release pipeline is in place ([RELEASING.md](RELEASING.md)); v1.0 is not
tagged yet. What is left needs the maintainer:

- [ ] **Create the release key** and add it as secrets of the `release`
      environment on GitHub (RELEASING.md, "One-time setup").
- [ ] **Put the key's certificate fingerprint in the README**, replacing the
      placeholder under "Install".
- [x] **Choose a license.** MIT, in `LICENSE`; the release archives include it.
- [ ] **Merge to `main`, let CI pass, then tag `v1.0.0`.** CI has not run on
      GitHub yet; the workflows were checked locally (GoReleaser snapshot,
      signed APK with a throwaway key).
