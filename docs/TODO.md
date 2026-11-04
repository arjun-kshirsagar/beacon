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
