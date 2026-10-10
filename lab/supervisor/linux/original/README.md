# Original Linux guest

This standalone native component creates one bounded Linux session from an original Ubuntu cloud image and its own public NoCloud seed. It creates a fixed guest account, reads the guest host key from the actual guest, and runs a fixed capture through its own OpenSSH child. Credentials remain in CNG memory; only the public key enters the seed.

The Linux build produces `gatebouncer-linux-original` and `gatebouncer-capture`. It does not run either executable. On Windows, configure with `GB_ORIGINAL_GUEST_ARTIFACT_DIR` pointing to those two verified executables. Their actual hashes and the newly built Proxy hash are compiled into the host. Verify the source commit and artifact digest before using a downloaded build.

The host entry takes a verified media directory and a new output directory. The media directory contains the two Linux executables, `ubuntu-24.04-server-cloudimg-amd64.img`, `SHA256SUMS`, `SHA256SUMS.gpg`, `ubuntu-cloudimage-keyring.gpg`, and `qemu-w64-setup-20260811.exe`. The QEMU installer is read as an archive, never executed. Resource pins identify one exact Ubuntu image, QEMU archive, GPG installation, 7-Zip installation and OpenSSH installation. A changed resource stops the operation.

The host requires its original containing Job and isolated desktop. It starts QEMU once with two virtual CPUs, 2 GiB RAM and software emulation, with a total 300-second boot/session/shutdown budget. It does not enable host virtualization features, alter the host firewall, install services or reboot the host. Its working disk permits QEMU writes; the initial image hash does not certify later mutable disk contents.

The guest channel requires INIT before HELLO, matching generation and sequence, and explicit acknowledgement. Each identity request and signature checks fresh guest readers through this same original channel. A connected pipe, DTO, PID, MAC address or public record alone grants no credential operation. The Proxy is created by OpenSSH and verifies the actual process lineage before bridging bytes.

This component needs independent source review, Windows build verification and an actual bounded guest run before its session behavior can be considered validated. The separate local Linux reader remains an observer and does not authenticate this session.

Upstream resources: [Ubuntu cloud images](https://cloud-images.ubuntu.com/releases/noble/release/), [Ubuntu checksum verification](https://cloud-images.ubuntu.com/docs/how-to/verify-image-checksums/), [QEMU Windows builds](https://www.qemu.org/download/#windows), [Windows build provider](https://qemu.weilnetz.de/w64/). Third-party executables and firmware are not redistributed here; their upstream licenses apply.
