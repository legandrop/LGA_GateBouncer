# Local Linux reader

This standalone Linux observer retains its own process, filesystem and local
kernel network readers. It takes no arguments and reads no input or environment
configuration. It expects a preinstalled `gatebouncerlab` account with home
`/home/gatebouncerlab`, shell `/bin/bash`, a single P256 public authorized key and
an Ed25519 public host key. The network profile has one active Ethernet interface
and one global unicast address.

The observer checks the retained readers and their complete paths, and rejects
filesystem or network changes and notification loss. It closes its own resources
explicitly. Its output contains only a local status and a resource count.

An observation does not establish a VM identity, an installation, an authenticated
channel or any permission. The observer does not create an account, change network
settings, install anything, launch SSH, read private keys or sign data. Installation
custody and the link to a particular VM must be established separately.
