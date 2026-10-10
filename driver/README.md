# TCP initial classifier

This WDM driver supplies retained initial outbound TCP causes at ALE connect IPv4
and IPv6. Its inspection callouts return Continue only with ACTION_WRITE. They
never authorize traffic. The existing principal policy owns permanent Allow and
Block rules. UDP, reauthorization, elevated-IRQL acquisition, AppContainer causes,
Once, process-instance permissions and timed enforcement are unsupported.

The device admits only LocalSystem with the enabled LGAGateBouncerLab service SID,
one retained caller process and one file object. At PASSIVE_LEVEL, the callback
requires the current process context to match the OS endpoint-owner metadata and
references that EPROCESS immediately, without looking up a saved PID. The OS
endpoint token must be the same primary token. It copies
the OS APP_ID, creation time, endpoint and tuple into a bounded queue. A delivered
handle is opened directly from that referenced process object in the service's
handle table. PID and creation-time fields are descriptive; they never reacquire
authority. Token replacement, exit, queue loss or source reset invalidates causes.
File cleanup releases the cause queue and its process/token references.

DriverEntry loads an inert device with no registered callouts. The authenticated
service performs START before source acquisition; START registers the callbacks
and dynamic WFP objects after the driver image is already retained. This initial
cut deliberately provides no DriverUnload: removal requires a guest reboot. A
partial START failure preserves every acquired session/callout and marks the
device unavailable until reboot. It never reports a failed unregister as drain
or unloads an image that might still own callbacks. Closing the service file
stops cause acquisition; the retained inspection callouts continue without granting
permissions. Dynamic driver lifecycle and unattended repair are not implemented.

NativeSource reads this device through its private owner and retains the cause
through draft and commit. A cause is an initial classifier indication, not a
correlated netevent drop or a suspended socket. Before admitting a permanent
future policy, the source reads the classifier's exact registered callout/filter,
the existing policy inventory and the current runtime Block baseline, and rejects
an own matching outbound Allow. That readback does not prove platform-wide traffic
coverage or precedence over other firewall providers.

Build the standalone CMake project with MSVC x64 and explicit WDK/SDK roots. It
produces an unsigned `.sys`. Building does not install, load or sign a driver.
There is no INF, installer, production signing or driver deployment admission yet.
The service opens a present device; when absent it retains its netevent producer
and does not advertise kernel permission scopes. Driver execution and causal
traffic validation must occur in an explicitly authorized guest deployment.
