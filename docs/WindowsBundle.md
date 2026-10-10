# Windows transport bundle

`scripts/assemble_windows_package.ps1` assembles the current 18-file administrative source set from the Qt GUI build (including the offline signature helper), the Windows SDK service build, Qt 6.8.2 MinGW64, and its MinGW runtime. It copies the repository's Inter fonts and creates the exact `qt.conf` expected by deployment admission.

Run it in a new PowerShell process with absolute paths on fixed local drives:

```powershell
& .\scripts\assemble_windows_package.ps1 -QtBuild <gui-build> -SdkBuild <service-build> -QtRoot <qt-mingw-root> -MinGwRoot <mingw-root> -QtDocsRoot <qt-6.8.2-docs> -StandardLicensesRoot <standard-license-texts> -OutputRoot <new-bundle-directory>
```

The output parent must exist. The output directory must be new and separate from every input. Each output is created relative to its retained original parent handle using a single filename and a create-only disposition. Missing files, reparse points, existing outputs, changed retained identities, or a failed write/readback stop assembly with exit code 2. Partial output is preserved after a failure; it must not be distributed.

The notice input set is explicit: 49 original Qt Core/GUI attribution pages, the three module index pages, and `qtdoc/licensing.html`, `licenses-used-in-qt.html` and `qtentrypoint.html` from the installed Qt 6.8.2 documentation. The original HTML bytes are copied; documentation assets and relative navigation are not included. The script also copies Qt's installed `sbom/qtbase-6.8.2.spdx.json`, GCC license and runtime exception texts, the winpthreads license, and the repository's Inter license. The supplied standard license directory must contain `LGPL-3.0-only.txt`, `GPL-3.0-only.txt`, `GPL-2.0-only.txt` and `Qt-GPL-exception-1.0.txt`. These are labeled as standard license texts and are not represented as Qt 6.8.2 source. All 65 notice files must exist; the script does not download or fabricate missing materials. These materials do not identify every compiled third-party component or certify all redistribution requirements; applicable source, attribution, relinking and documentation redistribution obligations still require a distribution review.

The resulting directories have different purposes:

- `source/` contains exactly the 18 input files expected by the administrative preparation code, without a deployment manifest or license extras.
- `notices/` contains the supplied license materials.
- `BUNDLE.txt` identifies the output as a transport bundle.

Administrative preparation computes and writes its own deployment inventory from retained source files. This assembler does not create a deployment manifest.

The service has a separate product preparation entry, `--prepare-deployment <source> <new-package> <new-store> <account-SID>`. It requires an elevated administrator running the original service image from an authenticated administrative source directory: the exact 18-file set, retained original files and directories, protected administrative ACLs, and no reparse points. The transport bundle alone does not satisfy these prerequisites. Applying an ACL or calculating a hash does not establish the provenance of an external binary; distribution authentication remains a separate requirement.

Product preparation acquires its administrative lease and original source before creating a fresh protected `HKLM\SOFTWARE\LGA\GateBouncer` root. The `LGA` parent must be protected and must not be a registry link; it is created with administrative ACLs if absent, while an existing unprotected parent is rejected. An existing product root, package or store is rejected. It stages the original files, writes and reads back its own inventory and complete configuration, creates the `LGAGateBouncer` service disabled, and only publishes automatic startup after those checks. It does not start the service. Product service dispatch uses `--service` and admits the retained deployment, configuration, SCM image, PID and product service SID. It does not use `EnableWfp` as authorization. Explicit `--prepare-guest-deployment` and `--service --guest-wfp` retain the separate laboratory gate and service identity.

Product maintenance uses `--update-deployment <current> <source> <new-package>`, `--finalize-deployment <current>` and `--uninstall-deployment <current>`. These reuse the original maintenance owners and state readbacks. Finalization accepts only the complete durable prepared tuple with a stopped service and zero PID, and finishes disabled-to-automatic startup without starting it. Failures preserve partial objects and recovery state; preparation does not adopt a partial or existing deployment. Uninstallation retains package and store data and does not unload a driver.

The classifier driver remains outside this bundle. Its source has no production signing, INF, kernel-service admission or installation entry; its device admission currently uses the laboratory service identity. Its lifetime has no unload callback, and documented partial-start/removal cases require a reboot. Product driver admission and signed distribution therefore remain required work. Without that admitted device, the existing net-event producer can expose only its supported fallback: process-instance, Once, duration and complete protection are not established by a running service or available net events. Preparation, startup mode and transport assembly do not certify network protection.

Keep the notices with the bundle. A future installer must deliver them separately from the closed application inventory. This script does not grant administrative ACLs, create a laboratory gate, install or start a service, register login startup, sign binaries, package a driver, or establish network protection. A transport bundle is not an installed deployment.
