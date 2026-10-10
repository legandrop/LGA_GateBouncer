# Windows transport bundle

`scripts/assemble_windows_package.ps1` assembles the current 17-file administrative source set from the Qt GUI build, the Windows SDK service build, Qt 6.8.2 MinGW64, and its MinGW runtime. It copies the repository's Inter fonts and creates the exact `qt.conf` expected by deployment admission.

Run it in a new PowerShell process with absolute paths on fixed local drives:

```powershell
& .\scripts\assemble_windows_package.ps1 -QtBuild <gui-build> -SdkBuild <service-build> -QtRoot <qt-mingw-root> -MinGwRoot <mingw-root> -QtDocsRoot <qt-6.8.2-docs> -StandardLicensesRoot <standard-license-texts> -OutputRoot <new-bundle-directory>
```

The output parent must exist. The output directory must be new and separate from every input. Each output is created relative to its retained original parent handle using a single filename and a create-only disposition. Missing files, reparse points, existing outputs, changed retained identities, or a failed write/readback stop assembly with exit code 2. Partial output is preserved after a failure; it must not be distributed.

The notice input set is explicit: 49 original Qt Core/GUI attribution pages, the three module index pages, and `qtdoc/licensing.html`, `licenses-used-in-qt.html` and `qtentrypoint.html` from the installed Qt 6.8.2 documentation. The original HTML bytes are copied; documentation assets and relative navigation are not included. The script also copies Qt's installed `sbom/qtbase-6.8.2.spdx.json`, GCC license and runtime exception texts, the winpthreads license, and the repository's Inter license. The supplied standard license directory must contain `LGPL-3.0-only.txt`, `GPL-3.0-only.txt`, `GPL-2.0-only.txt` and `Qt-GPL-exception-1.0.txt`. These are labeled as standard license texts and are not represented as Qt 6.8.2 source. All 65 notice files must exist; the script does not download or fabricate missing materials. These materials do not identify every compiled third-party component or certify all redistribution requirements; applicable source, attribution, relinking and documentation redistribution obligations still require a distribution review.

The resulting directories have different purposes:

- `source/` contains exactly the 17 input files expected by the administrative preparation code, without a deployment manifest or license extras.
- `notices/` contains the supplied license materials.
- `BUNDLE.txt` identifies the output as a transport bundle.

Administrative preparation computes and writes its own deployment inventory from retained source files. This assembler does not create a deployment manifest.

Keep the notices with the bundle. A future installer must deliver them separately from the closed application inventory. This script does not grant administrative ACLs, create a laboratory gate, install or start a service, register login startup, sign binaries, package a driver, or establish network protection. A transport bundle is not an installed deployment.
