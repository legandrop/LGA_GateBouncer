# Export, import and clean up rules

Settings → Rules keeps your rules safe and tidy. All three need the GateBouncer engine of the same release; with an
older engine the buttons stay off and say why. Import and clean up change rules, so they also need a window that can
decide (not view only).

## Export

Export saves your permanent rules to a `.gbrules` file (plain JSON). Temporary rules are never exported, and the rows
that a rule for an app, a publisher or a folder already covers are rebuilt by themselves.

- **Full backup**: every permanent rule (for a file, an app, a publisher or a folder) and the two Protection switches.
  Use it to bring everything back after reinstalling Windows. The file lists the paths of your programs and folders:
  keep it for yourself.
- **Share**: only rules by signature, an app or a publisher, for the whole app or for one server. No paths, folders or
  switches, so nothing about your PC goes in the file.

## Import

Choose a `.gbrules` file. It is checked first (format, version, up to 8 MB and 20,000 rules); entries GateBouncer does
not know are listed as skipped, never guessed. Then a list shows what would happen:

- **New**: rules you do not have. They are on and get added.
- **Conflicts with your rules**: you have a different rule for the same app, for example Block where the file says
  Allow, or rules for single servers where the file has one for the whole app. They are off: yours stays unless you
  turn the row on, and then the rule in the file replaces yours.
- **Already in your rules**: exactly the same rule. Nothing to do.
- **Skipped**: a folder that is not on this PC, a temporary rule, invalid data, or an all-apps rule for a Windows
  publisher.

A rule for a file that is not on this PC yet is still imported: it waits for the file. A full backup also offers the
two Protection switches, off by default, so your current settings stay unless you choose them. Nothing changes until
you press Import; at the end a summary says how many rules were added, replaced or kept, and why any failed.

## Clean up

Clean up suggests rules to remove, in four groups:

1. **Program no longer exists**: a rule for a file that is not on this PC. On.
2. **Folder no longer exists**: a rule for a folder that is not on this PC. On.
3. **Installers not used in 14 days**: setup and update programs, or programs in Temp or Downloads. Off.
4. **Not used in 90 days**: no connection attempt in that time. Off.

A drive or a server that does not answer is not taken as missing. The engine notes when each rule is used (a DNS query,
a connection or a block, for Allow and Block alike) from the first start of this release on: until enough days have
passed since then, nothing is suggested for not being used, and the window says since when use is tracked.

Nothing is ever removed on its own. When you press Remove, a full backup is saved first in
`%LOCALAPPDATA%\LGA\GateBouncer\Backups`, and the summary shows where. To undo, import that file.
