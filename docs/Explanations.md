# AI explanations

When an application is blocked, the desktop notice can ask an AI model what the application is, why it would connect,
and what you gain or lose by allowing it. The answer only helps you decide. It never allows or blocks anything, it can
be wrong, and it never states that an application is safe.

Two providers are supported, each with your own API key: **Anthropic** (Claude models) and **NVIDIA** (its API
catalog). The provider follows the model you choose: models named `claude-...` use Anthropic, the others NVIDIA.

## Setup

In **Settings → AI explanations**:

1. Choose the model. The key field, the consent and the texts below it switch to that model's provider.
2. Paste the provider's API key and choose **Save key**: an Anthropic key starts with `sk-ant-` (create it in the
   Claude Console), an NVIDIA key with `nvapi-` (create it in NVIDIA's API catalog). Requests use your account with
   that provider and its terms.
3. Check **Send app details to <provider> when an explanation is requested**. Consent is kept per provider: agreeing
   to send details to one does not cover the other. Without it, the notice only offers to open Settings.
4. Optionally choose the language and **Explain automatically when a notice appears**. **Test with Notepad** checks
   the key and the model.

The default model is `claude-haiku-5-5`. In a comparison on 13 real blocked applications it gave sound advice in about
3.5 seconds per answer; `claude-opus-5-5` was slightly sharper (for example, it linked a `curl.exe` download to the
application that ran it) in about 7 seconds, and `claude-sonnet-5-5` sat in between. On NVIDIA,
`nvidia/nemotron-3-ultra-550b-a55b` answered in 10 to 35 seconds or not at all at busy times. The models a provider
offers change over time: if one stops answering, choose another and use **Test with Notepad**.

The answer says what the application is, whether it is the application itself or a helper such as an updater, what
its folder and signature indicate about it, and what you lose by blocking it. It suggests blocking telemetry, crash
reporting, advertising and news feeds, and mentions a temporary Allow when blocking could get in the way later.

## What is sent

Only when you ask (or when automatic explanations are on), for the application on the notice:

- the file name and its folder, with your user folder replaced by `%USERPROFILE%` and your account name removed;
- the signer of its signature (embedded, Windows catalog or app package), as verified by the engine, or that it has none;
- the product name, description, company and version stored in the file;
- the public address and port it tried to reach, and the server name the application looked up for that address
  when the engine saw it. Addresses on your local network, and their names, are not sent;
- the file name of the program that started it, when it is still running (for example `Code.exe` for a `node.exe`);
- for an LGA application (see below), a fixed sentence saying so.

Never the file itself, its command line, your account name or anything else on your computer.

## Known applications

Before any model is asked, the notice checks a small catalog that ships with GateBouncer
(`resources/catalog/known_apps.json`). Each entry is a signer, a file name, optionally a destination, the usual
decision and one sentence about the application; every entry was reviewed by hand before it was published. A match
shows **Known app · usually Allow** (or Block) on the notice right away. Unsigned applications never match, because
anyone can use a file name. Like the explanations, the catalog never allows or blocks anything by itself.

LGA applications are unsigned, so they are recognized by their folder instead: installed in `C:\Portable\LGA\<App>\`
or `C:\Program Files\LGA <App>\`, or built in a `build*` folder of a `C:\Portable\LGA_<Repo>\` source tree. They show
**LGA app · usually Allow**: they connect to update themselves or for a feature that needs the internet. On the notice,
in Requests and in Protection the recommended button is outlined. It is only a recommendation: you still click, and an
unsigned rule covers that exact file. Any program saved in those folders gets it, so it is no proof of origin.

## How the keys are kept

Each key is encrypted with Windows DPAPI for your Windows account and stored in
`%LOCALAPPDATA%\LGA\GateBouncer\Explain` (`anthropic.key`, `nvidia.key`), a folder only your account and SYSTEM can
open. A key is decrypted only to send a request to its own provider and is never shown, logged or passed to the
engine. Like saved browser passwords, this does not protect it from software already running under your account or
from an administrator. **Remove key** deletes the key of the selected model's provider.

## Requests

- They go only to the provider's fixed address, `https://api.anthropic.com` or `https://integrate.api.nvidia.com`, with
  TLS 1.2 or later; redirects are refused, so a key never reaches another host.
- Anthropic requests ask for low effort and a fixed answer shape, so the reply is always the expected fields. On
  Sonnet and Opus, a request declined by a safety filter is answered by a fallback model instead.
- The engine lets the installed window connect to TCP port 443 only, so explanations work while every other unknown
  application is blocked.
- One request per application at a time, answers are reused for the rest of the session, and there are at most 100
  requests a day.
- The answer is shown as plain text. Text from the model is never treated as a link or an instruction, and a late
  answer is ignored if the notice already shows another application.

`GateBouncerExplainProbe.exe` (built with the window) asks several models about a list of executables with the saved
keys and writes the answers and times to a JSON file, to compare models.
