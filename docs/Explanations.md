# AI explanations

When an application is blocked, the desktop notice can ask NVIDIA what the application is, why it would connect, and
what you gain or lose by allowing it. The answer only helps you decide. It never allows or blocks anything, it can be
wrong, and it never states that an application is safe.

## Setup

In **Settings → AI explanations**:

1. Paste your NVIDIA API key (it starts with `nvapi-`) and choose **Save key**. You can create one in NVIDIA's API
   catalog. Requests use your NVIDIA account and its terms.
2. Check **Send app details to NVIDIA when an explanation is requested**. Without it, the notice only offers to open
   Settings.
3. Optionally choose the model and the language, and **Explain automatically when a notice appears**. **Test with
   Notepad** checks the key and the model.

## What is sent

Only when you ask (or when automatic explanations are on), for the application on the notice:

- the file name and its folder, with your user folder replaced by `%USERPROFILE%` and your account name removed;
- the signer of its embedded signature, as verified by the engine, or that it has none;
- the product name, description, company and version stored in the file;
- the public address and port it tried to reach. Addresses on your local network are not sent.

Never the file itself, its command line, your account name or anything else on your computer.

## How the key is kept

The key is encrypted with Windows DPAPI for your Windows account and stored in
`%LOCALAPPDATA%\LGA\GateBouncer\Explain`, a folder only your account and SYSTEM can open. It is decrypted only to send a
request and is never shown, logged or passed to the engine. Like saved browser passwords, this does not protect it
from software already running under your account or from an administrator. **Remove key** deletes it.

## Requests

- They go only to `https://integrate.api.nvidia.com`, with TLS 1.2 or later; redirects are refused.
- The engine lets the installed window connect to TCP port 443 only, so explanations work while every other unknown
  application is blocked.
- One request per application at a time, answers are reused for the rest of the session, and there are at most 100
  requests a day.
- The answer is shown as plain text. Text from the model is never treated as a link or an instruction, and a late
  answer is ignored if the notice already shows another application.

`GateBouncerExplainProbe.exe` (built with the window) asks several models about a list of executables with the saved
key and writes the answers and times to a JSON file, to compare models.
