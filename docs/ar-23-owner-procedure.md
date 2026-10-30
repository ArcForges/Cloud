# AR-23: the owner's Windows Hello procedure

AR-23 is the one acceptance item of the account pages (AF-CTR-03 part A2) that needs a person and real hardware: creating a
passkey with the owner's own **Windows Hello** and signing in with it, on the acceptance environment. Everything else the browser
acceptance does uses Chromium's virtual authenticator, which is **MOCKED hardware in a real browser**
([proof bootstrap and acceptance](center-identity.md#proof-bootstrap-and-acceptance)). AR-23 stays pending until the owner has run
this procedure and handed back the evidence below. Nothing here touches production: the script refuses every host but
`proof.arcforges.com` and `localhost`.

## What it proves, and what it does not

It proves that the pages' passkey registration and sign-in work with a platform authenticator Windows provides, with user
verification, in the Playwright Chromium that the acceptance uses (`chromium-1243`): the creation options and the assertion the
pages ask for are accepted by Windows Hello, and the center accepts what it makes. It does not prove anything about other
browsers, other operating systems, a phone, or the passkey's synchronisation, and it is not an accessibility audit.

## Before you start

- The acceptance environment is deployed from the merged `main` with the pages surface, and the owner exists: the MOCKED
  acceptance has run at least once, so `%USERPROFILE%\.arcforges\proof-acceptance\owner-credential.json` exists. (Without it
  the script refuses `--real-authenticator` and says so.)
- Windows Hello is set up for your Windows account (Settings, Accounts, Sign-in options: a PIN, fingerprint or face).
- A PowerShell with Node 24.21 on its path, and the repository checked out at the merged `main`; the browser is the already
  installed Playwright `chromium-1243`:
  `%LOCALAPPDATA%\ms-playwright\chromium-1243\chrome-win64\chrome.exe` (version 153.0.8010.12; the script finds it by itself). Do
  not install or download a browser.
- You can answer the Windows prompts at the keyboard for about five minutes. The script waits up to three minutes for each prompt.

## Commands (Windows, PowerShell)

```powershell
cd <your checkout of ArcForges/Cloud>
git switch main; git pull --ff-only
cd eng\verification\browser; npm ci --engine-strict=false; cd ..\..\..   # installs only playwright-core 1.63.0, from the exact lockfile
node eng/verification/browser/acceptance.ts --real-authenticator
```

`--engine-strict=false` is there because the package states `npm >=11.19.0 <12` and a PowerShell that finds npm 12 first would
otherwise stop with `EBADENGINE`; npm then only warns and installs the locked package. The run takes a few minutes: the script holds
its requests to the edge limit of the proof environment.

The address the script opens is `https://proof.arcforges.com/api/account/sign-in`. A Chromium window opens, because Windows Hello
needs a window you can see; leave it alone except for the Windows prompts, and do not type into it.

## What happens, and what you see

1. **Sign in with the saved virtual credential.** The script signs in on the page (no prompt) and opens "Account and passkeys".
2. **Step up and reach the passkey creation.** The script fills "Name for the new passkey" with `Windows Hello AR-23 <date>` and
   presses "Add a passkey"; the virtual credential proves the step-up (no prompt). The page "Create your passkey" appears.
3. **Windows Hello creates the passkey.** The script removes the virtual authenticator, prints
   `>>> Windows Hello asks you to confirm now`, and presses "Create the passkey". **A Windows Security dialog asks you to create a
   passkey for `proof.arcforges.com`.** Check that it names that site, then confirm with your PIN, fingerprint or face. The page
   returns to "Account and passkeys", which now lists the new passkey by its name, still "Never" used.
4. **Sign out**, then **sign in with Windows Hello.** The script prints `>>> Windows Hello asks you to choose the passkey and
confirm`. **Windows lists the passkey(s) for `proof.arcforges.com`; choose yours and confirm.** The page opens "Account and
   passkeys" again. The script then reads the pages' own "last used" times: the new passkey must now be marked used and the
   virtual passkey's time must not have changed, which is what shows that Windows Hello, and not the virtual credential, signed in.
5. The script signs out and prints `PASSED`.

If you close the dialog of step 3 (the creation), or its prompt times out, the page shows "The passkey prompt was closed. Try again
when you are ready." and the script reports `FAILED` naming the step. No passkey was created, so run the command again; it starts
from the saved virtual credential each time.

If the script fails after the Windows Hello passkey was created (the passkeys page lists it, or you closed the sign-in prompt of step 4),
that passkey is on the account and in Windows, and the next run's creation page lists it among the passkeys to exclude: Windows Hello
then refuses the creation, and the script fails at step 3 with "That passkey is already registered." Do not run the command again
yet. Either sign in by hand on the proof site with that passkey, or remove it as the paragraph "Afterwards" describes, and only then
run the command. If no Windows dialog appears at all in `chromium-1243`, stop and report that; do not switch browsers.

## Evidence to hand back

- The script's last lines (`PASSED`, and the count of steps by label: the two Windows Hello steps are labelled
  `REAL hardware: Windows Hello`, every other step `MOCKED hardware: Chromium virtual authenticator in a real browser` or
  `no authenticator`) and the file `artifacts\browser-acceptance.json` (steps, counts and flags; it holds no token, key or cookie).
  It must show `mode: real-authenticator`, `result: passed`, `windowsHelloPasskeyCreated: true` and `signedInWithWindowsHello: true`.
- Your own statement, with the date and time: that you saw the Windows Security dialog twice (create and sign in), that it named
  `proof.arcforges.com`, and that you confirmed it yourself with Windows Hello. Add the Windows version (`winver`) and the Chromium
  version the script printed on its first line.
- No screenshot is needed, and the script takes none (tracing, screenshots and videos are off by design). Do not send the credential
  file, the bootstrap file or any cookie or token to anyone.

## Afterwards

The Windows Hello passkey stays on the proof owner's account and in Windows (Settings, Accounts, Passkeys). The account then has the
virtual passkey and yours, which is allowed. To remove yours: open "Account and passkeys" on the proof site, press "Remove" on
its row (the page asks for a passkey check first, which Windows Hello answers), and delete the passkey for `proof.arcforges.com`
in Windows. Removing it is not part of AR-23, and the script never removes it.

If you ever lose the saved virtual credential, or restore an older copy of it (the center refuses a counter that does not rise), the
runbook's total-loss steps apply: drop `arcforges_acceptance` in the Neon Console and dispatch a new deployment with a new
bootstrap ([proof bootstrap and acceptance](center-identity.md#proof-bootstrap-and-acceptance)).
