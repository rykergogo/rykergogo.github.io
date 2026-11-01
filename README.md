# Rykergogo - Ethical Hacking
## Huntress CTF 2026 Solutions!
### These are my write-ups from Huntress CTF 2026 — mostly web exploitation, static malware config extraction, and a couple of mobile challenges.

*Heads up: unlike my other posts these are command-line / terminal walkthroughs, so there aren't many screenshots — the payloads and commands tell the story. Most of the web boxes hand back a per-instance `proof_<hex>` evidence token that you submit on the scoreboard to get the flag, and every one has an `/api/clues` route that leaks the feature endpoint and your role.*

#### [Web] Query Me This

A search box backed by an `articles` table that only shows rows where `visibility='public'`. The flag is a hidden `private` row.

The query turns out to be `... WHERE col LIKE '%<q>%'`, so a leading `'` makes `LIKE '%'` — always true. That's the trap: every `' OR 1=1` floods all rows and *looks* like a bypass that does nothing. The real lever is `AND`, not `OR`.

Backend is SQLite, errors are swallowed (a broken query just says "Nothing matched"), and the only filtering is on comment-to-end tokens (`--`, `#`, `/*`). So instead of commenting out the rest of the query, I balance the trailing `%'` with a `'1' like '1` tail. That gives a clean boolean oracle — rows = TRUE, "Nothing matched" = FALSE:

```
' and (CONDITION) and '1' like '1
```

With no data reflected on the page, this is pure boolean-blind extraction. Walk `sqlite_master` (count → name length → each character via a binary search on `unicode(substr(...))`), pull the schema out of the `CREATE TABLE` text, then dump the hidden row:

```
' and ((select summary from articles where visibility='private')='proof_...') and '1' like '1
```

The server only ever answers true/false, but asking a few hundred of the right yes/no questions reconstructs the whole string. Flag captured — and the same payload worked unchanged across three instances (`/lookup`, `/explore`, `/search`); only the endpoint path changed.

#### [Web] Django Dispatch

A tiny Django app with one authz boundary. Your role is `analyst`, server-side, with no cookie to tamper, so there's nothing client-side to mess with. The clue points at `/dispatch-fa3df6`.

The whole challenge is a path-normalization mismatch between the auth gate and the URLconf:

```
GET /dispatch-fa3df6/   →  404 not_found
GET /dispatch-fa3df6    →  200  (protected effect fires!)
```

The no-slash form resolves straight to the privileged view, and the trust decision never stops it — classic `APPEND_SLASH` / proxy-vs-urlconf disagreement. Method doesn't matter (GET/POST/OPTIONS all work), and the proof *is* the response body:

```json
{"ok": true, "effect": "framework_authorization_bypassed", "evidence": "proof_..."}
```

One request, no payload. Nice and clean.

#### [Web] Search Mirror

A reflected-XSS box: `/execute-4d56c5?q=` drops your input straight into `#preview` via `innerHTML`, so `<img src=x onerror=...>` gives full JS execution. But the page itself holds no secret, and the callback endpoint refuses a plain request with `browser_callback_required`.

The "something to read" is a `callback_nonce` exposed at `/api/clues` — and it's only readable same-origin, which is *why* it has to come from the XSS rather than an outside request. So the chain is: read the nonce, call the callback with it, render the reflected flag back into the page.

```html
<img src=x onerror="fetch('/api/clues').then(r=>r.json()).then(c=>fetch(`/callback-77e6ec?nonce=${c.callback_nonce}`)).then(r=>r.text()).then(t=>{document.getElementById('preview').insertAdjacentHTML('beforeend',`<pre>${t}</pre>`)})">
```

One thing that bit me on another instance: a literal `+` in a URL query string decodes to a *space*, so hand-writing `'...'+c.nonce` silently breaks the JS. Use template literals (no `+` anywhere) or encode `+` as `%2B`. A later timed variant was also one-shot and checked that the callback came from the feature page — so it genuinely had to fire through the reflected XSS, not a console call. Flag captured on every instance.

#### [Web] Serialized Offender

"Your session is just a blob of misplaced trust. Reshape the bytes, sign nothing." That's the hint, and it's literal — the session is base64url'd JSON with no signature:

```
{"user":"analyst","role":"analyst"}
```

There's nothing to forge; you just flip `role` and re-encode. The only actual work is guessing the privileged string. `admin` and `superadmin` get rejected — the magic value is **`administrator`** (the formal spelling of the `admin` you start with).

```
{"user":"analyst","role":"administrator"}  →  base64url  →  POST /action-d34380
```

Server decodes it, believes the role verbatim, and returns `serialized_role_trusted` with the proof. A sibling instance used base64**url** (`-_` instead of `+/`) — worth noting, though it didn't matter here since the JSON produced no `+` or `/`.

#### [Web] Error Courtesy

An ASP.NET Core app whose own clue states the intended behavior: *"deny access when the policy service is unavailable."* The bug is that it does the opposite.

A valid `public` policy token (a `remote:<id>:<base64url-json>` string) returns only analyst-level access. The description nudges hard — *"investigate what happens when that decision cannot be decoded"* — so instead of forging a privileged scope, feed it something **undecodable**: invalid base64 after the prefix.

```
GET /submit-017890?policy=remote:<id>:%%%invalid%%%
  →  {"ok":true,"effect":"exceptional_condition_fail_open","evidence":"proof_..."}
```

The decoder throws, the access-decision code swallows the exception, and it defaults to *allow* instead of *deny*. Classic fail-open. The lesson here was trusting the challenge wording over the obvious scope-forging rabbit hole.

#### [Web] Double Spent

A two-route app: `POST /execute-bdb3f6` spends one credit (read balance → check `> 0` → decrement, and that's **not atomic**), and `GET /audit-ad790f` hands over the flag once the balance goes negative.

A fresh instance seeds the balance to exactly 1 and never regenerates, so you have to race that single credit before any clean spend consumes it. (My first instance was already spent to 0 — 3,500+ sequential attempts did nothing — so it needed a reset.)

On a fresh instance I fired **50 concurrent spends in a single tick**. Five of them read `balance == 1` and passed the `> 0` check before any decrement committed, driving the balance to **−4**. Audit flipped from `403 credit_not_overspent` to:

```json
{"ok":true,"effect":"single_credit_spent_twice","evidence":"proof_..."}
```

The `X-Arena-Diagnostic-*-Overlap` headers were the challenge literally scoring how well my requests overlapped, and the ~1.5 ms handler is exactly why the TOCTOU window is so easy to hit. Textbook double-spend.

#### [Web] If a Breach Falls in a Log

A PHP Slim app built around an export flow. `/process-c6f50d` generates exports but only ever logs a `page_view` event — never a `protected_export`. `/status-40896a` runs an "audit comparison."

The theme ("a breach that falls in a log") is the solution: you assert that a decisive event is *missing* from the log while another was *observed*:

```json
{"export_id":"e5942704d0ebb20052dc2e1c","missing_event":"protected_export","observed_event":"page_view"}
```

```json
{"ok":true,"effect":"decisive_security_event_missing","evidence":"proof_..."}
```

That `missing=protected_export, observed=page_view` pair is the only one that passes — a pure logic gate proving the security event that was never written. Flag down.

#### [Web] Trust the Build

A Go (Fiber) update-manifest activator. You get a signed manifest:

```json
{"package":"local-telemetry-adapter","version":"1.0.13078","artifact":{"build":"release-13078","hook":"passive_health"},"artifact_sha256":"c25168d2...9766","signature":"62aa5d91...f321"}
```

The instinct is to forge the signature — don't bother, it's a keyed MAC with a server-side secret (I tested every obvious preimage; none match). The real question is *what the signature covers*. Mutating fields one at a time shows it:

- change `artifact_sha256` / blank it / drop `signature` → `signed_manifest_rejected` (so the MAC covers the hash)
- change `package`/`version` → `update_not_found` (catalog key)
- change `build` → `artifact_not_supported` (artifact selector)
- change **`artifact.hook`** → *accepted!*

The `hook` is what the policy maps to routine vs restricted (`passive_health` = routine, `privileged_export` = restricted), and it sits **outside the signed scope**. So you replay the legitimately-signed routine manifest verbatim and just flip the hook:

```bash
curl -s https://<host>/inspect-4e00a5 -H 'Content-Type: application/json' \
  -d '{"package":"local-telemetry-adapter","version":"1.0.13078","artifact":{"build":"release-13078","hook":"privileged_export"},"artifact_sha256":"c25168d2...9766","signature":"62aa5d91...f321"}'
```

```json
{"effect":"unverified_update_activated","ok":true,"evidence":"proof_..."}
```

The integrity contract binds the signature to the artifact bytes but not to the field that actually drives authorization. Lovely bug.

#### [Web] Trust Transit

A Kotlin (Ktor) app, and the server even names the vuln class in its response: SSRF → object authorization. `/api/topology` leaks an internal service at `http://127.0.0.1:8080/status-8f4309` that trusts requests by **network origin** (loopback = trusted). `/api/cases` lists case `4334` (mine, `analyst`) and `11581` (the executive's, off-limits). `/submit-90943c?target=` is a server-side fetcher.

Hitting `/status-8f4309` directly gives `403 internal_service_only`. But tunneling it through the SSRF makes the request arrive *from the server itself* — i.e. as loopback — and once you're trusted, the service hands over any case `id` with no owner check. So one request defeats both the network boundary and object-level authz:

```
/submit-90943c?target=http://127.0.0.1:8080/status-8f4309?id=11581
  →  {"ok":true,"effect":"ssrf_then_object_authorization","evidence":"proof_..."}
```

The path had to be exactly `/status-8f4309` and the param had to be `?id=` (not `case=`), pointing at the executive's `11581`. The internal service gates on *where* the request comes from instead of *who* you are — chain SSRF to satisfy "where," IDOR to pick "what."

#### [Malware] Nimble

A 9-sample static-analysis set (zip password `infected`, AES — so 7z or pyzipper) spanning C/C++ ELFs, a .NET PE, JARs, a Swift binary and a Nim binary. Every sample hides its config in the same `HCFG` container, which is worth learning once because it shows up again (see Bridge Troll):

```
"HCFG" | version | 1-byte XOR key | 2-byte LE length | 4-byte LE CRC32 of plaintext | XOR'd JSON
```

The key tricks:

- Recover the one-byte XOR key from known plaintext — the JSON always starts with `{`, so `enc[0] ^ ord('{')` gives you the key instantly. It even stores the key in the header at byte 5.
- The CRC32 in the header is over the *decrypted* bytes — recompute it to confirm your decode is right and you didn't just land on a decoy.
- Day 1 also had a `recover_code` symbol that was just `mov eax, 0x1fa4 ; ret` → `8100`.

Storage moved around per day — raw in the binary, a Base64 constant in a Java class, inside the Swift data section, a Nim string literal next to a `raw[0..3] == "HCFG"` assert. For the .NET one, `objdump -p` confirms the CLR header / `mscoree.dll!_CorExeMain` stub, then ILSpy/dnSpyEx shows the `Config` byte array and the XOR loop directly. All solved statically — nothing ever executed.

#### [Malware] Bridge Troll

The same `HCFG` config format from Nimble, but cranked up to **22 language runtimes / 264 answer fields**. Once you have a generic parser (find `HCFG`, read key/length/CRC from the header, XOR the payload, verify the CRC), most of it falls out automatically. The interesting parts are the gotchas:

- **Member order for the `sha256_N` fields** comes from the ZIP central-directory order, which isn't alphabetical on a few days (d15/d16/d22) — read the order from the archive, don't sort filenames.
- **Decoy HCFG headers** that fail the CRC check are scattered around; the CRC is what tells the real one from the bait.
- **d11 (a D / LDC binary)** has no literal `HCFG` bytes on disk at all — the config only exists after the D stdlib base64-decodes a `.rodata` run at runtime, which you can confirm in the `_Dmain` call chain.
- **d15** ships the same program symbolized *and* stripped; a raw byte search for `HCFG` finds the config identically in both, and nothing in `.text` even references it.

All 264 accepted. The reusable lesson: build the parser once, then let the CRC separate signal from decoys.

#### [Malware] Lost in Translation

A monster — **75 obfuscated scripts, 615 answer fields** — across PowerShell, JScript, VBScript, Batch, Python, Bash, Node and PHP. Each one hides a JSON descriptor a different way: XOR-over-base64, decimal lists, hex with a shift, reversed-then-XOR, or a self-labeled `codec`/`material` constant. Everything was decoded with Python; nothing was executed.

The real challenge wasn't decoding — it was the grading. It's all-or-nothing with no per-field feedback, so a single wrong label sinks all 615. The move that cracked it:

- Decode every IOC programmatically (URLs, paths, campaign IDs, adapters, next-stages) so the concrete values are rock-solid.
- Discover that **partial submissions get graded** — then submit in sections to isolate the ~39 label fields whose exact vocabulary the files never state.

That isolation surfaced the grader's own naming scheme: launcher/chain/relay take the language's interpreter sub-technique (`T1059.003` Batch, `.005` VBScript, `.006` Python, `.004` Bash, `.007` JScript/Node), uploaders are `T1041`, and control-flow labels look like `for_once`, `do_once`, `while_once`, `call_subroutine`, `goto_dispatch`, `if_guard`. The very last holdout, `batch-uploader-control`, turned out to be `if_guard`. All 615 — flag captured.

#### [Mobile] Exported Trust (Day 01)

A small, unobfuscated APK (`com.huntress.mobile.d01...`). Unpack it (an APK is just a ZIP), decode the manifest with androguard and decompile the DEX with jadx — three classes, no obfuscation.

`ChallengeActivity` is marked `android:exported="true"` and registered for the deep link `huntress01://exported-trust/unlock`. It reads `answer` and `case_id` from either intent extras or the URI, then builds a loopback scoring request carrying a hardcoded `client_secret` and loads it in a WebView — with no caller check whatsoever. That's the whole lesson: an exported component the developer assumed only their own app would call, reachable by anyone (adb, another app, or the browser following the deep link).

The expected answer is sitting in plain text in `assets/huntress_puzzle.json`:

```json
{"schema":"huntress.mobile.puzzle.v1","day":1,"codec":"plain","data":"ANS-DACC86F43B0B1C1A"}
```

So the intended solve is to fire the exported activity (via the deep link or an `am start`) with `answer=ANS-DACC86F43B0B1C1A` and let the app submit the proof itself.

#### [Mobile] Protocol Reconstruction (Day 28)

Same Huntress Mobile Arena setup as Day 01, but the answer is wrapped in a little binary protocol. The `data` field of `huntress_puzzle.json` is a hex-encoded packet:

```
48 41 | 14 | 41 4e 53 2d ... 41 43 | 11
"HA"   len   "ANS-601D3906BB5885AC"   checksum
magic  =20   (20-byte payload)
```

Break it into fields like any binary protocol:

- **Magic** `HA` — a fixed marker ("this is one of our packets," same idea as PNG's `\x89PNG` or ZIP's `PK`).
- **Length** `0x14` = 20, which is exactly `ANS-` plus 16 hex chars.
- **Payload** — the answer, `ANS-601D3906BB5885AC`.
- **Checksum** `0x11` — the XOR of every preceding byte. It matches, which proves the parse is right and the value isn't a decoy.

```python
d = bytes.fromhex("484114414e532d3630314433393036424235383835414311")
x = 0
for b in d[:-1]: x ^= b
print(d[3:3+d[2]].decode(), x == d[-1])   # ANS-601D3906BB5885AC True
```

The DEX shows the matching `huntress28://protocol-reconstruction/unlock` deep link and loopback scoring endpoint, mirroring Day 01.
<br>

## Huntress CTF 2023 Solutions!
### These are my solutions to Huntress challenges that I found to be the most fun.
<br>
<details markdown>
  <br>
  <summary>[Malware] Zerion Solution</summary>
  For this challenge, participants are provided with a file named <code>zerion</code>.<br><br>
  At first glance, the contents of this file reveals some PHP code.<br><br>
  <img src="https://i.imgur.com/vAJmHp2.png"><br><br>
  Digging in a little farther, there seems to be some encoded text at the end of the file.<br><br>
  <img src="https://i.imgur.com/pnB0T5D.png"><br><br>
  In the first screenshot, the variable <code>$L66Rgr</code> is being assigned to an array containing the php code and the base64 string at the end of the file.<br><br>
  Specifically, the explode function is splitting the current file by the string <code>?></code> which would isolate the base64 string into the second element of the array.
  The array should look similar to this:<br><br>
  
  <code>[php_code, base64_text]</code><br><br>
  
  <img src="https://i.imgur.com/u0WLJKE.png"><br><br>
  A little further along the code is this variable <code>$L6CRgr</code>. Here, an array is created as so:<br><br>
  
  <code>[/x/i, x, base64_text]</code><br><br>
  
  The first two arguments are just decoded base64 text. The third element is what we want to pay more attention to. It's doing some stuff to the second element of the array created before.<br><br>
  Following the function call, first run the third element of the array (base64 text at end of file) through a rot13 decoder.<br><br>
  <img src="https://i.imgur.com/MYvLDUF.png"><br><br>
  Then take the output and reverse the string.<br><br>
  <img src="https://i.imgur.com/tJnesuQ.png"><br><br>
  Then we get, surprise surprise, base64 text. Run that through a base64 decoder.<br><br>
  <img src="https://i.imgur.com/YxBvzRf.png"><br><br>
  Now we're getting somewhere...<br><br>
  <img src="https://i.imgur.com/UFND3UT.png"><br><br>
  After searching through more php code, the flag is captured!
</details>
<details>
  <br>
  <summary>[Forensics] Traffic Solution</summary>
  <b>~~ NOTE: It's easier to complete this challenge within a Linux environment. ~~<br><br></b>
  For this challenge, participants are provided with a file called <code>traffic.7z</code>.<br><br>
  After extracting the file, reveals a bunch of gzip files<br><br>
  <img src="https://i.imgur.com/0N4uQeJ.png"><br><br>
  The naming convention of the files suggests these are zeek logs. <a href="https://docs.zeek.org/en/master/script-reference/log-files.html" target="_blank">More Info</a><br><br>
  After extracting the gzip files, we can now spin up a database using <a href="https://github.com/activecm/rita" target="_blank">Rita</a><br><br>
  <img src="https://i.imgur.com/oxjtWe1.png"><br><br>
  <code>rita import . logs</code> will create a database including all the files in the present working directory and name it logs.<br><br>
  <img src="https://i.imgur.com/jfZONRr.png"><br><br>
  <code>rita show-beacons logs -H</code> will spit out some data to look at. We can already see some suspicious looking connections based on how many were made. However, this format is hard to read and doesn't really show much.<br><br>
  <img src="https://i.imgur.com/PPQ9RPI.png"><br><br>
  Running the command <code>rita html-report logs</code> will create an organized html report for us.<br><br>
  <img src="https://i.imgur.com/x07K0Gt.png"><br><br>
  Looking at the Beacons, there are several outgoing connections that seem to be repeated more than usual. Along with a score that is VERY close to 1, this raises some red flags. Even more so with the highlighted IP.<br><br>
  <img src="https://i.imgur.com/8xqe2rV.png"><br><br>
  Trying to access the IP directly reveals this is pointing to some github url. 104 connections being made to one github link? Something isn't right.<br><br>
  <img src="https://i.imgur.com/hFkSOxm.png"><br><br>
  Switching to the Beacons SNI page, and searching for any github urls we find a github pages link.<br><br>
  <img src="https://i.imgur.com/Pq72u3J.png"><br><br>
  Voilà! Flag is captured :-)
</details>
<details>
  <br>
  <summary>[Malware] Hot Off The Press Solution</summary>
  Participants are provided with a file <code>hot_off_the_press</code>. In the metadata of the file we see it's UHA compressed file.<br><br>
  <img src="https://i.imgur.com/Qyw8oZD.png"><br><br>
  <img src="https://i.imgur.com/KfrOOka.png"><br><br>
  Using <a href="https://sam.gleske.net/uharc/" target="_blank">UHARC Cmd</a> we can extract the files provided we give the supplied password <code>infected</code> found on the challenge site.<br><br>
  <img src="https://i.imgur.com/YQ5XU4B.png"><br><br>
  The extracted file seems to be a <code>.ps1</code> Powershell file.<br><br>
  Going inside the file, we see some gzip and base64 happening to a provided string that is being concatenated.<br><br>
  <img src="https://i.imgur.com/2gdDxKb.png"><br><br>
  Going to the end of the string, we see that the string is first being decompressed using <a href="https://www.gzip.org/" target="_blank">gzip</a>, then decoded using Base64.<br><br>
  Looking closer, there is the <code>-f</code> Powershell string format specifier with replacement happening with 'L' and 'E'. This will be important further along...<br><br>
  <img src="https://i.imgur.com/fpOB1F7.png"><br><br>
  Copying the string into a new file, we can start to clean it up and make sense of it. First, by removing all instances of <code>'+'</code> since it's purely Powershell code and has nothing to do with the actual string.<br><br>
  <img src="https://i.imgur.com/IlhFid0.png"><br><br>
  Next we can remove <code>'</code>. It's safe to assume it doesn't have anything to do with the string.<br><br>
  <img src="https://i.imgur.com/mreTC4e.png"><br><br>
  Remember the replacement with 'L' and 'E' mentioned before? Here it comes into play. There are several <code>{0}</code> and <code>{1}</code> placements throughout the string. Now, we can replace every <code>{0}</code> with L and every <code>{1}</code> with E.<br><br>
  <img src="https://i.imgur.com/z3QjLNX.png"><br><br>
  <img src="https://i.imgur.com/STlzFpx.png"><br><br>
  Following the function call of the original Powershell code, put the cleaned up string into a gzip decompressor.<br><br>
  <img src="https://i.imgur.com/aPfObPj.png"><br><br>
  We have some more powershell code, and from first glance there doesn't seem to be anything interesting.<br><br>
  <img src="https://i.imgur.com/0S71jd9.png"><br><br>
  Until we notice a very long Base64 string.<br><br>
  <img src="https://i.imgur.com/ZA6PQJf.png"><br><br>
  Just copy and paste the string into a Base64 decoder and the flag is captured!
</details>
<details>
  <summary>[Forensics] Backdoored Splunk Solution</summary>
  For this challenge, participants are provided with a zip file containing some files used for Splunk Add-on for Windows.<br><br>
  <img src="https://i.imgur.com/lNbC6oe.png"><br><br>
  We want to direct our attention to the bin folder since these files were deemed suspicious. By viewing a certain powershell file within <code>bin/powershell/nt6-health.ps1</code> we can see a web request being made to the provided container on the challenge site.<br><br>
  <img src="https://i.imgur.com/t9eG782.png"><br><br>
  This web request includes an authorization header which is important to note... If we go to the challenge site we are met with this json message.<br><br>
  <img src="https://i.imgur.com/oHyw4Z2.png"><br><br>
  Now we can craft a HTTP GET request to the site adding in the authorization header with the value we found from the powershell file.<br><br>
  <img src="https://i.imgur.com/NG6ypYq.png"><br><br>
  You can use any tool you want to do this. Personally, I'm using <a href="https://www.postman.com/" target="_blank">Postman</a> because it's simple and gets the job done, but other tools like <a href="https://portswigger.net/burp/communitydownload" target="_blank">Burp Suite</a> should work fine.<br><br>
  <img src="https://i.imgur.com/ugyyO3i.png"><br><br>
  Once the request is sent, the server responds back with some Base64 encoded text inside a HTML comment.<br><br>
  <img src="https://i.imgur.com/kOpgJf7.png"><br><br>
  Decode the text using your favorite tool, and flag captured!
</details>
<details>
  <summary>[Misc.] Rock, Paper, Psychic Solution</summary>
  <br>
  Participants are provided with a 7zip archive which contains an exe file. Using DIE we can see it's a 64-bit exe file.<br><br>
  <img src="https://i.imgur.com/DHQGhPs.png"><br><br>
  <img src="https://i.imgur.com/n2EN0IO.png"><br><br>
  From the entropy analysis page, the binary seems to not be packed, which makes our job a lot easier.<br><br>
  <img src="https://i.imgur.com/VLP83uF.png"><br><br>
  Next open the binary in a dissassembler and begin to look for any interesting strings. I'm using <a href="https://hex-rays.com/ida-free/" target="_blank">IDA Freeware</a><br><br>
  <img src="https://i.imgur.com/QWPfcF3.png"><br><br>
  Here we can see several interesting strings that have to do with the gameplay along with some interesting Hex and seemingly random string of characters.<br><br>
  <img src="https://i.imgur.com/NPZOsXu.png"><br><br>
  Clicking into the Hex string, we see it's referenced in a function called <code>printFlag</code>.<br><br>
  <img src="https://i.imgur.com/TbAd2VE.png"><br><br>
  Searching through the function, it will lead you to a <code>fromRC4</code> function and then to a <code>genKeystream</code> function. Now we have an understanding that the flag is not hardcoded in the binary, rather it's generated at run time. To investigate further, we need a debugger.<br><br>
  <img src="https://i.imgur.com/wtbUMcI.png"><br><br>
  Before going further, take note of the address where <code>printFlag</code> is since we can try to trigger it during run time.<br><br>
  <img src="https://i.imgur.com/fLXDO0W.png"><br><br>
  Open the binary in a debugger of your choice, I'm using <a href="https://x64dbg.com/" target="_blank">x64dbg</a><br><br>
  <img src="https://i.imgur.com/s3J7v5k.png"><br><br>
  Run through the game, and the instruction will go to a different location in memory. We can exploit this by changing the next instruction to jump to the location of <code>printFlag</code> we saved earlier. Instruction should look similar to <code>jmp 0x4168F0</code>. Your address might be different.<br><br>
  <img src="https://i.imgur.com/gyxkfoj.png"><br><br>
  Continue with execution, and if done properly, flag should appear. Well done!
</details>
<details>
  <summary>[Misc.] PRESS PLAY ON TAPE Solution</summary>
  <br>
  This challenge is one of my personal favorites simply because of how unique it is.<br><br>
  Participants are provided with a wav file named <code>pressplayontape.wav</code>. Playing the audio file reveals an ear piercing sound, and a spectrogram reveals nothing.<br><br>
  <img src="https://i.imgur.com/P1HRlrN.png"><br><br>
  This requires us to think a little outside the box... Do a quick search on the filename and this will pop up.<br><br>
  <img src="https://i.imgur.com/m02sH4N.png"><br><br>
  Hmm.... Commodore 64. That's computer related, right? Turns out, Commodore 64 had it's own special audio file format with the extension <code>.tap</code> that could be used to hide messages and data when recorded from VHS tapes. So, now it's time to try to convert this <code>.wav</code> into <code>.tap</code>.<br><br>
  <img src="https://i.imgur.com/Fge62hj.png"><br><br>
  To accomplish this, I'm using <a href="https://commodore.software/downloads/download/160-tape-related-utilities/974-c64-tape-decode-v0-1" target="_blank">C64 Tape Decode</a>. Specifically, <code>wav2tap.exe</code>. Now we have the raw Tape data.<br><br>
  <img src="https://i.imgur.com/TybDqAq.png"><br><br>
  We can now take this data and save it into a tap file. I've named it <code>output.tap</code>.<br><br>
  <img src="https://i.imgur.com/oo0yaRd.png"><br><br>
  Here, I'm using a tap analysis tool <a href="https://commodore.software/downloads/download/160-tape-related-utilities/14125-tapex-v1-6" target="_blank">TapEx</a> to analyze <code>output.tap</code>. Another tool from commodore.software. Going to the View tab we see several sections. The section that looks the most interesting seems to be the <code>CBM DATA FIRST</code>. It contains some hex.<br><br>
  <img src="https://i.imgur.com/5H4pGMK.png"><br><br>
  Pop this hex into an online tool and convert to ascii, and there's the flag!
</details>
<details>
  <summary>[Forensics] Texas Chainsaw Massacre: Tokyo Drift Solution</summary>
  <br>
  This challenge is difficult and therefore one of my favorites.<br><br>
  Participants are provided with a Windows Event Log named <code>Application Logs.evtx</code>.<br><br>
  <img src="https://i.imgur.com/R7AuC4a.png"><br><br>
  Viewing this file with the built in Windows Event Viewer, not much can be found from the log alone.<br><br>
  <img src="https://i.imgur.com/YoCUk0m.png"><br><br>
  If we take a look at the event log, there is some interesting obfuscated text planted in the file here.<br><br>
  <img src="https://i.imgur.com/d1JKe0n.png"><br><br>
  This text is obfuscated powershell code, so we can edit it. Remove the last statement to print it separately and run the script. Now we have our first stage of deobfuscation.<br><br>
  <img src="https://i.imgur.com/ccoUGvt.png"><br><br>
  Copy the output and modify it so the first statement is on a separate line. Make additional edits as needed and run, and now we have something that is starting to look like recognizable code. This task is all about trial and error...<br><br>
  <img src="https://i.imgur.com/2XtazI6.png"><br><br>
  You know the drill, copy the output and make modifications as necessary to get it to run properly. However, this time, it's not spitting anything out. Hmm... We need to try something else.<br><br>
  <img src="https://i.imgur.com/NCNwjZT.png"><br><br>
  Maybe it's nothing we're doing wrong, the code just isn't supposed to print anything at this stage. So we force it to print output with <code>Write-Output $output</code>. With <code>$output</code> assigned to the code.<br><br>
  <img src="https://i.imgur.com/P8ERqxQ.png"><br><br>
  Taking the output from the previous run, copy that output and format it so it spits out the result. Your code should look similar to mine, and now we run and get something that looks like pure Powershell code. Now we're close.<br><br>
  <img src="https://i.imgur.com/ggW3lIF.png"><br><br>
  Looking closer at the output from the previous run, the code seems to be trying to get some data from the Dns Name <code>eventlog.zip</code>.<br><br>
  <img src="https://i.imgur.com/GBeWKsk.png"><br><br>
  We also notice the data taken from the remote server is being decoded from base64 and converted into a readable string. We can force this to run by taking the code out of the try catch block and just running it independently on the next line.<br><br>
  <img src="https://i.imgur.com/Pz13vbd.png"><br><br>
  Run that code, and flag is down!<br><br>
  NOTE: This challenge is based off a fairly recent attack which involves hiding shellcode in Windows Event Logs. More info <a href="https://www.bleepingcomputer.com/news/security/hackers-are-now-hiding-malware-in-windows-event-logs/">here</a>.
</details>
<details>
  <summary>[Malware] Speakfriend Solution</summary>
  <br>
  Participants are provided with a 7zip archive named <code>main.7z</code>. Within this archive is a main file which seems to be an <code>ELF</code> file.<br><br>
  <img src="https://i.imgur.com/4TOPncn.png"><br><br>
  <img src="https://i.imgur.com/lSw4zsA.png"><br><br>
  We can use <a href="https://ghidra-sre.org/" target="_blank">Ghidra</a> to dissassemble the file and we can already see some weird Hex in the main function.<br><br>
  <img src="https://i.imgur.com/xy1O0s4.png"><br><br>
  Take the hex and convert to Ascii, and you get a string that's reversed. By reversing the string again, we get something that looks meaningful. Take note of this string it will be important later.<br><br>
  <img src="https://i.imgur.com/dtTmSse.png"><br><br>
  If we notice the response from a simple GET request to the container, there is a header <code>User-Agent</code> that looks very similar to the string we just extracted from the <code>main.elf</code>.<br><br>
  <img src="https://i.imgur.com/EY5SjCL.png"><br><br>
  Make a GET request to the container again, but this time replace the <code>User-Agent</code> header with the string we extracted from the main file. The response we get is a link to somewhere else on the server.<br><br>
  <img src="https://i.imgur.com/KUiZfRh.png"><br><br>
  Make a GET request to the provided url, and you win!
</details>
<details>
  <summary>[Malware] RAT Solution</summary>
  <br>
  Participants are provided with a 7zip archive named <code>rat.7z</code>. Extracting the archive reveals a file <code>rat</code>.<br><br>
  <img src="https://i.imgur.com/wCpYqjb.png"><br><br>
  This file has the "MZ" signature which indicates a PE (Portable Executable). Now it's time to analyze this further within a virtual environment.<br><br>
  <img src="https://i.imgur.com/K0flyqC.png"><br><br>
  <a href="https://github.com/horsicq/DIE-engine" target="_blank">Detect It Easy</a> indicates this is a .NET 64 Bit exe file.<br><br>
  <img src="https://i.imgur.com/FhLq2qD.png"><br><br>
  It's always good to check entropy to see if it needs unpacking. All indications point to not being packed which makes the job easier.<br><br>
  <img src="https://i.imgur.com/oBWrJ0X.png"><br><br>
  Here, we can use a .NET dissassembler and debugger <a href="https://github.com/dnSpy/dnSpy" target="_blank">dnSpy</a> to take a look inside the code. There's a decrypt function that's worth looking at.<br><br>
  <img src="https://i.imgur.com/m3K3T7X.png"><br><br>
  If we place a breakpoint on the return array after decrypting and run, we get an array with the magic bytes signature <code>4D 5A</code>. This indicates it's decrypting and probably going to try to execute the PE file contained within the array.<br><br>
  <img src="https://i.imgur.com/IqcxCW0.png"><br><br>
  We can view the array in a Memory Map and dump the selection to a file to analyze this file further.<br><br>
  <img src="https://i.imgur.com/4XkMvVL.png"><br><br>
  Using DIE, this file seems to be a .NET 32 Bit exe.<br><br>
  <img src="https://i.imgur.com/FGDLjc9.png"><br><br>
  This file seems to also not be packed.<br><br>
  <img src="https://i.imgur.com/S7DxlGQ.png"><br><br>
  Using dnSpy again, this file seems to be the actual RAT that will attempt to spin up a reverse shell (Client.Helper probably) along with applying some features in Settings.<br><br>
  <img src="https://i.imgur.com/Z2wy09T.png"><br><br>
  Going into Settings, there's more decryption going on that seems to be getting the settings for the stub. This will be important in a little bit...<br><br>
  <img src="https://i.imgur.com/DDlxNmM.png"><br><br>
  Scrolling down we notice a string <code>Flag</code> that isn't used by any code present in the file. Copy this string down as we'll use it.<br><br>
  <img src="https://i.imgur.com/eyIcjAz.png"><br><br>
  What we can do now is place a breakpoint on the return statement in <code>Decrypt</code> and replace the input with the string we just copied down.<br><br>
  <img src="https://i.imgur.com/bC47XN6.png"><br><br>
  Step over the return statement to view the return value, and nice job! We took down the RAT.
</details>
<details>
  <summary>[Malware] Batchfuscation Solution</summary>
  <br>
  Participants are provided with a file <code>batchfuscation</code> and upon inspection, it's a batch script.<br><br>
  <img src="https://i.imgur.com/XxfbwZa.png"><br><br>
  <img src="https://i.imgur.com/jbegCcX.png"><br><br>
  To print the output of the script into a text file, we can add this code to the top of the file and run it.<br><br>
  <img src="https://i.imgur.com/9wZi2YK.png"><br><br>
  The output prints something like this, and we can notice some replacement going on with the alphabet, numbers, and some special characters.<br><br>
  <img src="https://i.imgur.com/C4Ydxo2.png"><br><br>
  Using the replacement provided, we can craft the word <code>flag</code>. We need to include <code>%%</code> as we'll be searching for it in the script.<br><br>
  <img src="https://i.imgur.com/SrQxLCM.png"><br><br>
  Searching for this word, we find several instances. It looks like <code>flag</code> is apart of some sentences here, and looking closer each sentence <code>flag</code> is apart of, starts the same. Let's print this out during runtime and log it.<br><br>
  <img src="https://i.imgur.com/oyq0AP9.png"><br><br>
  Copy the entire sentence including <code>flag</code> and replace with <code>echo + (sentence + flag)</code> as shown.<br><br>
  <img src="https://i.imgur.com/vZ69kQC.png"><br><br>
  After running the script again, the log will now show the characters of the flag indexed from 1 to 37 (including <code>flag{}</code>). We basically have the flag, now it's just a matter of magic string formatting.<br><br>
  <img src="https://i.imgur.com/Ol9MMeA.png"><br><br>
  We can narrow the text down to just the flag characters by using a regex expression.<br><br>
  <img src="https://i.imgur.com/M3rdfJP.png"><br><br>
  At this point, use whatever methods and tools you want to format the string further to piece together the flag. For example, I just stripped the text down to the <code>(index)=(flag_character)</code> and semi-ordered by the index to make it easier to piece together.<br><br>
</details>
<details>
  <summary>[Forensics] Tragedy Redux</summary>
  <br>
  <img src="https://i.imgur.com/6T1egNK.png"><br><br>
  Participants are provided with a 7zip file containing a file <code>tragedy_redux</code>. Upon inspection it has a magic bytes signature that doesn't signify any known file type.<br><br>
  <img src="https://i.imgur.com/wRYTAIo.png"><br><br>
  Looking through the contents of the file for clues to it's type, it has a <code>word/vbaProject.bin</code> which means it's likely a word document with macro(s).<br><br>
  <img src="https://i.imgur.com/ya388zG.png"><br><br>
  The magic bytes signature for word documents is <code>50 4B 03 04</code>, so we can overwrite the previous incorrect signature. <a href="https://en.wikipedia.org/wiki/List_of_file_signatures">List of file signatures</a>.<br><br>
  <img src="https://i.imgur.com/LdzBREr.png"><br><br>
  Opening the file in Microsoft Word or any software that can handle word documents, reveals a page with the dictionary definition of tragedy.<br><br>
  <img src="https://i.imgur.com/tFXfhDo.png"><br><br>
  Checking the macros in the document we see some interesting VB code that's jumping through hoops to decode a string. You can sit and manually step through the code yourself, but I think it's best to run this and see what the output string is.<br><br>
  <img src="https://i.imgur.com/nrJgGxX.png"><br><br>
  Now, we can take this code and modify as needed to fit the VB program we're going to run. We can also remove the <code>If ActiveDocument.Name</code> snippet as this isn't going to be triggered in a word document.<br><br>
  <img src="https://i.imgur.com/PWoPAFB.png"><br><br>
  Running the code reveals a Base64 encoded string.<br><br>
  <img src="https://i.imgur.com/yL47CLI.png"><br><br>
  Decode the message using a Base64 decoder. Nice work!<br><br>
</details>
<br>
