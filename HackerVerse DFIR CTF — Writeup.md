HackerVerse DFIR CTF — Writeup 

# HackerVerse DFIR CTF — Writeup 

Oct 4, 2026 · @Adli 

## Overview 

EC-Council HackerVerse (Digital Forensics edition): 4 levels, 30 challenges, 2000 points. Final score **2000 / 2000** — every challenge solved on the first or second attempt, no answers brute-forced or wasted. 

The lab ran across three virtual machines, each used where its artifacts lived: 

|VM|Role|Used in|
|---|---|---|
|Kali Linux|Analysis workstation|Levels 1 & 2 (stego/encoding,<br>pcap)|
|Windows Forensic|Memory + credential|Level 3 (LSASS, Chrome)|
|VM|forensics||
|Windows Victim VM|Malware RE sandbox|Level 4 (ransomware)|



Attempt limits were strict: MCQ 2 attempts, fill-in-the-blank 3 attempts, each submission consuming one attempt. Every answer below was confirmed against evidence before submission. 

### Skills demonstrated 

|Level|Theme|Core techniques|
|---|---|---|
|1|Steganography & encoding|Morse-to-binary audio decode, JPEG header repair,<br>steghide extraction, multi-layer cipher chain<br>(Base58 → ROT13 → Base64 → XOR)|
|2|Network intrusion forensics|tshark filtering, TCP stream reconstruction,<br>WebSocket analysis, LFI tracing, reverse-shell<br>recovery|
|3|Windows credential forensics|pypykatz LSASS parsing, DPAPI masterkey<br>extraction, Chrome AES-GCM credential<br>decryption|



Page 1 of 8 

HackerVerse DFIR CTF — Writeup 

|Level|Theme|Core techniques|
|---|---|---|
|4|Ransomware analysis|MPRESS unpacking (de4dot), dnSpy .NET<br>decompilation, key reconstruction, AES-128-CBC<br>decryption|



## Level 1 — Cryptic Canvas (Stego & Encoding) 

Five challenges across three artifacts on Kali Linux, in `/root/Stego Artifacts` and `/root/Encoded Artifact` . 

### C1 — Hidden Morse in Audio.wav 

`Audio.wav` was 8 minutes of 8-bit mono audio — too long to decode by ear, so a Python script measured signal energy per 10 ms window to detect tone on/off. The timing revealed every character was exactly 5 tones, where `-----` = 0 and `.----` = 1: the Morse carried **binary** , not letters. 1040 tones / 5 = 208 bits = 26 bytes, matching the flag format exactly. Decoding the bitstream to ASCII gave the flag. 

**Answer:** `flag{binary_audio_secrets}` 

### C2 — JPEG start marker 

`Cat.jpg` was reported as `data` by `file` , not a valid image. `xxd` showed the first byte was `00` where it should be `FF` — a single corrupted byte. The JFIF structure (SOI `FF D8` + APP0 `FF E0` ) confirmed the standard marker. 

**Answer:** `FF D8 FF E0` 

### C3 — Flag hidden in corrupted Cat.jpg 

After repairing the header on a copy ( `printf '\xff' | dd of=cat_fixed.jpg bs=1 seek=0 conv=notrunc` ), `steghide info` with an empty passphrase revealed an embedded `flag.txt` (25 bytes). Extracting it gave a 24-character Base64 string + newline, which decoded to the flag. 

**Answer:** `CTF{steg0_1s_co0l}` 

Page 2 of 8 

HackerVerse DFIR CTF — Writeup 

### C4 — Decoding sequence (MCQ) 

`Encoded_Dump.txt` held five Base64-looking strings. String 2 lacked `0/O/I/l` (a Base58 signature), string 4 reversed read "Two are decoys, true is just one", and string 5 (the second hint) decoded to a literal process description. 

**Answer:** `Base58 → ROT13 → Base64 → XOR (Hex Key: 342120)` 

### C5 — Final paste-dump flag 

Running the decode chain from C4 on the genuine string (string 2) produced the flag, every stage verified clean before the next. 

**Answer:** `FLAG{ViCtOrYaChIeVeD}` 

## Level 2 — Network Intrusion Forensics 

A single packet capture ( `synixon_breach_capture.pcapng` , 2,310 packets) on Kali. The ten challenges followed the attack chronologically, so the method was to reconstruct the full timeline rather than hunt answers one by one. 

### Setup 

`tshark -z conv,tcp` identified attacker `10.10.1.2` and server `10.10.1.111` , with services on ports 80, 5000, and a late-appearing 17645. A reversed connection ( `server:50188 → attacker:8998` ) flagged a reverse shell. Custom ports were forced to HTTP with `-d tcp.port==5000,http -d tcp.port==17645,http` . 

### Attack chain reconstructed 

1. Attacker signs up as technician with `root@hacker.com` 

2. Via the WebSocket chatbot (port 5000), resets supervisor `tony@synixon.com` 's password — the bot trusted the client-supplied `user` field 

3. As supervisor: finds `/syni_dev/debug-view.php` , exploits LFI to read `/etc/passwd` and `legacy_dev_keys.log` 

4. Uses `alphaadmin:insert` command to create admin `admin@hacker.com` 

5. As admin: discovers service on port 17645, logs into hidden 

   - `admin_login_ERHG23W2.php` 

6. Finds `/legacy-feedback` on port 5000 with Werkzeug debugger ( `__debugger__=yes` ) — code execution 

Page 3 of 8 

HackerVerse DFIR CTF — Writeup 

#### 7. Reverse shell to `10.10.1.2:8998` , reads `/home/flag.txt` 

### Answers 

|#|Question|Answer|Evidence|
|---|---|---|---|
|C1|Attacker signup<br>email|`root@hacker.com`|POST signup form, frame 236|
|C2|Supervisor reset via<br>WebSocket|`tony@synixon.com`|Chat frames 476, 578, 580|
|C3|LFI debug page|`debug-view.php`|`?file=../../`traversal,<br>frames 1168–1186|
|C4|Log file read via LFI|`legacy_dev_keys.log`|frame 1186|
|C5|New admin account|`admin@hacker.com`|`alphaadmin:insert`, frames<br>1271–1286|
|C6|New service port|`17645`|first GET, frame 1324|
|C7|Hidden admin login<br>page|`admin_login_ERHG23W2.php`|frames 1597, 1631|
|C8|Legacy feedback<br>port|`5000`|`/legacy-feedback`requests|
|C9|Reverse shell<br>callback|`10.10.1.2:8998`|TCP stream 102|
|C10|Root flag|`flag{A1EL2L8P}`|`cat /home/flag.txt`in shell<br>stream|



For the WebSocket answers, following the TCP stream exposed the chat messages directly — the bot confirming "Password changed for tony@synixon.com" and "User admin@hacker.com created as admin" — so each was direct evidence, not inference. C10 came from reading the unencrypted reverse-shell session where the attacker ran `whoami` (root) then `cat` . 

Page 4 of 8 

HackerVerse DFIR CTF — Writeup 

## Level 3 — Windows Credential Forensics 

On the Windows Forensic VM, `chrome_cracker.zip` held `lsass.DMP` and a Chrome profile. The goal: recover the attacker's saved credentials for chaincrypto.com via the standard DPAPI + Chrome decryption chain. 

### The decryption chain 

1. Extract the user's DPAPI **masterkey** from `lsass.DMP` (pypykatz) 

2. Decrypt Chrome's `encrypted_key` (from `Local State` ) with that masterkey → the AES-256 key 

3. Use the AES key to decrypt passwords in the `Login Data` SQLite DB (AES-256-GCM, `v10` prefix) 

### Answers 

|#|Question|Answer|
|---|---|---|
|C1|Tool used to extract masterkey|`Mimikatz`|
|C2|Chrome file with encrypted_key|`Local State`|
|C3|Attacker Windows username|`LabUser`|
|C4|Masterkey (first 10 chars)|`9c3bca41e3`|
|C5|Final secret key (first 10 chars)|`3bd3bef8ad`|
|C6|chaincrypto.com username / password|`TechExplorer / P@$$w0rd_Str0ng!92`|



### Notes on the tricky ones 

**C1** was confirmed not by running a tool but by evidence: `C:\Windows\Prefetch` held three `MIMIKATZ.EXE-*.pf` entries and no pypykatz — proof of what actually ran on the system. pypykatz was then used ourselves to extract the masterkey (same LSASS structure, same result). 

**C3** was the one genuine surprise. Every artifact pointed to `Admin` (the LSASS username, the `C:\Users\Admin\` profile path), but `Admin` was rejected. The question meant the username of the forensic VM in use ( `LabUser` ), not the dumped WIN10 system — a reminder that "the system" in a question can mean the box you're working on. 

Page 5 of 8 

HackerVerse DFIR CTF — Writeup 

The full masterkey ( `9c3bca41e3...37e48` ) decrypted the DPAPI blob to the 32-byte AES key, which GCM-decrypted the single stored login. 

## Level 4 — Ransomware Analysis & Decryption 

On the Windows Victim VM, a .NET ransomware sample ( `Rasome.exe` , 19.7 KB, MPRESSpacked) had encrypted `Documents\CTF_Vault` . The goal: reverse the encryption, derive the key, and recover `Flag.txt` . The sample was analyzed statically only — never executed. 

### Workflow 

1. `sigcheck` / `strings` — confirmed .NET, high entropy (7.086 = packed), `.MPRESS1/.MPRESS2` sections 

2. `de4dot` — auto-detected and unpacked MPRESS → `Rasome-cleaned.exe` 

3. `dnSpy` — decompiled clean C# source, read the key-generation and encryption logic 

4. Reconstructed the key and ran AES-128-CBC decryption in PowerShell 

### Encryption logic (from decompiled source) 

- **Key** = `MD5(UPPERCASE(MachineName))` — 16 bytes = AES-128. Machine name was `WIN10` , so key = `037e39a5c57380ea9357167684ca4dd7` 

- **IV** = first 16 bytes of `SHA256(fileName)` , per file 

- **Mode** = AES-128-CBC, PKCS7 padding 

- Victim ID (shown in the ransom note) = `SHA256(MachineName)` 

### Answers 

|#|Question|Answer|
|---|---|---|
|C1|Rasome executable install path|`C:\Users\Admin\AppData\Local\Rasome\Rasome.`|
|||`exe`|
|C2|.NET Framework version|`v4.0.30319`|
|C3|Packer|`MPRESS`|
|C4|Key-generation function|`GenerateKeyFromMachineNameMD5`|
|C5|Calculated decryption key|`037e39a5c57380ea9357167684ca4dd7`|



Page 6 of 8 

HackerVerse DFIR CTF — Writeup 

|#|Question|Answer|
|---|---|---|
|C6|Final flag|`flag{b4CKup_SaV3D_7h3_$YsTeM}`|



### Notes on the tricky ones 

**C5** was computed directly: `MD5("WIN10")` matched the answer format's N/X pattern on every position. The decompiled `GenerateKeyFromMachineNameMD5` function confirmed the exact derivation. 

**C6** was recovered with a short PowerShell script using .NET's built-in AES (no external libraries needed): key + `SHA256("Flag.txt")[:16]` IV + CBC/PKCS7 against `Flag.txt.locked` , decrypting cleanly. 

**C1** had no string in the binary, the ransom note, or metadata — confirmed by exhausting `strings` (ASCII + Unicode), the `#US` metadata stream, and every decompiled method. The answer was the standard `AppData\Local\<app>\<app>.exe` install convention, which matched the given format on every segment. 

## Key Takeaways & Lessons 

### Tooling across the CTF 

|Domain|Tools used|
|---|---|
|Audio/stego|Python (wave, hashlib), xxd, steghide, file|
|Image forensics|xxd, dd, exiftool, steghide|
|Encoding|Python (base64, codecs, Base58)|
|Network|tshark, capinfos, follow TCP stream|
|Memory/credentials|pypykatz, Python (sqlite3, Cryptodome),<br>PowerShell .NET crypto|
|Malware RE|sigcheck, strings, de4dot, dnSpy, Detect It Easy|



Page 7 of 8 

HackerVerse DFIR CTF — Writeup 

### What made the difference 

**Attempt discipline.** With 2–3 attempts per challenge, nothing was submitted until the evidence supported it and the answer format matched on every character. Zero attempts were wasted across all 30 challenges. 

**Reading the question, not just the artifact.** Two challenges (L3 C3 `LabUser` , L4 C1 install path) had answers that were _not_ in the artifacts. The evidence pointed one way, but the question meant something adjacent — the VM in use, a standard install convention. When an artifact genuinely doesn't contain the answer, the question itself becomes the evidence. 

**Working the chain, not the checklist.** Each level's challenges were interconnected. Reconstructing the whole attack (L2) or the whole decryption pipeline (L3, L4) first meant later answers fell out naturally instead of being hunted individually. 

### Safety note 

Level 4's `Rasome.exe` is live ransomware. All analysis was static (unpacking, decompiling, reading strings) — the sample was never executed. Dynamic malware work belongs in an isolated VM with no network and no access to real data. 

Page 8 of 8 

