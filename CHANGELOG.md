# Changelog

All notable changes to this project will be documented in this file.

## [1.0.61] — 2026-10-27

### Fixed

- A low-entropy private-key body in one mid-body `@@` hunk on a secret-looking path, such as `key.pem`, is redacted when that hunk has no BEGIN line, no END line, and no secret finding. The line is at least 32 characters and either uses fewer than 10 distinct characters or has Shannon entropy under 4.2. The `@@` context is redacted only when that context is the low-entropy key line. Diff markers stay, and so do `+hello`, `-removed ordinary line`, the note, and `thisIsAVeryLongCamelCaseIdentifierName`. A high-entropy line in that same bare `key.pem` hunk stays raw. A low-entropy line on a normal path still leaks, the same as v1.0.60. `readme.md`, `notes.txt`, `config.js`, and `data.txt` stay raw.
- `redactSecretsInText` redacts that same low-entropy lone base64 hunk when it is called with no findings table. The output matches the call that includes a `secret-looking-path` finding.
- A truncated PEM block (a BEGIN line and no END line) stays open across a key-body line that begins or ends with `-` or `_`, an interior `-` or `_` that is not a break between real words, and a key run glued to a path. Every body line is redacted until a real END line or a clearly non-key line. `/src/app.ts`, `/src/components/Button.tsx`, `hello world`, `note: done`, and `user_profile_settings_name` stay. `Next` stays. A snake_case name stays after a gap and after a resumed body line.
- `./src/app.ts`, `src/App.tsx`, and `app/src/index.ts` stay visible after a JWT whose signature contains `+` or `/`, and after a non-RSA signature at that alg's exact length. The JWT stays fully redacted. `/Src.ts`, `/App.ts`, `/Bin.ts`, and `/App.md` stay masked. Ed448 is not split at the Ed25519 length (86). A `+` or `/` at a shorter length inside a longer signature stays inside the mask. An odd RSA run (511, 600, 682) is not split at the next exact length.
- After a gap, a camelCase line stays when every hump is a dictionary word or a known identifier word, and the hump is word-shaped. A random letters-only line of 16 to 19 characters with word-like camelCase humps is redacted. A seeded sweep (seed `0x1061a11`, 2048 draws) keeps none of those lines, and a 5000-draw sweep keeps none. Realistic identifiers stay, including `handleClickEvent` and `computeTaxAmount`. A 1500-name corpus built from the dictionary in `hump-words.ts` stays near the v1.0.60 keep rate, and so does the earlier 78-name corpus. That near rate holds only on a corpus built from `hump-words.ts`. On third-party real identifiers, this cut masks 773 of 3000 and main (v1.0.60) masks 246 of 3000, about three times as many. A dictionary-word camelCase secret tail of 16 to 24 characters, such as `CorrectHorseBatteryStaple`, after a truncated PEM and a gap is kept about 69% of the time, the same as main. `indexedDBOpenRequest`, `cryptoRandomUUID`, `atobBase64Decode`, `calculationResult`, `graphqlResolverFn`, `downwardAPIVolume`, and `bulkheadIsolation` stay. `encodeURIComponent`, `decodeURIComponent`, and `abcDe12fghijklmn` stay redacted. Those names are redacted when they follow a resumed body line.
- The leaks fixed in 1.0.47 through 1.0.60 stay closed, including mid-body key hunk redaction, later-hunk no-BEGIN redaction, `@@` context handling, the `Zm9v` over-mask fix, base64url tails, unfenced diff keys, glued 3-letter paths, long identifier keeps, and the post-gap short final line.

### Notes

- These are v1.0.60 Release QA follow-ups.
- A low-entropy key line is redacted in a lone mid-body hunk only when the diff path is secret-looking, such as `key.pem`. A high-entropy line in a bare hunk with no finding stays raw, the same as v1.0.60. `Zm9v` stays in a file that is not a secret file. Normal paths still leak that low-entropy line. `notes.txt`, `config.js`, and `data.txt` stay raw, the same as v1.0.60.
- A key-body line that begins or ends with `-` or `_`, or a key run glued to a path, does not end a truncated PEM block. A real path, prose, or a snake_case identifier does.
- `./src/app.ts`, `src/App.tsx`, and `app/src/index.ts` stay after the JWT. The signature stays redacted, including when it uses standard base64 (`+` and `/`).
- A word-like camelCase hump is not enough to keep a letters-only line after a gap. The hump has to be a dictionary word or a known identifier word. Seed `0x1061a11` keeps 0 lines out of 2048 and out of 5000. On a corpus built from `hump-words.ts`, realistic identifiers stay near the v1.0.60 keep rate, including `handleClickEvent` and `computeTaxAmount`. The 78 identifiers stay. On third-party real identifiers, this cut masks 773 of 3000 and main (v1.0.60) masks 246 of 3000. `encodeURIComponent` stays redacted.
- A dictionary-word camelCase secret tail of 16 to 24 characters, such as `CorrectHorseBatteryStaple`, after a truncated PEM and a gap is kept about 69% of the time, the same as main.
- Package version bumped to `1.0.61`. Pin comments that track the current cut are `v1.0.61`. The action default pin is `1.0.61`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.60] — 2026-10-22

### Fixed

- A private key edited inside a git diff `@@` hunk is redacted. The BEGIN line may be a context line with one leading space. Body lines may mix a leading space, `+`, and `-`, and the hunk may end before the END line. Inside the hunk, one leading space, `+`, or `-` on any line is a diff marker. The BEGIN line does not have to carry that prefix, and neither does every body line. `---`, `+++`, and the `@@` header stay visible. The note after the block and `thisIsAVeryLongCamelCaseIdentifierName` stay visible. LF and CRLF hunks redact to that same block. A 26-line key with only line 2 edited does not print a raw key line in `show` or the share HTML. That seeded sweep stays inside the one hunk that contains BEGIN: it varies the edited line, the hunk start and end, and a cut before END. No key body line from that hunk is raw in redact output, `show`, or the share HTML.
- A later hunk of a file that contains a private-key block, or a file named by a `private-key-block` finding, is redacted when that hunk has no BEGIN line. A mid-body hunk and a hunk that has only the END line are both covered. Base64-like body lines are redacted. A key-shaped final line of 4, 8, or 12 characters is redacted. A letter-only line of that length stays, including `QUJD`. The `@@` function context is redacted only when it is base64-like. `---`, `+++`, `+hello`, `-removed ordinary line`, the note after the hunk, and `thisIsAVeryLongCamelCaseIdentifierName` stay visible. LF and CRLF redact to that shape. A 26-line key with lines 2 and 14 edited and line 20 deleted does not print a raw key line in `show`, `show --json`, or the share HTML. A seeded sweep varies edited lines, deletions, hunk boundaries, and hunks without BEGIN or END. No key body line is raw in redact output, `show`, `show --json`, or the share HTML.
- A single mid-body edit is one `@@` hunk with no BEGIN line and no END line. That hunk is redacted when a `secret-looking-path` or `high-entropy-secret` finding names the file. The `@@` function context is redacted only when it is base64-like. Ordinary code context such as `def handler(event):` stays. A short base64-like line such as `Zm9v` stays in a file that is not a secret file. `YQ==` stays redacted. LF and CRLF redact to that shape. A 26-line `key.pem` with only body line 12 edited does not print a raw key line in `show`, `show --json`, or the share HTML. A seeded sweep covers a single hunk with neither marker.
- One or two body lines that are already key text with a leading `+` are not read as a diff. A final line of 4, 8, or 12 characters that starts with `+` stays inside the block when another `+` body line sits above it. A leading `+` on a normal PEM line is still base64.
- `k8sNamespaceName`, `sha256DigestValue`, and `base64UrlEncoded` stay visible after a truncated key and a gap, when no body line has resumed. They are redacted after a resumed body line. A digit mixed into any other line stays redacted, including `abcDe12fghijklmn`.
- After a truncated PEM private key and a gap, a camelCase, PascalCase, or snake_case line stays when every part is a real word or a common abbreviation (`JSON`, `URL`, `ID`, `HTTP`), and a camelCase name also stays when it has at least two humps, is mostly lowercase, and each hump is word-shaped. A hump is 2 to 16 letters, a one-letter hump is only `a` or `i`, a hump of 5 or more letters contains a vowel (`w` counts), and a consonant run is at most 4. A random letters-only line of 16 to 19 characters is redacted, including a line that only looks like camelCase. `veryLongCamelCaseIdentifier`, `IdentifierValue16`, `HTTPServerConfig`, `getUserProfileSettingsNow`, `thisIsAVeryLongCamelCaseIdentifierName`, `parseJSONResponse`, `getUserProfileById`, `fetchAccountBalance`, `handleWebSocketMsg`, `dockerComposeFile`, `webpackDevServer`, and `kubeletConfigPath` stay when they follow the gap and no body line has resumed. They are redacted when they follow a resumed body line. A corpus of 134 realistic identifiers keeps the listed names and redacts `encodeURIComponent` and `decodeURIComponent`. A seeded sweep of letters-only lines in that window leaves none raw for seed `0x1060a11`. The other seeds in that sweep keep at most 4.
- A base64url secret or signature split on `_` or `-` no longer leaves a tail of 1, 2, or 3 raw characters (`_`, `-`, `_x`, `_ab`). The whole token is redacted. A whole-word hyphen suffix still stays (`-then`, `-Then`, `-config-file`). Two tokens joined by `_` or `-` stay `[REDACTED]_[REDACTED]` and `[REDACTED]-[REDACTED]`.
- A private key in an unfenced unified diff is redacted. One leading `+` or `-` is a diff marker when the BEGIN line carries that prefix or every body line does. It is not part of the key text, so every body line is redacted. `---`, `+++`, and ordinary diff lines stay visible. A leading `+` on a normal PEM body line is base64. A truncated block whose final line is 4, 8, 12, or 16 characters and starts with `+` is redacted, including LF, CRLF, and a lone CR, fenced and unfenced. The note after the block and `thisIsAVeryLongCamelCaseIdentifierName` stay visible. A seeded sweep leaves no final key line raw.
- A glued 3-letter path fragment does not keep a raw signature. `/Src.ts`, `/App.ts`, `/src.ts`, `/app.ts`, and `/App.md` stay masked, the same way `/Bin.ts` does. A second segment keeps the path, so `./src/app.ts`, `src/App.tsx`, `app/src/index.ts`, `/src/app.ts`, `/src/App.tsx`, and `/src/nav.ts` stay.
- `thisIsAVeryLongCamelCaseIdentifierName` and `parseJSONResponse` stay visible on plain and JSON output for `show`, `last`, `compare`, `share`, `prove`, `verify`, and `attest`. The key stays fully redacted. A random camelCase line after the gap stays redacted.
- The leaks fixed in 1.0.47 through 1.0.59 stay closed, including the post-gap short final line, 3-letter directory grounding, the resumed-body identifier keep, the gap-resume width rule, the PEM timing bound, and PascalCase keeps.

### Notes

- These are v1.0.59 Release QA follow-ups, plus the v1.0.60 Release QA re-gate on this same entry. The version was not bumped again.
- A letters-only line of 16 to 19 characters after a gap is key material unless every camelCase or snake_case part is a real word or a common abbreviation, or the name is word-shaped camelCase (`getUserProfileById`, `fetchAccountBalance`, `handleWebSocketMsg`, `dockerComposeFile`, `webpackDevServer`, `kubeletConfigPath`). `thisIsAVeryLongCamelCaseIdentifierName` and `parseJSONResponse` stay when no body line has resumed. A random capital does not. A corpus of 134 realistic identifiers keeps the listed names and redacts `encodeURIComponent` and `decodeURIComponent`.
- A short tail split on `_` or `-` is part of the token. 1, 2, and 3 raw characters stay inside the mask. `-then` still stays.
- An unfenced diff prefix is stripped before key-body detection when the BEGIN line carries that prefix or every body line does. Inside an `@@` hunk, one leading space, `+`, or `-` is a marker on any line, including a context BEGIN and a hunk that ends before END. A later hunk of that file is redacted when it has no BEGIN line, including a mid-body hunk and a hunk with only END. The `@@` function context is redacted only when it is base64-like. `def handler(event):` stays. `Zm9v` stays in a file that is not a secret file. Diff markers and ordinary diff lines stay. A `+` that starts a normal PEM line of 4, 8, 12, or 16 characters is key text, so that final line stays inside the block. One or two body lines that are already key text with a leading `+` are not a diff. The note after the block stays visible.
- `scripts/pack-check.js` reads `npm pack --dry-run --json` and requires `bin/agent-receipt.js`, `dist/index.js`, and the policy packs `policies/baseline.yml`, `policies/supply-chain.yml`, `policies/ci-protect.yml`, and `policies/strict.yml` in that file list.
- `k8sNamespaceName`, `sha256DigestValue`, and `base64UrlEncoded` stay when they follow a gap and no body line has resumed. `abcDe12fghijklmn` stays redacted.
- `/Src.ts` and `/App.ts` stay masked. `./src/app.ts`, `src/App.tsx`, and `app/src/index.ts` stay.
- Package version bumped to `1.0.60`. Pin comments that track the current cut are `v1.0.60`. The action default pin is `1.0.60`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.59] — 2026-10-22

### Fixed

- After a truncated PEM private key (a BEGIN line with no END) and a gap, a final base64-only line of 16 to 19 characters is redacted. That includes an alphanumeric-only line (no `+` or `/`) that follows one or two resumed full-width body lines, at 16, 19, 20, and 43 characters, even when the line looks like camelCase. Ordinary short text stays visible: words with spaces, punctuation, and paths, including `hello world`, `hello!`, `note: done`, and `/src/app.ts`. `Next` and `Ab1` stay. A camelCase or PascalCase word stays when it follows the gap and no body line has resumed. Digits in that word are only a trailing run, as in `IdentifierValue16`. Digits mixed into the line stay redacted. `HTTPServerConfig` stays after that gap: consecutive capitals are one word when every hump is a real word. The same name directly after a resumed full-width body line is redacted. A 20-character base64 line that is not that word shape stays redacted. LF, CRLF, and a lone CR still work. The scan is still one forward pass. A seeded sweep of a resumed body plus a final alphanumeric line leaves no final key line raw.
- A 3-letter directory word `bin` does not by itself keep a raw signature fragment. `/Bin.ts`, `/bin.ts`, and `/BIN.ts` stay masked. A second grounding segment is required, so `./bin/cli.js`, `/bin/cli.js`, `/bin/run`, `src/bin/main.rs`, `/src/bin/main.rs`, and `node_modules/.bin/tsc` stay visible. `/App.md` and `/src/nav.ts` stay. A seeded sweep leaves no raw signature substring of 3 or more characters.
- After a truncated key and a gap, with no resumed body line, a camelCase or PascalCase word stays visible, and so does a snake_case name. A leading `+` on that name is a diff marker, not key material. A 48-hex or 56-hex string stays visible when it follows the gap and the body has not resumed. A 64-hex digest followed by another body line does not leave that body line raw. A 44-wide, 70-wide, or 76-wide hex body line is still redacted with the key. The key itself stays fully redacted. A diff fence is redacted as one block, so a private key in a diff is not left behind line by line. The same keep is covered on plain and JSON output for `show`, `last`, `compare`, `share`, `prove`, `verify`, and `attest`.
- The leaks fixed in 1.0.47 through 1.0.58 stay closed, including the gap-resume width rule for 64, 70, 76, and 44-wide bodies, grounded short paths, 3-character path fragments, deep Java and PHP paths, truncated PEM CR-only and mid-body short lines, exact footer shapes, the PEM timing bound, and PascalCase keeps.

### Notes

- These are v1.0.58 Release QA follow-ups, plus the v1.0.59 Release QA re-gate on this same entry. The version was not bumped again. The re-gate redacts an alphanumeric final line after resumed full-width body lines, including a line that looks like an identifier.
- A 16-to-19 character base64-only line after a gap is the key's last line, including when full-width body lines already resumed. `hello world`, `hello!`, `note: done`, and `/src/app.ts` stay. `veryLongCamelCaseIdentifier`, `IdentifierValue16`, and `HTTPServerConfig` stay when they follow the gap and no body line has resumed. They are redacted when they follow a resumed body line. A digit-mixed line such as `abcDe12fghijklmn` stays redacted.
- `/Bin.ts` stays masked. `./bin/cli.js`, `node_modules/.bin/tsc`, and `src/bin/main.rs` stay. `/App.md` and `/src/nav.ts` stay. Eating a signature-like tail is still preferred over leaving raw signature characters in the clear.
- `user_profile_settings_name`, a 48-hex string, and a 56-hex string stay when they follow the gap and the body has not resumed. A 64-hex digest followed by another body line is still redacted with that later line. A 44-wide, 70-wide, or 76-wide hex body line is still redacted with the key. A hex digest directly after a resumed body line stays redacted, because that line is also a legal key line.
- Package version bumped to `1.0.59`. Pin comments that track the current cut are `v1.0.59`. The action default pin is `1.0.59`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.58] — 2026-10-21

### Fixed

- After a truncated PEM private key (a BEGIN line with no END) and a gap, ordinary text stays visible when it is clearly prose. A gap is a blank line, a line of 1 to 15 characters, or a `Proc-Type` / `DEK-Info` header. Masking resumes on any base64 body line that is at least as wide as the block's first body line, or the same width. That includes 44-wide and 76-wide lines, not only 64 (OpenSSL) and 70 (OpenSSH). A shorter final line is still redacted when it is at least 20 characters, or when it contains `+`, `/`, or `=`. A hex digest (32, 40, 64, 96, or 128 hex digits), a short identifier such as `IdentifierValue16`, `/src/components/Button.tsx`, and `ok` before a sha stay. A hex-only line that is body-shaped does not end the block: a 44-wide, 70-wide, or 76-wide hex body line is redacted with the key, and a 64-hex digest does not leave a later body line raw. The truncated key itself stays fully redacted, including CR-only and CRLF endings, a short or blank line in the middle of the body, and `Proc-Type: 4,ENCRYPTED` / `DEK-Info` headers. The scan is still one forward pass.
- A short line that ends a truncated private-key block stays visible. That includes a short mixed-case alnum line such as `Ab1`, plus `Next`, `README`, `npm`, `test`, `TODO`, and `QUJD`. A 4-character key-shaped line such as `YQ==` stays redacted.
- A path segment of 4 to 7 lowercase letters is a real word when another segment grounds the path. `/src/lib/redact.ts` stays visible. A joined segment whose pieces are 4 to 7 letters stays when another segment grounds the path, so `/node_modules/pkg/index.js` stays visible. A word of 8 or more letters still has to be an ordinary directory word, so `/abcdefgh/x.ts` stays masked.
- A 3-character filename word such as `nav`, `bar`, or `get` does not by itself keep a raw signature fragment. `/nav.ts`, `/bar.ts`, `/get.ts`, `/xyz.ts`, and `/abc/def.ts` stay masked. That short word is a directory word when another segment grounds the path, so `/src/nav/x.ts`, `/lib/nav.ts`, `/o/nav.ts`, `/src/bar/index.ts`, `/src/nav.ts`, and `/nav/src.ts` stay visible. Grounded short directories stay visible: `/src/app.ts`, `/ab.ts`, `/a/b.js`, `/App.md`, `/components/NavBar.vue`, `/src/api/getUser.js`, and `/Users/pramod/repo/x.ts`. A seeded sweep leaves no raw signature substring of 3 or more characters.
- Deep Java and PHP paths stay visible: `src/main/java/com/example/service/UserService.java` and `app/Http/Controllers/Admin/UserController.php`, with or without a leading slash, and with a `+` joiner. The same keep is covered on plain and JSON output for `show`, `last`, `compare`, `share`, `prove`, `verify`, and `attest`. A secret-shaped segment stays masked, including `src/main/java/com/example/service/Ahsqowx.java`.
- The leaks fixed in 1.0.47 through 1.0.57 stay closed, including exact footer shapes, ASCII-only trailing whitespace, odd RSA runs, CR-only verify, subdirectory `relativePath`, short RSA tails, lowercase RSA tail residual, uppercase 7-letter short tails, glued paths after signatures, not-found path masking, shadow roots, nested non-git roots, truncated PEM CR-only and mid-body short lines, PascalCase keeps, and the PEM timing bound.

### Notes

- These are v1.0.57 Release QA follow-ups, plus the v1.0.58 Release QA re-gate on this same entry. The version was not bumped again. The re-gate closes a truncated-key gap leak at body widths other than 64 and 70, and keeps grounded short directory words visible.
- A short mixed-case alnum line such as `Ab1` stays when it ends a truncated private-key block. `Ab1` is 3 characters and is not key-shaped. A 4-character key-shaped line such as `YQ==` stays inside the block.
- After a gap, a 64-hex or 40-hex hash, a 16-character identifier, `/src/components/Button.tsx`, and `ok` before a sha stay. A later base64 line at least as wide as the first body line, including 44, 64, 70, and 76 characters, is still redacted with the key. A shorter final line of at least 20 characters, or one that contains `+`, `/`, or `=`, is redacted too. A hex-only body line does not end the block.
- `/nav.ts`, `/bar.ts`, and `/get.ts` stay masked. `/src/nav/x.ts`, `/lib/nav.ts`, `/o/nav.ts`, `/src/bar/index.ts`, `/src/lib/redact.ts`, and `/node_modules/pkg/index.js` stay. `/src/app.ts` and the deep Java and PHP paths stay. Eating a signature-like tail is still preferred over leaving raw signature characters in the clear.
- Package version bumped to `1.0.58`. Pin comments that track the current cut are `v1.0.58`. The action default pin is `1.0.58`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.57] — 2026-10-21

### Fixed

- An ordinary path directly after an exact-length RSA signature stays visible. `/Users/x/repo/a.ts` and `/Users/pramod/repo/x.ts` stay. The signature itself stays fully redacted. The same keep is covered on plain and JSON output for `show`, `last`, `compare`, `share`, `prove`, `verify`, and `attest`.
- Ordinary filenames stay visible: `UserProfile.tsx`, `HomeView.swift`, `MyClass.java`, `formatDate.ts`, `Dockerfile`, and `package.json`. A filename glued onto an exact RSA signature with no slash stays when it is one of those names, or a PascalCase or camelCase run of path words, and a filename extension follows (2 to 4 letters, or `.swift`). `Dockerfile` needs no extension. Capitalized project paths stay visible: `/Views/HomeView.swift`, `/Sources/App/AppDelegate.swift`, `/Models/User.cs`, `/components/NavBar.vue`, `/lib/parseJSON.ts`, `/src/api/getUser.js`, `/LICENSE`, `/CHANGELOG.md`, and `/tsconfig.json`. `UserService.java` and `UserController.php` stay. `get` and `service` are filename words, and `controller` is an ordinary path word, so `getUser`, `UserService`, and `UserController` are camelCase or PascalCase runs of path words. Secret-shaped segments stay masked: random mixed-case base64, and short uppercase tails such as `/Ahsqowx.ts`, `/OHALMQO.ts`, and `/QZXWVKT.md`. A seeded sweep leaves no raw signature substring of 3 or more characters.
- The PEM linear-time check now has a size and a timing bound. A buffer of at least one million characters of repeated private-key headers stays linear, so a quadratic regression fails. The bound is loose enough for a slow, loaded host.
- A PEM private-key header with no matching END line is redacted from the BEGIN header through the base64 body. LF, CRLF, and a lone CR are line breaks. A key body line is base64 of at least 16 characters, or a shorter multiple of 4 that contains a digit, `+`, `/`, or `=`, including 4 characters such as `YQ==`. A letter-only line shorter than 16 stays visible when it ends the block, including `Next`, `README`, `npm`, `test`, `TODO`, `QUJD`, and `abcdefghijkl`. A line of 1 to 15 characters, or a blank line, does not end the block when a key line follows it, so a later 64-character body line is not shown raw. That short line ends the block when the next line is prose or the input ends. `Proc-Type: 4,ENCRYPTED` and a `DEK-Info` line are part of the block when a key line follows them. The `DEK-Info` algorithm is uppercase letters, digits, and hyphens, and the IV is an even run of at least 8 hex digits. A header that is only those lines, with no key line, stays in place. A partial line redacts the leading base64 run and keeps the trailing prose. The break after the block stays, for LF, CRLF, and a lone CR, so the following text does not glue to the marker. A truncated block at the end of the input is still redacted. A header with no body line is left in place. The scan is one forward pass. A complete private-key block and a mismatched END are still redacted. A certificate stays.
- The leaks fixed in 1.0.47 through 1.0.56 stay closed, including exact footer shapes, ASCII-only trailing whitespace, odd RSA runs, CR-only verify, subdirectory `relativePath`, short RSA tails, lowercase RSA tail residual, uppercase 7-letter short tails, glued paths after signatures, not-found path masking, shadow roots, and nested non-git roots.

### Notes

- These are v1.0.56 Release QA follow-ups, plus the v1.0.57 Release QA re-gate on this same entry. The version was not bumped again. They are over-masking and robustness, not new leak classes.
- After an exact RSA signature (342, 512, or 683), `/Users/x/repo/a.ts` and `/Users/pramod/repo/x.ts` stay. `UserProfile.tsx`, `HomeView.swift`, `MyClass.java`, `formatDate.ts`, `Dockerfile`, and `package.json` stay. `/Views/HomeView.swift`, `/Sources/App/AppDelegate.swift`, `/Models/User.cs`, `/components/NavBar.vue`, `/lib/parseJSON.ts`, `/src/api/getUser.js`, `UserService.java`, `UserController.php`, `/LICENSE`, `/CHANGELOG.md`, and `/tsconfig.json` stay. `/Ahsqowx.ts`, `/OHALMQO.ts`, `/QZXWVKT.md`, `/Makefile`, and a random mixed-case stem stay masked. Eating a signature-like tail is still preferred over leaving raw signature characters in the clear.
- A truncated private key with no END line is redacted through the base64 body. A lone CR is a line break, the same as LF and CRLF. A short or blank line between key lines does not leave a later 64-character line raw. A 4-character key-shaped line such as `YQ==` is redacted. A letter-only line shorter than 16, including `QUJD` and `abcdefghijkl`, stays when it ends the block. `Proc-Type: 4,ENCRYPTED` and a `DEK-Info` header with an even hex IV of at least 8 digits do not leave the following key lines raw. A partial last line keeps its trailing prose. The break after the block stays for LF, CRLF, and a lone CR. A short line such as `Next`, `README`, `npm`, `test`, or `TODO` stays visible. A bare header with no body line is unchanged. The PEM scan stays one forward pass and is bounded in size and time.
- Package version bumped to `1.0.57`. Pin comments that track the current cut are `v1.0.57`. The action default pin is `1.0.57`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.56] — 2026-10-21

### Fixed

- `attest <receipt>`, `attest last`, and `export --format intoto` write `<stem>.intoto.jsonl` beside that receipt, in `.agent-receipt/receipts/`. The README glob `attest --verify .agent-receipt/receipts/*.intoto.jsonl` and the help example `attest --verify .agent-receipt/receipts/receipt.intoto.jsonl` both find that file. `--session <id>` still writes beside `outDir`.
- A short RSA tail is measured without the leading `/` or `+`, so a 7-letter segment is short (`/Ahsqowx` is 7, not 8). It stays masked when a segment of 3 or more letters is not a real path word, even with a 2-to-4 letter extension. No digit is required. `/Ahs.ts`, `/Qow.md`, `/hnw/x.ts`, `/Ahsqowx.ts`, `/OHALMQO.ts`, and `/QZXWVKT.md` stay masked. A segment of 1 or 2 lowercase letters still stays, and a longer piece stays only when it is a path atom or an ordinary word, so `/ab.ts`, `/a/b.js`, `/App.md`, and `/README.md` stay. A tail that contains an uppercase letter uses that same per-segment word check, including when the tail is longer than 7. `/Jrq/kl/x.ts` and `/qb/Zrh/x.ts` stay masked. Mixed-case base64 with 2 characters before `.ts` or `.md` stays masked unless both characters are lowercase letters (`/aa.ts`, `/ab.md`). The check is one pass over the tail, which is already capped at 48 characters.
- A tail of 8 to 48 characters with no uppercase letter stays when a 2-to-4 letter extension follows, every segment is a filename, and some segment is a path atom or an ordinary word (`src`, `docs`, `home`, `run`, `scripts`, `components`, `utilities`, `packages`, `frontend`, `handlers`, `internal`). It also stays with no extension when every segment is a path atom or an ordinary word. One run of a single repeated character still stays. `/src/app.ts`, `+/src/app.ts`, `/src/utilities/format.ts`, `/packages/frontend/main.ts`, `/internal/handlers/api.go`, `/src/index`, `/bin/run`, `/home/runner/work/a/b.ts`, `/scripts/deploy.sh`, and a 48-character repeated-character path stay. `components/utilities` stays. Digit tails, ungrounded letter tails, and words outside that set stay masked: `/tonaxc/u1`, `/ab/cd/ef`, and `/abcdefgh/x.ts`. A tail with an uppercase letter stays only when a 2-to-4 letter extension follows, the tail is a filename, and every segment is a path atom, an ordinary word, or a camelCase run of those atoms (`button`, `use` + `auth`). `/src/components/Button.tsx`, `/src/hooks/useAuth.ts`, `/src/App.tsx`, `/docs/README.md`, `/README.md`, and `/App.md` stay. `/Makefile` and `/AbCdEfGh/x` stay masked. Odd RSA lengths (511, 600, 682) stay redacted as a whole run.
- Repeated unterminated `-----BEGIN … PRIVATE KEY-----` headers are one left-to-right scan. A header with no matching `-----END … PRIVATE KEY-----` is left in place. A complete private-key block is still replaced with a redacted block.
- A directory is a receipts root only when it holds receipt data: a receipt markdown file under the configured outDir, or `.agent-receipt/index.json` with a non-empty `receipts` array. `audit.jsonl`, keys, a config file, an empty receipts directory, or any extra file beside an audit-only `.agent-receipt` do not make that directory a root, so it does not shadow the real root.
- Nested non-git receipt roots use one root-resolution function. `share`, the readers, the example receipt picker, and `verify` pick the same root, so `relativePath` and the opened file agree. A git checkout still uses the git toplevel. The nearest receipts root at or above the working directory that contains the file wins, so a cwd-relative root wins over a parent root when both contain that relative path. The example picker tries that root before a cwd-relative file. A file that merely exists under the working directory does not shadow the receipt. The cwd-relative file is only the fallback when no receipts root contains the path.
- `last`, `prove`, `report`, `attest`, `sign`, `export`, and `history` resolve the receipts root the same way `share` and `verify` do. From a non-git subdirectory they find that root.
- Ordinary path segments of 8 or more letters stay visible when they are ordinary words (`components`, `utilities`). Secret-shaped segments stay masked. The leaks fixed in 1.0.47 through 1.0.55 stay closed, including exact footer shapes, ASCII-only trailing whitespace, odd RSA runs, CR-only verify, subdirectory `relativePath`, short RSA tails, glued paths after signatures, and not-found path masking.

### Notes

- These are v1.0.55 Release QA follow-ups, plus the v1.0.56 Release QA re-gate on this same entry, including the short-tail signature leak. The version was not bumped again.
- A short tail is measured without the leading `/` or `+`. It stays only when the extension is 2 to 4 letters and every segment of 3 or more letters is a real path word. `/Ahs.ts`, `/Qow.md`, `/hnw/x.ts`, `/Ahsqowx.ts`, `/OHALMQO.ts`, and `/QZXWVKT.md` stay masked. `/ab.ts` and `/App.md` stay. A tail with an uppercase letter uses the same word check, so `/Jrq/kl/x.ts` and `/qb/Zrh/x.ts` stay masked, and mixed-case base64 with 2 characters before `.ts` or `.md` stays masked unless both are lowercase. A longer lowercase tail stays when it is a grounded filename with that extension, or every segment is a path word, so `/src/index`, `/bin/run`, `/home/runner/work/a/b.ts`, `/scripts/deploy.sh`, `/packages/frontend/main.ts`, and `/internal/handlers/api.go` stay. Eating a signature-like tail is preferred over leaving raw signature characters in the clear. `/src/components/Button.tsx`, `/src/hooks/useAuth.ts`, and `/src/utilities/format.ts` stay. `components/utilities` stays. `/abcdefgh`, `/Makefile`, and `/AbCdEfGh` stay masked.
- `attest <receipt>`, `attest last`, and `export --format intoto` write the `.intoto.jsonl` beside the receipt. The help text and the README `attest --verify` glob name that directory.
- A directory is a receipts root only when it holds receipt markdown or a non-empty index. An audit log plus an extra file is not a root. Every command uses the same root resolution, so nested non-git roots agree and a reader started in a non-git subdirectory finds that root. A git toplevel is unchanged. The nearest root at or above the working directory wins: a cwd-relative root wins over a parent root when both contain the relative path. The example receipt picker tries that root before a cwd-relative file, which is only the fallback.
- Package version stays `1.0.56`. Pin comments that track the current cut are `v1.0.56`. The action default pin is `1.0.56`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.55] — 2026-10-20

### Fixed

- An RS* or PS* signature run with `/` or `+` at 342, 512, or 683 is redacted as a whole run when the length is not an exact RSA end (342, 344, 512, 683, or 684) and the in-segment tail is not a clear path. A tail of 3 to 7 characters with no filename extension, such as `/ab/c`, `/abc/de`, or `+/mn`, stays masked. The same kind of tail stays masked when `.ts`, `.md`, `.json`, or `.tsx` follows and the tail is not a filename: `/Qx7.ts`, `/aB3k9.md`, `/XYZ12.md`, and `/K.ts`. On a mixed-case sample with those extensions, the share of tails left in the clear is not higher than on v1.0.54. The run check is one pass over the tail. A filename check runs only for a short tail or a tail with an uppercase letter. Both stay inside the 48-character cap.
- A filename glued on after an exact RSA signature stays when the in-segment tail is a clear path of 1 to 48 characters. A tail of 8 to 48 characters with no uppercase letter stays when every alphanumeric run is shorter than 8, or the tail is one run of a single repeated character. `/src/app.ts`, `+src/app.ts`, `+/src/app.ts`, and a 48-character repeated-character path stay. A tail of 3 to 7 characters, or a tail that contains an uppercase letter, stays only when a 2-to-4 letter extension follows the segment and every segment is a filename: 1 to 7 lowercase letters (`app`, `src`, `my-app`), a Capitalized word of 3 to 7 letters (`App`), or an all-caps word of 4 to 7 letters (`README`). Uppercase in a path with more than one segment also needs a directory segment of 2 or more lowercase letters. `/src/App.tsx`, `/docs/README.md`, `/README.md`, `/App.md`, and `/Src/lib/App.tsx` stay. The signature itself stays masked. These stay masked: `/src/components/Button.tsx` (`components` is a mixed run of 8 or more), `/Makefile` (no 2-to-4 letter extension), `/abcdefgh/x.ts` (`abcdefgh` is a mixed run of 8), and `/AbCdEfGh/x` (uppercase, no filename extension, and a mixed run of 8). An uppercase tail with no filename extension, a mixed alphanumeric run of 8 or more, and a tail longer than 48 stay masked with the signature.
- `share --json` `relativePath` uses the receipts root of the receipt file when the working directory is not a git checkout. A secret-shaped parent of that root is not part of the value. The value is set when the receipt file exists under that root, including when share runs from a parent of that root or from a nested directory. Displayed `path` stays masked. A git checkout still uses the git toplevel. A directory whose `.agent-receipt` contains only `audit.jsonl` is not a receipts root. `share` appends that audit line on the receipts root of the file, so a fresh non-git subdirectory does not become the root. From that subdirectory, `share`, the example receipt picker, and `verify` exit 0. That holds when the parent of the receipts root is a plain directory and when that parent is secret-shaped.
- `verify` and `show` mask a secret-shaped path in the not-found error the same way other displayed paths are masked. Plain output and `verify --json` both mask it. `attest --verify` masks a secret-shaped path in the missing-file error, in plain output and in `--json`. `verify --package` masks a secret-shaped path in the missing-directory error, in plain output and in `--json`.

### Notes

- These are v1.0.54 Release QA follow-ups, plus the v1.0.55 Release QA re-gate on this same entry. The version was not bumped again.
- A 2-to-4 letter extension does not by itself keep a short tail or an uppercase tail. The tail stays only when it is a filename path, as above. Eating a signature-like tail is preferred over leaving raw signature characters in the clear. `/src/components/Button.tsx`, `/Makefile`, `/abcdefgh/x.ts`, and `/AbCdEfGh/x` stay masked.
- `relativePath` in a git checkout is still computed from the git toplevel. With no toplevel, the base is the receipts root of the file, not the working directory, and not an audit-only `.agent-receipt` directory.
- Package version stays `1.0.55`. Pin comments that track the current cut are `v1.0.55`. The action default pin is `1.0.55`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.54] — 2026-10-20

### Fixed

- `share` then `verify` from a subdirectory resolves `relativePath` against the git toplevel when that path is not already under the working directory. The same resolution is used by every command that opens a receipt by path, including the receipt picker. When the directory is not a git checkout, the base is the receipts root: the nearest parent that contains `.agent-receipt` or `.agent-receipt.yml`. The value `share --json` prints stays relative to the git toplevel (or the share working directory when there is no toplevel). Displayed `path` stays masked. `examples/github/action.yml` and `examples/github/pr-gate.yml` resolve that path the same way before `sign`, `verify`, or the artifact stage.
- `docs/gate.schema.json` declares optional `relativePath` (`string` or `null`, omitted except on `share --json`). A strict consumer pinned to the v1.0.52 schema (`additionalProperties: false`, no `relativePath`) rejects current `share --json` until it allows that field.
- An RS* or PS* signature run with `/` or `+` at 342, 512, or 683 is redacted as a whole run when the length is not an exact RSA end (342, 344, 512, 683, or 684) and the in-segment tail is signature material. A tail of 1 to 48 characters stays only when it is a clear path: no uppercase letter, and every alphanumeric run is shorter than 8 characters, or the tail is one run of a single repeated character. `/src/app.ts`, `+src/app.ts`, and `+/src/app.ts` stay. A 48-character repeated-character path stays. A mixed run of 8 or more, an uppercase marker, or a tail longer than 48 is masked with the signature. The extra check is one pass over that tail.
- `verify` accepts a CR-only receipt the same way it accepts LF. CRLF was already accepted. A lone CR inside an otherwise LF or CRLF body stays in the hash. The writer-footer rule is unchanged: only the exact footer passes, and only ASCII space, tab, CR, and LF are ignorable trailing whitespace. NBSP, BOM, U+3000, and U+2028 still fail.

### Notes

- These are v1.0.53 Release QA follow-ups.
- `relativePath` is still computed from the git toplevel. This cut fixes consumers that joined that string to a subdirectory cwd, including the example action picker.
- Strict v1.0.52 gate schemas reject `share --json` because `relativePath` is a new property and `additionalProperties` is false. The shipped schema allows it. Other gate commands still omit the key.
- After an exact RSA base64url length, a glued path of 1 to 48 in-segment characters stays only when the tail has no uppercase letter and no mixed alphanumeric run of 8 or more. Eating a signature-like tail is preferred over leaving up to 48 raw signature characters in the clear. `/src/app.ts` stays because that tail is `/src/app`.
- Package version bumped to `1.0.54`. Pin comments that track the current cut are `v1.0.54`. The action default pin is `1.0.54`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.53] — 2026-10-20

### Fixed

- `verify --json` masks a secret-shaped repo or receipt path the same way `show`, `last`, `compare`, and `prove` already do. `attest` masks the path on `wrote <path>`, on `bundle <path>`, and on `OK` / `FAILED`, in plain output and in JSON. `verify --package` and `import` mask those displayed paths too. A failed `session import` masks a secret-shaped path in its error the same way, in plain output and in `--json` (the displayed package path, the reason, and planned file paths). A successful `session import` is unchanged. `last --path` stays raw. The stored receipt and the audit log stay as captured.
- An RS* or PS* signature whose standard-base64 run is longer than a known RSA length, and does not end on one, is not split at 342 or 512. Lengths such as 511, 600, and 682, with `/` or `+` at 342 or 512, are redacted as a whole run. A run that ends on 342, 344, 512, 683, or 684 still splits only at that length. After an exact RSA base64url length (342, 512, or 683), a clear glued path stays when the in-segment tail is 1 to 48 characters (`RSA_GLUED_PATH_MAX`). The 48 counts the `/` or `+` and the rest of the standard-base64 segment. It does not count a file extension after the segment dot. `/src/app.ts` stays because that tail is `/src/app` (8). A longer tail is masked with the signature. The check is one length compare on the segment that was already read.
- `share --json` adds `relativePath`: the receipt path relative to the git repository root (`git rev-parse --show-toplevel`), including when `share` runs from a subdirectory. When git has no toplevel, the base is the working directory. The value is null when that relative path leaves the base or is secret-shaped. Displayed `path` stays masked. `examples/github/action.yml` and `examples/github/pr-gate.yml` use `relativePath` when it is usable, and do not pass a masked path to `sign` or `verify`.
- `verify` fails closed unless the bytes after the integrity cut are the footer the writer emits: one `## Integrity` line, one blank line, one `<!-- agent-receipt-sha256:` line with 64 lowercase hex, one blank line, and one `SHA-256 of canonical body:` line carrying that same hash. A blank line here is only ASCII space, tab, CR, and LF (the writer emits an empty line). Extra lines, a second footer, a duplicated footer, a marker that is not 64 lowercase hex, and a prose hash that differs from the marker all fail. Plain output and `--json` both report `trailing content after the last chained record`, with exit 2, `verified` false, and `ok` false, including with `--require-sig`. `prove` follows that result. Trailing lines that are only ASCII space, tab, CR, or LF still pass. NBSP (U+00A0), BOM (U+FEFF), U+3000, and U+2028 after the footer fail. The hash still covers only the canonical body, so a hash mismatch stays the reason when the embedded marker does not match the body.

### Notes

- These are v1.0.52 Release QA follow-ups, plus the v1.0.53 Release QA re-gate on this same entry. The version was not bumped again.
- `RSA_GLUED_PATH_MAX` is 48. It applies only when the base64url prefix is an exact RSA length (342, 512, or 683) and the full third-segment run does not end on 342, 344, 512, 683, or 684. A clear path stays when that in-segment tail is 1 to 48 characters. A `/` tail is clear with a second slash or a file extension. A `+` tail is clear with a slash or a file extension. The 48 includes the joiner and stops at the end of the standard-base64 segment, so `.ts` in `/src/app.ts` is outside it. A longer tail is masked with the signature. Eating that path is preferred over leaving signature bytes in the clear. A `/` or `+` at 342 or 512 inside 511, 600, or 682 leaves a tail longer than 48, so those runs stay masked as a whole.
- Package version bumped to `1.0.53`. Pin comments that track the current cut are `v1.0.53`. The action default pin is `1.0.53`. That pin needs an npm publish, which is on hold.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.52] — 2026-10-20

### Fixed

- An RS* or PS* signature is no longer split at a shorter RSA length when the third segment reaches a longer one. The lengths are 342 (RSA-2048, standard-base64 344), 512 (RSA-3072, 512), and 683 (RSA-4096, 684 with one `=`). A `+` or `/` at 342 inside a 512- or 683-character signature stays masked, including when that signature is followed by `+`, `/`, `_`, or `=` and more text. A 342-character signature followed by a short path still keeps the path. The same rule applies to EdDSA, so an Ed448 signature (152) is not split at the Ed25519 length (86). The scan is still one pass over the segment that was already read.
- ES256K signatures use the ES256 length: unpadded base64url 86, standard-base64 88 with `==`. Ed448, which is EdDSA with a 114-byte signature, uses 152 in both forms. A clear glued path stays when the base64url run is that length. `=` after an Ed448 signature stays with the trailing text, because 152 is 0 mod 4.
- A JWT header that is only a non-empty string `kid`, or that puts `alg` after `kid`, is masked in both general and strict mode. A header that is still a JSON object but does not start with the usual `eyJ` is masked when it starts with `eyA` (`{` plus space), `ewo` (`{\n`), `ew0` (`{\r`), or `ewk` (`{\t`). `typ: JWT` with no `alg` and no string `kid` stays general-only. A kid-only token has no `alg`, so a glued path stays inside the mask.
- A secret-shaped directory name in the local repo path is masked on `compare`, `prove`, `doctor`, `audit`, `share`, `html`, `report`, and `log`, in plain output and in JSON where that command prints JSON. The mask is the same one `show` and `last` already use. `compare` has no JSON mode. `last --path` still prints the raw path. The stored receipt and the audit log stay as captured.

### Notes

- These are v1.0.51 Release QA follow-ups.
- A header that does not start with `eyJ`, `eyA`, `ewo`, `ew0`, or `ewk` is not scanned. That includes a UTF-8 BOM before `{`. Scanning every base64 run would mask ordinary base64 text.
- A path glued onto a signature whose base64url length is not the longest length that run reached, or onto an unknown `alg`, is still masked through the path. Eating the path is preferred over leaving signature bytes in the clear.
- Package version bumped to `1.0.52`. Pin comments that track the current cut are `v1.0.52`. The action default pin is `1.0.52`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.51] — 2026-10-14

### Fixed

- A padded standard-base64 JWT followed directly by `+`, `/`, `_`, or `=` and more text is masked. The example `eyJhbGciOiJub25lIn0=.+//v+w==.+y8=+hello` no longer leaves the header, payload, or signature in the clear. The joiner and the text after it stay. The same mask runs on the receipt (when redacted), attest, history, show, compare, and JSON listings. The scan stays linear. The `-`, `_`, `=`, `+`, and `/` joins of two tokens from 1.0.47–1.0.50 are unchanged.
- A path glued after a JWT with `/` or `+` is not eaten when the boundary is clear. A base64url token keeps `/src/app.ts` and `+src/app.ts`. A padded token keeps the path after the padding. The JWT itself is still masked.
- A filename that contains a backtick is included in the receipt files table and as an `attest` subject. The cell stores it git-quoted (`"has\140tick.txt"`) so the markdown span stays one span. A secret-shaped name is still stamped, and the raw token is not in the statement.
- Plain `history`, `show`, and `compare` mask secret-shaped text the same way `history --json` does. A `ghp_` token that was only in the git commit message, or in `--message`, is not printed. The stored receipt and index stay as captured.
- An old receipt that stored a literal git-quoted name (`"caf\303\251.txt"`) still decodes once with `unquoteGitPath`. The decode does not run twice, does not truncate the name, and does not turn `\400` into a NUL. A cell that was never quoted, including a backslash, stays as it was stored.
- The padding `=` search stops at the end of the current token (the first character that cannot be signature or padding). A multi-megabyte buffer with many JWTs and no `=` after them stays linear. The same shapes that were fast on 1.0.50 — space-separated tokens, `9xeyJ-` plus a JWT, a repeated `J/x/y.ts`, and a header plus `-eyJ-eyJ` — stay fast.
- A glued `/` or `+` path stays visible only when the base64url run before that character is the signature length for the token's own `alg`, read from the decoded header, and the tail is clearly a path. The lengths are HS256 43; HS384 64; HS512, ES256, and EdDSA 86; ES384 128; ES512 176; RS256, RS384, RS512, PS256, PS384, and PS512 any of 342, 512, or 683 (RSA 2048, 3072, or 4096). A `+` or `/` at 43, 64, or 86 inside a longer signature stays masked. That includes an HS512 signature with `/` at 43, and an RS256 signature with `+` at 64 or 86. An unknown `alg` (`none`, a name this list does not have) or a header that does not decode never splits. When that header is still a JWT, the mask includes the glued path. ES384 and ES512 keep a clear glued path. The earlier 1.0.51 path cases (`/src/app.ts`, `+src/app.ts`, and a padded token plus a path on a matching length) are unchanged. RS* and PS* accept every RSA size, so a `+` or `/` at 342 or 512 inside a longer RSA signature can still split.
- `last` and `last --json` mask secret-shaped text the same way `history`, `show`, and `compare` do. A `ghp_` token or an `AKIA` key that was only in the git commit message, or in `--message`, is not printed. The stored receipt and index stay as captured. `--path` still prints the raw path.
- A `=` is a boundary whenever the text before it is a valid JWT, at every signature length. The JWT is masked and the trailing text stays. The search stops at the end of the current token. Valid base64 padding is part of the mask: one `=` when the signature length is 3 mod 4 (HS256 is 43, RSA-4096 is 683), and `==` when the length is 2 mod 4 (HS512, ES256, and EdDSA are 86; RSA-2048 is 342). In those cases `=text` or `==text` leaves `text`. A `=` that is not padding stays with the text. HS384 (64), ES384 (128), ES512 (176), and RS384 at the RSA-3072 length (512) are 0 mod 4, so both `=text` and `==text` stay (`[REDACTED]=text`, `[REDACTED]==text`). A length that is 2 mod 4 keeps a single `=` (`[REDACTED]=text`) and consumes `==`. A length that is 3 mod 4 consumes one `=` and keeps a second (`==text` leaves `=text`). An already-padded token keeps a further `=text` after the mask. An empty signature followed by `=text` or `==text` keeps those equals. Hyphen suffixes are unchanged.

### Notes

- These are v1.0.50 Release QA follow-ups, plus the v1.0.51 re-gate on this same entry. The fixed bullets above are the behavior that ships.
- A path glued with `/` or `+` onto a signature whose base64url length is not the length for that token's `alg`, onto an empty signature, or onto an unknown `alg`, is still masked through the path. Eating the path is preferred over leaving signature bytes in the clear. The padding `=` boundary, and a base64url signature whose length matches that `alg` followed by `/` or `+` and a real path, are the cases that keep the path. A `+` or `/` earlier than that length does not start a path. RS* and PS* still share 342, 512, and 683, so a marker at a shorter RSA size inside a longer RSA signature can start one.
- Package version bumped to `1.0.51`. Pin comments that track the current cut are `v1.0.51`. The action default pin is `1.0.51`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.50] — 2026-10-14

### Fixed

- `unquoteGitPath` keeps raw non-ASCII inside a git-quoted path. With `quotePath=false`, a quoted name used to mask each character with `0xff`, so `你` collapsed to one byte and the file dropped out of the receipt and out of `attest`. An octal value above 255 (`\400`) is that character, not a NUL, and the rest of the path stays. Real UTF-8 octal (`\303\251`, `\304\200`) still decodes to the filename.
- The 1.0.49 sentence for a ~1MB `eyJ` run now matches measured time: about a second on a typical host, around three seconds on a slow one. It does not promise a hard sub-second bound. The masker is unchanged for that wording.
- Two JWT-shaped tokens joined by one `+` or one `/` are both masked. The joiner stays. Neither token's header, payload, or signature remains in the clear. A third token joined the same way is masked too. The `-`, `_`, and `=` joins from 1.0.48 and 1.0.49 are unchanged. The scan stays linear.
- A filename that contains a backslash or a newline is included in the receipt files table and as an `attest` subject. A newline is one quoted table row (`"has\nnewline.txt"`) so the row does not split. A secret-shaped name is still stamped, and the raw token is not in the statement.
- `history --json` masks secret-shaped text in the listing, including a `ghp_` token and the other existing secret patterns. A commit message passed as `--message` no longer shows the raw token. The stored index is left as captured.

### Notes

- These are v1.0.49 Release QA follow-ups.
- Package version bumped to `1.0.50`. Pin comments that track the current cut are `v1.0.50`. The action default pin is `1.0.50`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.49] — 2026-10-14

### Fixed

- Two JWT-shaped tokens joined by one `_` or one `=` are both masked. The joiner stays. Neither token's header, payload, or signature remains in the clear. A third token joined the same way is masked too. The hyphen join from 1.0.48 is unchanged. The scan stays linear.
- A hyphen suffix stays only when every piece is a whole word, lowercase or with one leading capital (`-then`, `-Then`, `-config-file`). The whole suffix stays, so `-config-file` is not cut down to `[REDACTED]-file`. A tail that is not one of those words is consumed with the token. That includes a short stopword (`-the`, `-a`, `-not`), an all-caps tail (`-THEN`), a digit (`-word9`), and the `-suffix` / `-low` leaks. A mixed tail such as `-suffix-file` is consumed in full. A padded token plus `-Then` or `-config-file` no longer leaves the token in the clear. `_x` and a lone `_` or `-` still stay.
- Filenames git prints quoted (non-ASCII and other C-style escapes, such as `"caf\303\251.txt"`) are decoded before the receipt is written. `attest` includes them as subjects. A secret-shaped name is still stamped, and the raw token is not in the statement.
- A ~1MB run of nine `eyJ-` prefixes plus a dot, and a ~1MB run of a JWT header plus repeated `-eyJ-eyJ`, finishes in about a second on a typical host and around three seconds on a slow one. That is not a hard sub-second bound. A header that is only `eyJ-` / `eyJ_` / `eyJ=` chunks is skipped, and a decoded header that is not one JSON object is not passed to `JSON.parse`. Real JWTs, including one after a long glued prefix, stay masked.

### Notes

- These are v1.0.48 Release QA follow-ups.
- Path stamping covers every secret-shaped filename, not only `ghp_`. Each path segment is stamped from that segment (`ghp_[REDACTED:<sha256-12>]`, and the same for the other secret shapes). The raw token is not in the stamp. `AKIA` and `ASIA` keep the key stamp.
- Package version bumped to `1.0.49`. Pin comments that track the current cut are `v1.0.49`. The action default pin is `1.0.49`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.48] — 2026-10-14

### Fixed

- A real JWT after a long glued run of `eyJ-`, `eyJ_`, or `eyJ=` prefixes is masked. The interior restart cap still stops a quadratic rescan. After that cap, the scan tries the last `eyJ` before the header dot once, so nine or more of one prefix, and a longer mixed run, no longer leave the token in the clear. The 64KB `eyJ-` / `eyJ_` / `eyJ=` bounds and the 1MB `eyJ=` bound stay in place.
- A `ghp_`-shaped filename is no longer raw in the share `###` path header or in `receipt.html`. Each path segment is stamped the same way a secret-shaped session id is (`ghp_[REDACTED:<sha256-12>]` from that segment). The raw token is not in the stamp. Other lines that already went through secret redaction stay free of the raw token.
- `attest` stamps a `ghp_`-shaped filename the same way, so two files stay two subjects and the raw name is not in the statement. Verify maps the stamp back by running that same stamp on the file name in the original receipt.
- Two JWT-shaped tokens joined by one `-` are both masked. The hyphen stays. Neither token's header, payload, or signature remains in the clear.
- A lowercase hyphen suffix that is an ordinary word (`-word`, and the existing `-then`) stays after `[REDACTED]`. A token-alphabet tail (`-suffix`, a tail with a digit, and the strict-mode `-low` fixture) is still consumed with the token.

### Notes

- These are v1.0.47 Release QA follow-ups.
- Package version bumped to `1.0.48`. Pin comments that track the current cut are `v1.0.48`. The action default pin is `1.0.48`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.47] — 2026-10-14

### Fixed

- JWT masking is a linear scan. A ~1MB run of `eyJ.` no longer goes through a nested quantifier that can backtrack. An interior `eyJ` after `-`, `_`, or `=` does not restart the scan over the same span. Restarts inside one header are capped, so a 64KB `eyJ-` or `eyJ_` run and a 1MB dotted `eyJ=` run stay fast. Real JWTs are still masked, including a segment longer than 8 KiB and a token after a short `eyJ-` / `eyJ_` / `eyJ=` prefix. Credential URLs keep the same `scheme://user:password@` replacement, with the scheme capped at 65 characters so that same input cannot make the scheme quantifier eat the whole buffer.
- Distinct AWS access keys no longer collapse to one masked id. `AKIA` and `ASIA` values are stamped `AKIA[REDACTED:<sha256-12>]` (and the same for `ASIA`) from the original key. The raw key is not in the stamp. The same key always stamps the same way. Session import still merges on the stored session string, so two packages that used different keys stay two sessions. Attest verify still maps that stamped subject name back to the file named in the original receipt.
- Every other masked session id is stamped the same way when the mask would be a bare `[REDACTED]`. A `ghp_` id becomes `ghp_[REDACTED:<sha256-12>]` from the original id, and a JWT-shaped id becomes `[REDACTED:<sha256-12>]`. Two different secrets stay two sessions after import. The same id always stamps the same way. The raw id is not in the stamp and cannot be looked up after import. Use the masked id on the packaged Session line or in `session-manifest.json`. `AKIA` and `ASIA` keep the key stamp above. Text that is not a session id, such as a `ghp_` token in a message, stays `ghp_[REDACTED]` without a stamp.
- `session export --include-host` without `--out` no longer uses a secret-shaped session id as the directory name. The default directory is `session-<sha256-12>.session` from the original id, the same opaque form as the v1.0.46 export fix. `--include-host` still keeps the original bytes and the original id inside the package. A non-secret id still uses `<id>.session`. `--out` still names the directory.
- A JWT segment longer than 8 KiB is masked. The per-segment cap is 256 KiB. A longer segment is not treated as a JWT. That bound is the DoS limit for the scan.
- A hyphen plus a lowercase base64url tail after a JWT (`-suffix`) is consumed with the token, including when padding makes the whole span invalid but the prefix is still a JWT. `_x` and a lone `_` or `-` stay. A mixed-case tail such as `-Def9Xyz` stays inside the token. A real word such as `-then` stays after the mask (`[REDACTED]-then`).

### Notes

- These are v1.0.46 Release QA follow-ups.
- Attest and keyless error scrubbers use a stricter JWT matcher than share, report, session export, and `redactSecretsInText`. Both use this linear scan, the 256 KiB segment cap, and the same suffix rule. The stricter matcher requires a non-empty `alg`. The general path also accepts a header whose `typ` is `JWT`.
- Package version bumped to `1.0.47`. Pin comments that track the current cut are `v1.0.47`. The action default pin is `1.0.47`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.46] — 2026-10-13

### Fixed

- `session export` (and `session pack`) of a session id that looks like a secret no longer exits 2 with a manifest/session mismatch. Share's redaction masked the Session line in the packaged receipt and re-hashed those bytes, then wrote the original id into `session-manifest.json`. The export integrity check compared those two and failed closed. The manifest `session` field is now the id on the packaged receipts, and the member hashes stay the hashes of the bytes that were written. When that id differs from the original and `--out` is omitted, the directory name is `session-<sha256-12>.session` from the original id, so the raw id is not a path segment. `--include-host` still keeps the original bytes and the original id on both sides. A package whose manifest session or member hash is then changed still fails verify.
- JWT masking now covers an unsigned `alg:none` token (an empty signature after two segments), short header, payload, and signature segments that still decode as a JWT header, and standard base64 (`+`, `/`, `=`) as well as base64url. The same share, report, and message paths as 1.0.45 apply. Dotted text that is not a token (a version, a filename, or an `eyJ` string whose header does not decode to a JWT) is left alone.
- A trailing `_x` or `-suffix` immediately after a JWT is no longer swallowed. The token is replaced and that suffix stays.

### Notes

- These are v1.0.45 Release QA follow-ups.
- Package version bumped to `1.0.46`. Pin comments that track the current cut are `v1.0.46`. The action default pin is `1.0.46`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.45] — 2026-10-13

### Fixed

- The signed report masks `--agent` before the page is written. The label is free text. Share's markdown pipeline already masked it, but the report payload and the session tree copied the raw label. `ghp_` tokens and the other patterns that pipeline already knows are replaced there. `--no-redact` still keeps the original text. A receipt that never went through share still verifies as captured.
- `--message` already went through that same mask on share and on the report, so a `ghp_` token in the message was already hidden. A JWT (`eyJ` header.payload.signature) was not one of those patterns. It is now masked in the share `receipt.md`, the share `receipt.html`, and the signed report payload. `--no-redact` still keeps the original text.
- A session id that looks like a secret (for example an id containing an AWS access key, `AKIA` plus 16 uppercase letters or digits) is masked in the signed report and in the human `session` tree. Looking up receipts still uses the original id. `--no-redact` on `report` still prints the original id. `session --json` still returns the original id.
- `report` and `report verify` of a session package check every member hash, including the recorded hash of `session-manifest.json`. A mismatch exits 2 with an integrity error and does not print VERIFIED.
- `session <id>` piped to a short reader (`head`) exits 0 when the only failure is EPIPE on stdout.
- Any command that fails to write to a full disk (`/dev/full`) exits 1 with one clean error line and no stack trace from the bin wrapper.
- A package with two or more receipts still loads `session-manifest.json` once for otlp, attest, and report.

### Notes

- Package version bumped to `1.0.45`. Pin comments that track the current cut are `v1.0.45`. The action default pin is `1.0.45`.
- 1.0.30 said the signed report uses the share redaction pipeline. The page still copied the raw `--agent` label into the payload, so a token there survived. Share already masked `ghp_` and the same patterns inside `--message`. This cut adds JWT masking on that message text and masks a secret-looking session id. 1.0.41 checked session-package member hashes on export and import. `report` on a package whose `session-manifest.json` hash did not match still printed VERIFIED. This cut corrects that too.
- `verify --json` does not grow a hash-cut index. `docs/gate.schema.json` rejects unknown keys, and the required gate keys stay the same. The cut index stays internal.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, npm Trusted Publishing, and a `verify --json` hash-cut index.

## [1.0.44] — 2026-10-13

### Fixed

- The human `session <id>` view writes the parent/child tree in bounded chunks instead of joining every line and calling `console.log` once. A session of tens of thousands of receipts, including a deep parent chain whose text is larger than one JavaScript string, finishes without `RangeError: Invalid string length`. The lines are unchanged: the `session <id>` header, the receipt count, a blank line, then `- id  status  exit N  …` with the same indent, orphan, cycle, and warning flags. `--json` is still one JSON object.
- `report` still embeds the session tree as one string in the signed payload. A tree that fits in 32 MiB is the same text as before, so a small report's signature does not change. A larger tree keeps a prefix and one truncation line (`session tree truncated: N more line(s) omitted (cap … bytes)`) instead of throwing. The signature covers that truncated text.

### Notes

- Package version bumped to `1.0.44`. Pin comments that track the current cut are `v1.0.44`. The action default pin is `1.0.44`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.43] — 2026-10-13

### Fixed

- `--out` refuses a hardlink or bind-mount alias of a share package file (`receipt.md`, `receipt.sig.json`, `manifest.json`, `manifest.sig.json`). The file has to sit in a `*.share` directory next to an input, or the input has to be that directory. Share files in other directories are not scanned. The check is the same identity test as v1.0.41: `realpath` of the parent plus `dev`+`ino`. The command uses the existing message and exit code and writes nothing. The name guard still refuses those names inside the `*.share` directory, including a `manifest.json` that is not on disk yet, and a case-folded name on a volume that folds case. A case-sensitive volume still allows a distinct basename.
- On a case-folding volume the basename fold also maps long s (U+017F) and dotless i (U+0131) to `s` and `i`. `manifeſt.json`, `manifest.jſon`, and `receıpt.md` do not bypass the share-file or companion guard. `ß` and ligatures are not folded.
- `share --package` can still create and refresh `receipt.md` and `receipt.sig.json` in that package. An alias of those files at another path is refused. A manifest file stays refused.
- A receipt whose body quotes `agent-receipt-sha256` or `## Integrity` inside a fenced block still hashes the whole body. The cut ignores those lines while the fence is open, so capture keeps the rest of the file and a fresh export writes. A plain `README.md` that only fences an example receipt does not protect `README.json`.
- A context line inside the receipt's own ` ```diff ` block is diff text. ` ``` ` and `~~~` on those lines do not open or close a fence, and they do not hide `## Integrity`. `capture --since <base>` of an edit inside a fenced code block in a markdown file still verifies.
- Receipts have no field for which cut sealed them. v1.0.42 cut at the first `agent-receipt-sha256` or `## Integrity` line, including one quoted in a diff, and that could leave ` ```diff ` or ` ``` ` unclosed. When that older body still hashes to the embedded marker, verify keeps that cut. A receipt sealed by v1.0.43 still hashes the quoted line and the rest of the fenced body.
- Every read of `session-manifest.json` in one command goes through one counter: the parse and the raw byte hash. Export, attest, and report of a package read that file once. A later hash of the same bytes is a cache hit.

### Notes

- Package version bumped to `1.0.43`. Pin comments that track the current cut are `v1.0.43`. The action default pin is `1.0.43`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- The text `session` view string-length limit noted here landed in 1.0.44 (chunked stdout).
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.42] — 2026-10-13

### Fixed

- `--out` refuses a share package `manifest.json` or `manifest.sig.json` when the name differs only by case (`MANIFEST.JSON`, `MANIFEST.SIG.JSON`). The check case-folds the basename and uses the same identity test as v1.0.41: `realpath` of the parent, and `dev`+`ino` when the target already exists. A case-sensitive volume still allows a distinct name. The command refuses with the existing message and exit code and writes nothing.
- `--out` refuses another receipt's `.md` and `.sig.json`, and a share package's `receipt.md` and `receipt.sig.json`, with that same identity check. The bytes stay put.
- A Markdown file protects the matching `.json` name only when that sibling is a receipt: the Markdown has the receipt marker, the `.json` parses as a receipt companion (`integrity` sha256), or the path is a share `receipt.md`. `README.json` next to a plain `README.md` is written.
- The identity check compares parent `dev`+`ino` and the file name when the destination file is not on disk yet, so a bind-mounted parent that names a missing companion is refused.
- Exporting a session package still reads `session-manifest.json` once per package. The package-export check counts that read instead of bounding wall-clock time.

### Notes

- Package version bumped to `1.0.42`. Pin comments that track the current cut are `v1.0.42`. The action default pin is `1.0.42`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- The text `session` view string-length limit noted here landed in 1.0.44 (chunked stdout).
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.41] — 2026-10-07

### Fixed

- `--out` is compared by file identity. `realpath` of the parent directory plus the file name is compared with the source, and `dev`+`ino` is compared when the target already exists. A symlinked parent that still names the source receipt no longer overwrites it. The same check covers macOS `/tmp` versus `/private/tmp` and a case-insensitive volume (parent `dev`+`ino` plus a case-folded basename when the file is not there yet; darwin and win32 always fold). The command refuses with the existing non-zero exit and writes nothing.
- That guard also covers `session-manifest.json`, `session-manifest.sig.json`, packaged receipts, and signature sidecars. A local receipt's `.sig.json` sidecar (`foo.md` → `foo.sig.json`) is protected the same way, including when the export is not reading a session package. HTML, Markdown, OTLP, intoto, share, prove, and report use it.
- `export --format otlp last --out <other>.json` will not replace another receipt's companion `.json` in the same directory.
- `--out` will not replace a share package `manifest.json` or `manifest.sig.json`.
- Exporting a session package reads that package's `session-manifest.json` once per export. A package with thousands of receipts no longer re-reads the manifest once per member.
- OTLP and intoto files are created with flag `wx` (exclusive create; an existing path is not opened or followed) and a `crypto.randomBytes` suffix. A pre-existing file or symlink at a temp-like path is left untouched. The temp file is removed if the write fails.
- Exporting a session package (`export --format otlp`, `export --format intoto`, and `session export` before it publishes) runs the same per-entry check as `session import`: canonical `sha256` and raw `bytes` hash. A mismatch exits 2 and writes nothing.
- A dangling symlink `--out` is refused and is not followed. A symlink to a file is refused. HTML and Markdown `--out` that ends with a slash, or names an existing directory, gets a clear error. `--out newdir/` used to write a file named `newdir` and now errors. OTLP, intoto, prove, report, `share --package`, and `session export` still accept a directory or a trailing slash as the folder for the default file.
- Parent-link walks for `session` and OTLP are iterative, so a chain of about 12k receipts does not overflow the stack.

### Notes

- Package version bumped to `1.0.41`. Pin comments that track the current cut are `v1.0.41`. The action default pin is `1.0.41`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.40] — 2026-10-07

### Added

- `agent-receipt export --format otlp` (alias `--format otel`) writes one OTLP/JSON trace file (`ExportTraceServiceRequest`: `resourceSpans`, `scopeSpans`, `spans`). The default path is the receipt with a `.otlp.json` suffix. `--out` names the file. `--session <id>` or a `*.session` package writes one linked trace: the root receipt is the root span, child receipts are child spans, and host is an attribute. Load the file with a collector `otlpjsonfile` receiver (Jaeger, Grafana Tempo, Honeycomb, Datadog). There is no network push.
- Resource attributes are `service.name` `agent-receipt`, `service.version`, and host and repository when the trace-root receipt has them. Scope name is `agent-receipt`. `traceId` is the first 16 bytes of that receipt sha256. Span ids are derived from the receipt sha256 and the span index. Commands and tool calls, including MCP, are child spans. A non-zero exit or a policy deny sets span status code `2` (`STATUS_CODE_ERROR`). Times are unix-nano strings. The same inputs write the same bytes.
- OTLP always redacts secrets in commands, arguments, host labels, and tool-call inputs. There is no `--no-redact`. HTML and Markdown still redact only with `--redact`. The receipt hash is checked before the write. Integrity failure exits 2 and writes nothing. The command does not append the audit log.
- [`docs/otlp.md`](docs/otlp.md) and [`docs/otlp-trace.schema.json`](docs/otlp-trace.schema.json).

### Fixed

- OTLP/JSON writes span `kind` and `status.code` as integers. `agent.run` is kind `1` (`SPAN_KIND_INTERNAL`). A command or tool call is kind `3` (`SPAN_KIND_CLIENT`). Status `1` is `STATUS_CODE_OK` and `2` is `STATUS_CODE_ERROR`. Name strings are not emitted. The schema accepts those integers and rejects the name strings.
- `export --format otlp --out` refuses the receipt's companion `.json` (`foo.md` → `foo.json`) as well as the receipt file. The companion bytes stay in place and no trace is written.
- A session whose parent links form a cycle exits 1 with a cycle error and writes no trace. `export --format otlp --session <id>` does this with no further flags. A normal parent/child tree still exports.

### Notes

- Package version bumped to `1.0.40`. Pin comments that track the current cut are `v1.0.40`. The action default pin is `1.0.40`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.39] — 2026-10-07

### Fixed

- `--allowed-host` and the live Host check reject a last label that is exactly `0x` (no hex digits). `foo.0x`, `0x`, `FOO.0X`, and `foo.0x:8080` are non-canonical. The host is lowercased before the check, so `0X` is the same label. Browsers parse a bare `0x` label as hex zero, which is an IPv4 address. `0x7f.example`, `foo.0xg`, and `foo.0x-a` are unchanged. The error still says non-canonical.

### Notes

- Package version bumped to `1.0.39`. Pin comments that track the current cut are `v1.0.39`. The action default pin is `1.0.39`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.38] — 2026-10-07

### Added

- `agent-receipt view --allowed-host <name>` (repeatable) accepts a LAN browser on a remote bind. Each value is a hostname, a canonical IPv4 address, or a bracketed or bare IPv6 address, optionally with `:port`. Without a port the name matches the bound port only. An entry with `:port` matches that port only. IPv6 is stored in compressed lowercase form, so `[fd00::1]`, `fd00::1`, and `fd00:0::1` are the same entry. Names are lowercased. The match is exact. There is no DNS lookup, no interface scan, and no wildcard.
- `--allowed-host` requires `--allow-remote` unless every value is loopback (`127.0.0.1`, `localhost`, or `::1`). It is rejected with `--static`. A comma-separated list is rejected. Repeat the flag. Empty values, a value that starts with `-`, wildcards, schemes, paths, whitespace, and userinfo are rejected before the server listens. Punycode labels (`xn--`) are accepted. Unicode internationalized names are rejected.
- The Host check accepts the bound host:port and each allowed host. `X-Forwarded-Host` and similar headers are ignored. A second `Host` header is HTTP 400 `{"error":"bad request"}`. Anything else is still 403 `{"error":"forbidden"}`.
- `--json` on a live bind adds `allowedHosts` (a normalized array, empty when the flag is omitted). The `--allow-remote` warning lists those hosts and says there is no auth. The default bind stays `127.0.0.1`.

### Fixed

- `--allowed-host` and the live Host check reject a non-canonical numeric address. A last label that is all digits or `0x` hex is rejected unless the value is a canonical IPv4 address: four decimal octets from 0 to 255 with no leading zeros. `127.1`, `2130706433`, `0x7f000001`, `1234`, and `010.0.0.1` are rejected. `192.168.1.20` still matches.
- IPv6 entries compare in compressed lowercase form. `fd00:0::1` matches `[fd00::1]`. Brackets on the flag are optional.
- `--allowed-host ""` fails with `--allowed-host requires a hostname, IPv4 address, or IPv6 address.` It does not report `view does not take a receipt path`.
- `--allowed-host -h`, and any other value that starts with `-`, is a usage error and exits non-zero. It does not print help.
- Punycode labels (`xn--`) stay allowed. A Unicode internationalized name is rejected. [`README.md`](README.md), [`docs/viewer.md`](docs/viewer.md), and `view --help` say so.

### Notes

- Package version bumped to `1.0.38`. Pin comments that track the current cut are `v1.0.38`. The action default pin is `1.0.38`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.37] — 2026-10-07

### Fixed

- The local viewer no longer trips its own Content-Security-Policy. Chrome was logging `frame-ancestors` from the `<meta>` policy (browsers ignore that directive in a meta element) and requesting `/favicon.ico`, which `img-src 'none'` blocked. The empty favicon is `<link rel="icon" href="data:,">` with `img-src data:`. `frame-ancestors 'none'` stays on the HTML HTTP header only. The meta policy omits it. Inline script and style stay sha256-hashed. There is no `'unsafe-inline'`, `'unsafe-eval'`, wildcard, or remote origin. The static `file://` bundle uses the same meta policy with `connect-src 'none'`.

### Added

- Integration tests spawn `view` on port 0. `--host 0.0.0.0 --allow-remote` prints the warning, emits the JSON line, and `GET /api/receipts` on `127.0.0.1` returns 200. Without `--allow-remote` the process exits non-zero and does not listen. `localhost` and `::1` stay loopback. A forged `Host` on a remote bind is still rejected. A parser test checks that every inline script and style in the served page and the static bundle is covered by the CSP hash, with no `on*` attributes, no `style` attributes, and no remote resource URLs.

### Notes

- Package version bumped to `1.0.37`. Pin comments that track the current cut are `v1.0.37`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.36] — 2026-10-06

### Added

- `agent-receipt view` serves receipts and linked session trees in a local browser. The server is `node:http` only, binds `127.0.0.1` by default, and is read-only. `--port 0` picks a free port. `--json` prints one line (`url`, `port`, `receiptCount`, `pid`) and keeps serving. `--open` opens a browser best-effort. `--receipts` selects the directory. `--trusted-key` and `--require-sig` use the same verify rules as `verify`.
- `agent-receipt view --static <dir>` writes a self-contained offline bundle (`index.html` and `data.json`, inline CSS and script, no CDN) that opens from `file://`. The same inputs write the same bytes.
- JSON API: `GET /api/receipts`, `GET /api/receipts/:id`, `GET /api/sessions`, and `GET /api/verify/:id`. Other methods return 405. Receipt ids come from an in-memory index. Path traversal is rejected. A `Host` header other than the bound host:port is rejected. Responses set `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
- The page lists time, agent, adapter, risk, exit, signed or unsigned, verify status, and policy-pack hits. Filters cover agent, risk, signed, failed, and text. Detail shows commands, files, tool calls, the gate, policy hits, signature, keyless, attestation, and hash-chain position. The session tree shows parent, child, and host for linked receipts.
- View always redacts, including secrets in host labels. `--no-redact` is rejected. Host labels that are not secrets stay visible.
- `doctor` adds an INFO `viewer` row. It is not a failure, including under `--strict`.
- [`docs/viewer.md`](docs/viewer.md).

### Changed

- `--policy-pack` rejects a comma-separated list and tells you to repeat the flag. Repeated `--policy-pack` still works. The GitHub Action input stays comma-separated and is split into repeated flags.
- `builtin:supply-chain` denies a PowerShell download piped to `Invoke-Expression` (`iwr`, `irm`, `Invoke-WebRequest`, or `Invoke-RestMethod` piped to `iex` or `Invoke-Expression`). Rule id `powershell-download-pipe`.
- `action.yml` rejects version pins with a leading zero (`01.0.34`). The default pin is `1.0.36`.

### Notes

- Package version bumped to `1.0.36`. Pin comments that track the current cut are `v1.0.36`.
- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. This is not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.35] — 2026-10-06

### Added

- Declarative policy packs. A pack is YAML or JSON with `apiVersion: agent-receipt/policy/v1`, `name`, `description`, and `rules`. Each rule has `id`, `description`, `severity` (`low`, `medium`, `high`, `critical`), `action` (`deny` or `warn`), and `match`. Match covers commands (glob or `regex:`), file globs, tool and adapter names, network and package-install commands, publish commands, exit codes, risk, agent, an unsigned receipt, redaction disabled, and size or count limits. The matcher is deterministic. There is no Rego engine and no eval.
- Built-in packs ship in `policies/`: `baseline` (secret files, workflow edits, history rewrite, curl piped to a shell), `supply-chain` (lockfiles, dependency manifests, package installs, publish), `ci-protect` (CI config and credential paths), and `strict` (those three, plus a required signature). Reference them as `builtin:<name>` or by file path. `extends` composes packs. The same rule id later in the chain overrides the earlier one.
- `.agent-receipt.yml` accepts `policyPacks` and `policyExceptions` (`rule`, `path`, `reason`, optional `expires`). An exception whose date is before today (UTC) does not suppress the hit and fails a gate that is using packs. A missing, unreadable, or invalid pack fails closed (exit 1).
- `agent-receipt policy list`, `policy show <pack>`, `policy lint <file>`, and `policy test <pack> [receipts...]`. Lint exits 1 on schema errors (unknown keys, duplicate ids, bad globs). Test exits 2 on a deny hit or an expired exception. `--json` prints one object for each.
- `--policy-pack <name|file>` (repeatable) on capture, wrap, share, verify, watch, and pr-comment. Deny hits fail the gate (exit 2). Warn hits are reported and do not change the exit code. With no pack configured, those commands omit the new keys and behave as before.
- Hits (`rule`, `pack`, `severity`, `action`, `evidence`, `receipt`) are redacted and included in the gate JSON (`policyPacks`, `policyPackHits`, `policyDenied`), a `## Policy packs` section on the receipt when packs ran, and the pr-comment summary (`### Policy packs`).
- `action.yml` input `policy-pack` (comma-separated) is passed through to the gate as repeated `--policy-pack`.
- `doctor` adds a `packs` row. It stays INFO when no pack is configured. `--strict` fails an invalid pack or an expired exception.
- [`docs/policy-packs.md`](docs/policy-packs.md) and [`docs/policy-pack.schema.json`](docs/policy-pack.schema.json).

### Changed

- Package version bumped to `1.0.35`. The action default pin is `1.0.35`.
- [`README.md`](README.md) and CLI help document policy packs. Pin comments that track the current cut are `v1.0.35`.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. Packs use the existing zero-dependency YAML reader. This is not a certificate authority.
- Still deferred: a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.34] — 2026-10-06

### Added

- Root [`action.yml`](action.yml) is a composite GitHub Action (`runs.using: composite`) with branding. One `uses:` line gates a pull request on agent receipts. Inputs include `version` (default `1.0.34`, installed with `npx` of that exact version, never `latest`), `command` (`gate`, `verify`, or `attest-verify`), `fail-on`, `policy`, `receipts`, `require-signature`, keyless `certificate-identity` / `certificate-identity-regexp` / `certificate-oidc-issuer` (passed through to `attest --verify`), `comment` (`on`, `off`, or `on-failure`), `comment-mode` (`update` or `create`), and `github-token`. Outputs are `verdict`, `risk`, `receipts-count`, `summary-path`, and `comment-url`. The step exits non-zero when the gate fails. Invalid inputs exit 1 before `npx`.
- `agent-receipt pr-comment` renders a short Markdown summary (verdict, risk, receipts checked, policy hits, signature or keyless status, hash-chain head, share packages). `--dry-run` prints it. `--out` writes it. `--json` prints one object. The same Markdown is appended to `GITHUB_STEP_SUMMARY` when that variable is set. Text is redacted with the existing secret masks before it is printed, written, or posted.
- Posting uses the GitHub REST API and global `fetch`. `<!-- agent-receipt:summary -->` marks the sticky comment. `--comment-mode update` patches that comment. `create` posts a new one. Repository, pull request number, and API URL come from `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, and `GITHUB_API_URL`, with `--repo`, `--pr`, `--api-url`, and `--event-path` overrides. The token is `GITHUB_TOKEN` and is never printed. HTTP 403 and 404 (a fork pull request with a read-only token) warn and fall back to the step summary without changing the gate exit code. Network errors do the same. A missing pull request context fails clearly unless `--dry-run` or `--comment off` is set.
- [`docs/github-action.md`](docs/github-action.md) has usage snippets (basic gate, policy and fail-on, signed and keyless verify) and a Marketplace checklist (release tag, major tag `v1`, listing). Those snippets are not installed as workflows.

### Changed

- Package version bumped to `1.0.34`.
- [`README.md`](README.md) and CLI help document the action and `pr-comment`. Pin comments that track the current cut are `v1.0.34`.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. No git tags and no GitHub release were created. This cut does not publish to npm.
- No new runtime dependencies. `pr-comment` uses `node:fs` and global `fetch` only. This is not a certificate authority.
- Still deferred: policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.33] — 2026-10-06

### Added

- `attest --keyless` signs one in-toto statement with an ephemeral P-256 key. Fulcio issues a short-lived certificate from an OIDC token. Rekor stores the DSSE entry. The bundle is `application/vnd.dev.sigstore.bundle.v0.3+json`, written as `<stem>.sigstore.json` beside the `.intoto.jsonl`. The private key and the OIDC token are never written and never logged. `sign --keyless` is not a command.
- The OIDC token comes from `--identity-token <file>` (`-` is stdin), else `SIGSTORE_ID_TOKEN`, else the GitHub Actions ambient token (`ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, audience `sigstore`). `--fulcio-url` and `--rekor-url` override the public-good hosts. A network error, HTTP error, or timeout exits 1 and writes nothing.
- `attest --verify <bundle.sigstore.json>` checks the bundle offline. `--certificate-identity` or `--certificate-identity-regexp`, plus `--certificate-oidc-issuer`, are required. Missing them exits 1. The certificate must chain to the trusted root (embedded public-good Fulcio and Rekor, or `--trusted-root`), be valid at the Rekor integrated time, and match the SAN and issuer. The DSSE signature, signed entry timestamp, checkpoint, and inclusion proof are checked, then the subject digests and the hash-chain head. A mismatch exits 2. See [`docs/keyless.md`](docs/keyless.md).

### Fixed

- A secret in an attestation subject filename is redacted (`AKIA…` becomes `AKIA[REDACTED]`). Verify still resolves the file from the on-disk receipt. Two files that redact to the same name with different digests fail closed.
- Dictionary passphrases in free text are redacted (`password: "correct horse battery staple"`, and `"password":"hunter2"`). Prose without an assignment, and words such as `compass` or `passport`, stay.

### Changed

- Package version bumped to `1.0.33`.
- [`README.md`](README.md), CLI help, and [`docs/keyless.md`](docs/keyless.md) document keyless signing. Pin comments that track the current cut are `v1.0.33`.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. The GitHub Actions example in [`docs/keyless.md`](docs/keyless.md) is a snippet only. [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) does not call the public Fulcio or Rekor services.
- This cut does not publish to npm. No new runtime dependencies. This is not a certificate authority. Embedded SCT verification is not implemented. Historical Rekor keys are not embedded. `attest` does not append `audit.jsonl`.
- Still deferred: a published GitHub Action, policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync, and npm Trusted Publishing.

## [1.0.32] — 2026-10-06

### Added

- `agent-receipt attest [path|last]` writes an in-toto Statement v1 (`_type` `https://in-toto.io/Statement/v1`) inside a DSSE envelope, one envelope per line (`.intoto.jsonl`). Payload type is `application/vnd.in-toto+json`. The signature is Ed25519 over the DSSE pre-authentication encoding (PAE), using the same local key as `sign`. `keyid` is that fingerprint. The envelope also carries the SPKI public key. The private key is never written. Missing keys write an unsigned envelope, warn, and exit 0. `--no-sign` does the same. A corrupt key file exits 1 and writes nothing.
- The default predicate is `https://agent-receipt.dev/run/v1` (agent, session, commands, tool calls, policy hits, exit code, and the hash-chain head). `--slsa` or `--predicate slsa` writes SLSA Provenance v1 (`https://slsa.dev/provenance/v1`) with `buildDefinition` and `runDetails`. Subjects are the receipt and changed files that are still regular files under the byte cap. Each digest is sha256 of the raw file bytes. The hash-chain head is the receipt canonical sha256, the same hex `verify` prints. Paths stay relative to the working directory. Host and workspace are omitted.
- `attest --verify <file>` (alias `attest verify <file>`) checks the DSSE signature against the trusted public keys, each subject digest against the file on disk, and the hash-chain head against the receipt. Unsigned, a bad signature, an untrusted fingerprint when the allowlist is active, a digest mismatch, or a hash mismatch exits 2. A missing file exits 1. An empty trust store accepts any cryptographically valid signature and prints a note (`trusted` is null). `--json` prints one object on stdout for create and verify. Warnings stay on stderr.
- `export --format intoto` (aliases `in-toto` and `dsse`) writes the same envelope as `attest`. It does not append the audit log. HTML and Markdown export are unchanged.
- One receipt writes `<stem>.intoto.jsonl` beside that receipt. A session package writes `<id>.intoto.jsonl` beside the package, one envelope per packaged receipt. `--session <id>` writes `<id>.intoto.jsonl` beside `outDir`. A receipt that fails integrity exits 2 and writes nothing. See [`docs/intoto.md`](docs/intoto.md) and [`docs/intoto-statement.schema.json`](docs/intoto-statement.schema.json).

### Fixed

- Write and Edit free text now redacts 1–3 character assignment values such as `password="ab"`. Longer values still use the existing pattern.
- Encoded secrets (base64 or even-length hex that decodes to printable ASCII and matches a secret pattern) are redacted in transcript text, including values stored under a non-sensitive key.
- Tool-argument keys are secret-shaped tokens after camelCase is split (`apiKey`, `api_key`). A path that merely contains `key` (`keyboard`, `src/keys/config.ts`, `file_path`) is no longer replaced wholesale.

### Changed

- Package version bumped to `1.0.32`.
- [`README.md`](README.md), CLI help, [`docs/agents.md`](docs/agents.md), [`docs/business.md`](docs/business.md), [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md), and [`SECURITY.md`](SECURITY.md) document attestation export. Pin comments that track the current cut are `v1.0.32`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the earlier smokes and adds an `attest last` / `attest --verify` smoke. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm. No new runtime dependencies. This is not a certificate authority. `attest` does not append `audit.jsonl`.
- Subject digests are the files on disk at attest time. A later edit fails `attest --verify` (fail closed). Verify must run where those relative paths still exist.
- Still deferred: Sigstore keyless signing, a published GitHub Action (the drop-in under `examples/github/` stays an example to copy), policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.31] — 2026-10-06

### Added

- `agent-receipt adapters` lists Claude Code, Cursor, Grok CLI, and Codex. `adapters status`, `adapters install [name]`, and `adapters uninstall [name]` are idempotent. Omit the name to install or remove every adapter. `--dry-run` writes nothing, including no backup. `--json` prints one object (`adapters` for list/status, `results` with `files` and `changed` for install/uninstall). `--no-stop` skips the extra Stop hook on Claude Code, Codex, and Cursor. SessionEnd stays. Codex installs SessionEnd and Stop. Grok uses SessionEnd only.
- Install merges into the project config and does not drop existing keys or other hooks. The first install snapshots the previous bytes under the git dir (`git rev-parse --git-path`, `.git/agent-receipt-adapter-backups/<adapter>/`), keyed to the project root, so the copy is not an untracked work-tree file. A repo without git uses `.agent-receipt/adapter-backups/` and gitignores that directory. Each entry records the post-install sha256. A later install refreshes the snapshot when the file changed. Uninstall restores the snapshot when the file still matches. When it does not, uninstall strips only this adapter's hooks unless `--force` is set. With no snapshot, uninstall strips and reports `stripped`. Invalid JSON, a `hooks` array, and an event that is not an array are refused and are not rewritten. A symlink is refused, including a symlink in the backup path. A read-only config fails with `permission denied` and leaves no snapshot. `init --claude`, `init --codex`, `init --cursor`, and `init --grok` use the same installers. Fresh Grok and Cursor rule bytes stay the checked-in constants. Hook commands use `$(git rev-parse --show-toplevel)`.
- `capture` and `wrap` accept `--transcript <file>` and `--adapter <name>` (`claude-code`, `cursor`, `grok`, `codex`). Tool calls, including MCP (`mcp__server__tool`, CallMcpTool, Codex `mcp_tool_call`, JSON-RPC `tools/call`), become a `## Tool calls` section inside the hashed body, labeled `mcp:<server>/<tool>`. Arguments are redacted key by key before they are stringified (keys matching pass, pwd, secret, token, key, auth, cred, cookie, or session), then with the secret patterns, including token prefixes after `_`, a high-entropy pass, and internal hosts such as `.corp` and `.lan`, even when `--redact` is off. Omit `--adapter` and the file is sniffed. A shell command is not scanned for paths. A missing or unparseable transcript warns on stderr, omits the section, and still exits 0. An unknown adapter exits 1 and writes no receipt. The companion JSON adds `toolCalls` (`adapter`, `count`, `truncated`, `sha256`, `events`). Those companion fields are not covered by the receipt integrity hash or the Ed25519 sidecar. Trust the hashed `## Tool calls` section. Low-severity risks `tool-call-unmentioned-diff` and `tool-call-write-not-in-diff` name a diff path no call mentions, and a write tool whose path is absent from the diff.
- Report `renderVersion` 2 includes that section when the receipt has one. An empty tool-call section is omitted. 1.0.30 rejects a payload that includes `toolCalls` and rejects renderVersion 2, so this page is a forward-compat break for 1.0.30. The version 1 renderer stays for pages written before that. `doctor` adds an `adapters` row that is always INFO and does not fail `doctor` or `doctor --strict`.

### Fixed

- Tool-call arguments and MCP tool names no longer keep JSON passwords, SQL `pw='…'` values, `api_key` and `tok_` values, high-entropy tokens, `AKIA` / `ghp_` / `xoxb-` prefixes after `_`, or one-label internal hosts when the transcript is recorded.
- Uninstall no longer discards edits made after install, and an install from a subdirectory no longer deletes a root config on uninstall from the repo root. A dry-run names `would discard user changes`.
- Stop hooks no longer treat an untracked receipt directory as a dirty tree, so a clean project does not write a new receipt on every stop. The out dir, `.agent-receipt/index.json`, `.agent-receipt/audit.jsonl`, and `.agent-receipt/resign-provenance.json` are ignored. Hook stdout and stderr are discarded and the wrap is limited to 120 seconds. A missing `sleep` does not kill the wrap. Cursor hook entries set `timeout: 120`.
- A corrupt adapter backup manifest or a missing blob fails uninstall and leaves the hooks and the backup in place. Manifest paths are checked before any file is written. `hooks: []` and an event set to an object are refused.
- `UNSIGNED (1 receipt not checked)` and `VERIFIED (payload only; 1 receipt not checked)` use the singular. A non-date prune timestamp says `prune timestamp is not a date`.
- A trusted key holder can re-sign an altered narrative. Trust means trusting the signer. `report verify` checks the signature and the page bytes. It does not prove the narrative matches an earlier unsigned draft.

### Changed

- Package version bumped to `1.0.31`.
- [`README.md`](README.md), CLI help, [`docs/agents.md`](docs/agents.md), [`docs/grok-cli.md`](docs/grok-cli.md), [`docs/business.md`](docs/business.md), and [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) document native adapters and MCP tool-call capture. Pin comments that track the current cut are `v1.0.31`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the 1.0.30 report smoke and adds a 1.0.31 `adapters install claude-code --dry-run` smoke that must not create `.claude`. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`docs/receipt.schema.json`](docs/receipt.schema.json) documents optional `toolCalls`. [`docs/report-payload.schema.json`](docs/report-payload.schema.json) documents optional `toolCalls` and renderVersion 2.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm. No new runtime dependencies.
- Hook scripts exit 0. They wrap only when the working tree is dirty. This is not a certificate authority.
- Still deferred: in-toto/SLSA export, Sigstore keyless signing, a published GitHub Action (the drop-in under `examples/github/` stays an example to copy), policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.30] — 2026-09-30

### Added

- `agent-receipt report <receipt|last>` and `agent-receipt report --session <id>` (also `report <path/to/*.session>` or a `session-manifest.json`) write one self-contained HTML file. The default path is the sibling of `outDir`: `.agent-receipt/receipts` becomes `.agent-receipt/<stem>.report.html`. A receipt stem that is not a safe filename becomes `report-<sha256-12>.report.html`. A session id that is one safe path segment becomes `<id>.report.html`; anything else becomes `session-<sha256-12>.report.html`. `--out <file>` is that file. An existing directory, or a path that ends with `/`, receives `<stem>.report.html`. The report is never written over the source receipt. `*.report.html` is not a receipt. `last`, `history`, and `prune` ignore it. The report does not append the audit log and does not add an index row.
- The page is one file: inline CSS, no images, fonts, or network requests. JavaScript is not required to read it. The verdict banner is VERIFIED, FAILED, UNSIGNED, or UNTRUSTED. The page shows what the agent did (summary, commands, files touched, risk flags, What to review, commits, range, and a capped diff excerpt), the session tree for a session report (parent, child, agent, and re-sign claims), signer fingerprints and trust per receipt, the CLI version, the generated timestamp, and the exact commands to re-verify offline. Those commands use basenames.
- Redaction uses the same `publishRedactedReceipt` pipeline as `share` and `session export` (secrets, nested receipt or index bodies, and the Host line). `--include-host` keeps Host and still masks secrets, the same as `share --include-host`. `--no-redact` skips that pipeline and wins over `--include-host`. Either opt-out prints a loud UNREDACTED marker. The default page does not.
- Signing embeds `<script type="application/json" id="agent-receipt-report">` with the canonical JSON payload. That payload holds every string the page shows: verdict, banner, pills, agent, fingerprints, trust, the signature status line, the title, the UNREDACTED state, and the narrative (branch, message, summary, files, diff, commits, risk, and the session tree). A detached `<report>.html.sig.json` is the existing Ed25519 `SignatureDocument` over the UTF-8 hex SHA-256 of that canonical JSON (sorted keys, no whitespace). The signature is not inside the payload. Render then inserts the same document as `id="agent-receipt-report-sig"` at a fixed place. An unsigned report embeds JSON `null` there and the page says UNSIGNED. Missing keys exit 0. A receipt that fails verify, a present invalid receipt signature, or a session whose root or any receipt fails verification still writes the page with verdict FAILED and exits 2. UNTRUSTED means an active allowlist rejected a fingerprint; generation still exits 0. See [`docs/report-payload.schema.json`](docs/report-payload.schema.json).
- `agent-receipt report verify <file.html> [more.html ...]` finds exactly one payload block and exactly one signature block outside HTML comments. The scan is a tag parser, not a regex. Zero, a duplicate, or a block inside a comment exits 2. A payload that is present but fails the schema exits 2. Verify checks the signature over the canonical payload, re-renders the page from that payload and the signature, and requires the same bytes. A single missing trailing newline is ignored. Any other difference exits 2 with `page content does not match signed payload`. Several files are checked; the exit code is the worst of them. Every candidate for a payload receipt must be acceptable: any file whose parsed id matches, or whose raw sha256 or embedded hash is the recorded `sha256` or `redactedSha256`, under any name, subdirectory, or session. `.md` is case-insensitive. A symlink candidate exits 2. A candidate must pass receipt integrity. When its raw sha256 is the recorded sha256, or equals the recorded `redactedSha256`, and the payload records a fingerprint or `originalFingerprint`, a valid sidecar with that fingerprint is required, with or without `--require-sig`. When the payload is unsigned, a valid stray sidecar is ignored. An invalid sidecar fails. Redact-then-hash (`publishRedactedReceipt`) is limited to a session-package report (`manifestSha256` set), and a non-null `originalFingerprint` then requires a valid sidecar with that fingerprint, so `report <package>.session` still verifies in the exporter's repo and a stripped re-hashed original does not. A package report records `originalSha256` when the exporter store still has the pre-redaction file. An unacceptable file exits 2 with `receipt <id> at <path> fails integrity`, `signature mismatch`, or `differs from the signed payload`. `--receipts <dir>` searches that directory only: a referenced receipt that is absent exits 2. Without `--receipts`, a missing receipt that the store index or audit log still lists exits 2. Otherwise the headline is `VERIFIED (payload only; N receipts not checked)` and `--json` uses verdict `VERIFIED_PAYLOAD_ONLY` with `notChecked`. `--receipts` pointing at a missing or unreadable directory exits 1. Exit 0 only when the signature is valid, the page matches, and the verdict is VERIFIED, or, without `--require-sig`, when an honestly UNSIGNED page matches (printed UNSIGNED, never VERIFIED). Verdict FAILED exits 2. Verdict UNTRUSTED exits 2. UNSIGNED with `--require-sig` exits 2. A non-zero exit never prints VERIFIED. A failing unsigned page prints `FAILED (unsigned)`, not UNSIGNED. A missing or unreadable report file exits 1. `originalFingerprint`, `resignedBy`, and `signedBy` are the manifest signer's claims when they come from a session package.
- Share HTML and the report use the same Content-Security-Policy meta tag: `default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'`. `style-src 'unsafe-inline'` is the stylesheet inside the file. There is no external CSS to hash, and a style hash would change on every edit without adding a boundary the opened file does not already have. `script-src 'none'` blocks executable script. The report's JSON blocks are `type="application/json"` data, not script. `prove --html` is unchanged and still has no script element.

### Changed

- Package version bumped to `1.0.30`.
- [`README.md`](README.md) and [`docs/business.md`](docs/business.md) document the signed one-page report. Pin comments that track the current cut are `v1.0.30`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.30. A smoke runs `report last` and `report verify`. Live [`.github/workflows/*`](.github/workflows) was not edited.
- Share HTML decodes a percent-encoded branch or workspace for display, then HTML-escapes it. The stored receipt is unchanged.
- Default `session export` of an unsigned receipt whose bytes change (redaction) no longer presents the exporter key as the original author. It warns on stderr and records `signedBy` with `originalFingerprint` null and `resignedBy` null. A same-key rewrite leaves `signedBy` null. A different key still requires `--resign` and uses `resignedBy`. Packages written before 1.0.30 omit `signedBy`; readers treat that as null. [`docs/session-package.schema.json`](docs/session-package.schema.json) documents the field. It is not required, so older packages still validate.

### Fixed

- `report verify` no longer accepts the first sha256 match and ignores other same-id files. A genuine copy cannot hide an edited original, including a copy named so it sorts first or last, a copy in a subdirectory, a stray edited copy, a same-id file from another session, or a directory passed to `--receipts` that holds both. An edit that redaction would mask (host, AWS key, `--include-host`, `--no-redact`, a session report, `--receipts` on the store or on a package) still exits 2, because a local-store report does not accept a redact-then-hash stand-in and every candidate must pass integrity and its signature. Re-hashing after that edit exits 2 with `signature mismatch` when the sidecar no longer verifies. On a session-package report, re-hashing the original and deleting its sidecar also exits 2 with `signature mismatch` when `originalFingerprint` is set, with or without `--require-sig`.
- A receipt removed from the store while `index.json` or `audit.jsonl` still lists it exits 2, including a deleted session root. The newest audit event for that sha256 or path wins. When that event is `prune`, or a prune event removed the index row, the receipt is not still listed: `report verify` exits 0 with the reason `receipt absent; audit.jsonl (unsigned) records a prune` and the headline `VERIFIED (payload only; N receipts not checked)` (`VERIFIED_PAYLOAD_ONLY`, `notChecked`). A missing capture, wrap, or watch event for that receipt is not tampering: the result stays payload-only (exit 0) with that reason. Exit 2 only when one of those events exists in this log and the prune is timestamped more than 5 seconds before it. Clock skew of up to 5 seconds stays payload-only. `audit.jsonl` is not signed. Anyone with write access can extend it. A prune line written by `prune` records `source` `command` or `retention`. When the store has no retention config (`maxCount`, `maxAgeDays`, or `autoPrune`) and the newest prune line is not `source` `command`, verify warns. `source` `retention` does not silence that warning unless that config is present; the warning then adds `(retention source claimed but no retention config found)`. `prune --max-count` and auto-prune (`maxCount` plus `autoPrune`) no longer false-fail a report of a receipt they deleted (re-gate `b9c376a`). A report checked where this store never listed the receipt prints that same payload-only headline, not a plain VERIFIED. A symlink candidate exits 2. A case-variant name such as `.MD` is a candidate.
- After `session import`, the imported copy's raw sha256 equals the exporter's signed `redactedSha256`. `report verify` accepts that byte match for a local-store page (`report --session`, a single receipt, and `--receipts` pointing at the package) and for a package report. It does not treat a redact-then-hash of a different body as that match.
- When `.agent-receipt/audit.jsonl` exists in the store being searched, `report verify` checks the audit hash chain with the same rules as `doctor --strict` and exits 2 with `audit log hash chain is broken` on a break. `--receipts` pointing elsewhere does not use an unrelated `audit.jsonl` in the current directory. A chain-only failure is counted in `failed`. Deleting a receipt, its index row, and audit lines cannot fall through to payload-only. A store with no `audit.jsonl` stays payload-only. Exactly one trailing CR is stripped from each audit line before the line is parsed and hashed, in `verifyAuditChain`, so `doctor` and `audit --verify` accept a `core.autocrlf` checkout of the log. Two trailing CRs still fail the chain. If the chain still fails and the failing line itself ends in CR, the reason names CRLF and `core.autocrlf`. Add `.agent-receipt/** -text` next to `*.report.html -text` in `.gitattributes`.
- A receipt-check failure keeps counting after the first problem and reports the full checked, skipped, and failed totals. The reason lists every problem.
- Share HTML escapes bidi controls (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F) as `\uXXXX`, the same as the report page.
- The receipt candidate walk has a depth cap of 4. It applies equally when verifying pages from `report last`, `report verify`, and `report --session`. A file at depth 5 or deeper is not a candidate.
- A report page that starts with a UTF-8 BOM (EF BB BF) exits 2. The decoder uses `ignoreBOM: true` and the leading bytes are checked explicitly. CRLF (`\r\n`) is still `page has CRLF line endings`. A lone CR is `page has CR line endings`. A receipt-check failure prints checked, skipped, and failed counts.
- CRLF (`\r\n`) in a report page exits 2 and names `core.autocrlf` (`*.report.html -text` and `.agent-receipt/** -text` in `.gitattributes`). The page bytes are not rewritten to LF. A lone CR uses `page has CR line endings` and does not use the CRLF message. Invalid UTF-8, including a `0xFF` byte where U+FFFD was rendered, exits 2.
- `renderVersion` (integer, starting at 1) is part of the signed payload. Verify selects the HTML renderer by that field and exits 2 with `unsupported report renderVersion` for an unknown version. The v1 renderer stays in place for a later template.
- With no trust store, `report verify --require-sig` still accepts any valid self-signed page. It prints a one-line note and the docs recommend a trust allowlist (`agent-receipt trust add --self`).
- Bidi controls (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F) in rendered fields, including agent names, are shown as `\uXXXX`.
- A single-receipt failure says `receipt <id> failed verification`. `session root` is only used for a session report.
- `report` refuses an input that contains the report payload block, including a report renamed to `.md`, not only a `*.report.html` name.
- `prune` lstats every target (receipt, JSON companion, and `.sig.json`) before it unlinks anything. A symlinked sidecar is refused and nothing from that batch is deleted, so prune does not exit 1 after deleting only some files.
- `session import` removes stale `.import-staging-*` directories it owns when they are older than the current run. A directory counts only when it contains the marker file `.agent-receipt-import-staging`. Anything without that marker is left alone, including a symlink that uses the prefix. `--dry-run` does not delete them.
- `session <id>` and the human `session import` summary show `originalFingerprint`, `resignedBy`, and `signedBy` after import. The claims are stored in `.agent-receipt/resign-provenance.json`, keyed by the canonical receipt sha256. That file is the manifest signer's claim. It is not a second signature over the pre-export bytes. `originalFingerprint` on the manifest is the same kind of claim, covered by `session-manifest.sig.json` when that sidecar verifies.
- A symlinked `.agent-receipt` parent is followed. Receipts, keys, and the trust store are written in the real directory.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm. No new runtime dependencies.
- The whole rendered page is covered. The signature is over the canonical payload, and `report verify` requires a deterministic re-render of that payload to match the file bytes (one optional trailing newline). This is not a certificate authority.
- Reports written by the unpublished pre-release commits `88dad95` and `985e363` do not verify under this code. Those pages have no `renderVersion` and use the earlier template. Commit `3131122` omits `originalSha256`, so those pages do not verify either. Nothing published depends on that format.
- Agent Receipt 1.0.29 cannot import 1.0.30 session packages. The manifest may include `signedBy`, which 1.0.29 rejects as an unknown field.
- `report <file>.report.html` exits 1 with `input is already a report; use report verify` instead of writing another report.
- `last` still selects the newest `*.md` under outDir by mtime. A planted copy with a newer mtime can become `last`. That is pre-existing and is not changed in this fix.
- Range and Summary are clean text. `session --json` waits for stdout to drain so a pipe is not cut off at 64 KiB.
- Still deferred: native adapters (Claude, Cursor, Grok, Codex, MCP), in-toto/SLSA export, Sigstore keyless signing, a published GitHub Action (the drop-in under `examples/github/` stays an example to copy), policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.29] — 2026-09-30

### Added

- `agent-receipt session export <sessionId>` (alias `session pack`) writes a portable session directory. The default path is the sibling of `outDir`: `.agent-receipt/receipts` becomes `.agent-receipt/<sessionId>.session/`. A session id that is not one safe path segment is packed as `session-<sha256-12>.session`. `--out <dir>` names that directory. An existing path is refused.
- The package contains every local receipt the `session <id>` list would show (including orphans, cycles, and a `missing-session` child), as `receipts/<basename>.md`, plus `receipts/<basename>.sig.json` when a sidecar is copied or re-signed, `session-manifest.json`, and optional `session-manifest.sig.json`. The manifest (`kind: agent-receipt-session`, version 1) records the CLI version, session id, receipt count, and one entry per receipt: id, parent, agent, host, relative path, canonical `sha256`, raw `bytes` hash, `signed`, `fingerprint` (the packaged sidecar), `originalFingerprint` (the source sidecar, or null), `resignedBy` (the local fingerprint when this export re-signed a different key, or null), and warning flags. See [`docs/session-package.schema.json`](docs/session-package.schema.json).
- Unless `--include-host`, export runs the same function as `share`: secret values are masked, a nested receipt or index diff body is replaced with `[REDACTED — nested receipt/index body omitted]`, and the header Host line becomes `[REDACTED]`. Session, parent, and agent stay. The receipt is re-hashed. `--include-host` keeps the original receipt bytes, including Host and any secrets, so a valid sidecar still matches. That flag does not match `share --include-host`, which still masks secrets and nested bodies and only keeps Host. An unchanged body copies a valid source sidecar. A body signed by the local key is re-signed when keys load and left unsigned (no stale sidecar) when they do not. A body whose sidecar fingerprint is a different key is not re-signed: export exits 2 and writes nothing unless `--resign`. `--resign` re-signs with the local key, warns on stderr with both fingerprints, and sets `resignedBy`. With no local key, `--resign` drops the sidecar, keeps `originalFingerprint`, and warns that the packaged copy is unsigned. `session-manifest.sig.json` is the same Ed25519 `SignatureDocument` as `sign`, over the UTF-8 hex SHA-256 of the manifest bytes, so it covers `originalFingerprint` and `resignedBy`. Missing keys omit it and do not exit 2.
- An empty session exits 1 and writes nothing. A listed receipt that fails verify, or a present sidecar that does not verify, exits 2 and writes nothing. Orphans and cycles are packed and named in `warnings` (`orphan`, `cycle`, `cross-session-parent`, `parent-unverified`, `missing-session`). A parent that fails verify outside this session does not by itself block export. Receipts, sidecars, and `session-manifest.json` are stat'd before they are read. The defaults are 32 MiB, 256 KiB, and 8 MiB. `--max-receipt-bytes`, `--max-sidecar-bytes`, and `--max-manifest-bytes` raise them (integer ≥ 1). Over the limit exits 2 with the size and the flag, and writes nothing.
- `agent-receipt session import <packageDir>` (alias `session merge`) verifies the package, then copies receipts and sidecars into `outDir`. The original basename is kept when it is a safe `*.md` name. The same id and the same canonical sha256 skips (idempotent) and does not rewrite a sidecar. The same id, or the same basename compared case-insensitively, with a different sha256 refuses the whole import and writes nothing. A stray sidecar is a conflict unless its bytes are identical. An unreadable destination, including mode `0200`, is a conflict. A symlink at the destination or at a parent inside `outDir`, including a dangling symlink and a symlink `outDir`, exits 2 and writes nothing. Copying stages under `outDir` and publishes each file with an exclusive no-overwrite link (`COPYFILE_EXCL` when the link is unavailable). A pre-existing file is not overwritten and is not deleted. A failure removes the stage and any names this import published. `--dry-run` plans the copy. `--json` prints `copied`, `skipped`, `conflicts`, and `files[]` with `fingerprint`, `originalFingerprint`, and `resignedBy`. `--require-sig` requires a valid receipt sidecar and a valid manifest signature, and trusted fingerprints when an allowlist is active. The same byte caps as export apply to the package, and an over-limit file exits 2 before it is read.
- Verify is fail-closed. Malformed manifest shape (kind, version, required fields, lowercase hex) exits 1. A file hash that does not match the bytes on disk, a receipt that fails the existing hash path, a canonical sha256 that does not match the manifest entry, a present invalid receipt sidecar, or a present invalid manifest signature exits 2. An absent receipt sidecar is fine when the entry is unsigned. An absent manifest signature is fine unless `--require-sig` is set. A failed verify copies nothing.
- After import, `agent-receipt session <id>` lists the merged tree. Imported receipts stay under `outDir` and keep their session id. Import does not append the audit log and does not add an index row. `history` still prefers the index, so a fresh import is absent there while the index has rows. `last` follows mtime.
- `last`, `history`, and `prune` ignore `*.session/` package directories the same way they ignore `*.share/`. `session-manifest.json` and the files inside the package are not receipts.

### Changed

- Package version bumped to `1.0.29`.
- [`README.md`](README.md) and [`docs/business.md`](docs/business.md) document cross-host session merge. Pin comments that track the current cut are `v1.0.29`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.29. A smoke runs `session export`, `session import`, and `session --json`. Live [`.github/workflows/*`](.github/workflows) was not edited.
- `doctor` link row names `session export` and `session import`. It stays INFO and does not fail default `doctor` or `doctor --strict`.

### Fixed

- `session export` verifies every listed receipt before it creates the package directory. A verify failure leaves no partial `*.session/` tree. A write that fails after a temporary directory is created removes that directory.
- Default `session export` no longer rewrites only the header Host line. It uses share's redaction function, so a nested `wrap --link` diff cannot keep a parent Host line or a secret that share would have removed.
- `session export` does not replace another key's sidecar. Redaction that must change those bytes exits 2 unless `--resign`, and the manifest records the original fingerprint and the re-signer.
- `session import` does not follow a symlink in `outDir`, does not overwrite a stray sidecar, and does not replace an unreadable same-basename receipt. A failed copy leaves no partial file.
- `prune` deletes the `.sig.json` sidecar of each receipt it deletes. A symlink sidecar is refused, not followed.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm. No new runtime dependencies.
- Export and import do not append `.agent-receipt/audit.jsonl` and do not invent capture index rows.
- Still deferred: a signed HTML report / signed one-pager, native adapters (Claude, Cursor, Grok, Codex, MCP), in-toto/SLSA export, Sigstore keyless signing, a published GitHub Action (the drop-in under `examples/github/` stays an example to copy), policy packs, a local web viewer, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.28] — 2026-09-29

### Added

- Optional receipt link metadata in the hashed body: `session` (a group of related runs), `parent` (the `r-` id or sha256 of the run that spawned this one), `agent`, and `host`. `capture`, `wrap`, and `watch` accept `--session`, `--parent`, and `--agent`. Flags win over `AGENT_RECEIPT_SESSION`, `AGENT_RECEIPT_PARENT`, and `AGENT_RECEIPT_AGENT`. `--agent` stays a free-form label (spaces allowed). `--session` still accepts the values 1.0.27 stored, including spaces and slashes, as one line. Generated session ids (`--session new`, `--link`) are `s-` plus 16 hex. `--host` uses the strict label charset. `--parent` is an r- id, a sha256, or a path to a receipt file. Empty values, newlines, control characters, and agent or session values longer than 256 characters fail before a file is written. Nothing new is written when no link flag and no link env var is set. Receipts written by 1.0.27 or earlier verify, `verify --require-sig`, and prove with the same exit codes as under 1.0.27, and no link metadata is read from them.
- `wrap --link`, or an explicit `--session` (including `--session new`), writes a session id and an `r-` id, then exports `AGENT_RECEIPT_SESSION` and `AGENT_RECEIPT_PARENT` (this receipt's id) to the command after `--`. A nested wrap records the same session and that parent. The child starts in the process working directory (pass `--cwd` on the child when the parent used it). The child's exit code is printed and does not change wrap's exit code. With no `--link` and no `--session`, arguments after `--` stay ignored.
- `host` is omitted unless `--host` or `AGENT_RECEIPT_HOST` is set. `share` and `export --redact` keep session, parent, and agent, and mask host as `[REDACTED]` unless `--include-host`. `--no-redact` skips that mask. A local `capture --redact` keeps an explicitly requested host.
- `agent-receipt session <id>` lists receipts in that session as a parent/child tree (pass/fail, exit, agent, timestamp, verified). `--json` prints `session` and `receipts[]` with `id`, `parent`, `agent`, `verified`, `exitCode`, and `warnings`, and flags orphans and cycles. Exit 1 when any receipt fails verify, when a local parent fails verify, or the session is empty locally. Orphans, cycles, a parent in another local session (`cross-session-parent`), and a child whose Session line is missing (`missing-session`, when a parent reference points at this session) do not by themselves change the exit code. Receipts written outside `outDir` are not listed.
- `prove` and `prove --html` show session, parent, and whether a local parent verifies. Those JSON keys are omitted when the receipt is unlinked. Parent verify does not change the prove exit code. Host is not shown.
- `doctor` adds an INFO `link` row. It does not fail default `doctor` or `doctor --strict`.

### Changed

- Package version bumped to `1.0.28`.
- [`README.md`](README.md) and [`docs/business.md`](docs/business.md) document linking multi-agent runs. Pin comments that track the current cut are `v1.0.28`.
- [`docs/receipt.schema.json`](docs/receipt.schema.json) documents optional `id`, `parent`, and `host`. The CI gate schema is unchanged (link fields are not on the gate).
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.28. A smoke runs a nested `wrap --link` and checks `session --json`. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Fixed

- `escapeHtml` also escapes `'` as `&#39;`, so a quote in receipt data cannot break out of an attribute in `prove --html`.
- The `prove --html` Content-Security-Policy meta tag adds `img-src 'none'` and keeps `default-src 'none'` and `style-src 'unsafe-inline'`.
- The `[1.0.27]` note that said the cut was stacked on #39. 1.0.27 landed on main directly after 1.0.26 (auto-prune, PR #39).
- `--agent` and `AGENT_RECEIPT_AGENT` accept the same free-form labels as 1.0.27, including spaces (`Claude Code`, `git hook`). Config `defaultAgent` uses those same rules. Newlines, other control characters, and more than 256 characters are rejected. Previously working hook and rule invocations (`--agent grok`, `--agent cursor`, `--agent git-hook`) still write receipts.
- `--session` keeps 1.0.27 acceptance for values such as `old sess/1` (spaces and slashes). The value is stored raw on one line. `--session new` and `--link` still generate an `s-` + 16 hex id. The strict label charset stays on `--host` and on those generated ids.
- `--message` accepts multiple lines again, as in 1.0.27 (`grok-wrap.sh $'a\nb'` included). The text is quoted in the TL;DR and indented inside the `## Session` header, so continuation lines cannot become headings or header fields. A one-line message is written the same way as before.
- `--parent` accepts an `r-` id, a 64-hex sha256, or a path that parses as an agent-receipt file. Arbitrary files are rejected.
- `examples/github/pr-gate.yml` labels `prove --html` as v1.0.27. That flag shipped in 1.0.27.

### Security

- Link metadata (`Id`, `Session`, `Parent`, `Agent`, `Host`) is parsed only when both of these hold. The bytes from `# Agent Receipt` through the end of `## Session` match the 1.0.28 writer grammar, and that check does not track fences. The grammar is the writer's title, then only TL;DR lines (`> **TL;DR**`, blank lines, and `> `-quoted message lines), then `## What to review` in the writer's body shape, then `## Summary` in the writer's table shape, then `## Session` fields in writer order, then the heading the writer emits next (`## Notable changes`, `## Commits`, or `## Files changed`). A raw line, a fence (`` ``` `` or `~~~`, any info string), an extra heading, a CR-only or mixed line ending, or an out-of-order field in that region fails the grammar. Uniform CRLF still matches. Then the whole file is scanned line by line with fences ignored: a line inside a fence still counts. There must be exactly one line equal to `# Agent Receipt`, exactly one equal to `## What to review`, and exactly one equal to `## Session`. If any count is not one, the receipt is pre-1.0.28: no link metadata, and there is no fallback `## Session`. When the TL;DR line contains a timestamp, it must match the header Timestamp. A TL;DR with no timestamp skips that check. The 1.0.28 writer emits one, and it matches. The Version field inside a grammar match decides 1.0.28+ (`1.0.28` and any newer major.minor.patch). Pre-1.0.28 receipts have no link metadata. `verify`, `verify --require-sig`, and prove keep the 1.0.27 exit codes, including when a pasted block contains `Id: TODO` or a host outside the strict label charset (those are not a 1.0.28 tamper failure).
- A 1.0.16, 1.0.20, 1.0.24, or 1.0.27 writer quotes only the first message line and writes the rest raw, then writes its own real header after the message. A message that pastes a 1.0.28 block (`## What to review`, the nothing-flagged line, the Summary table, a full `## Session` with Version 1.0.28, then `## Commits`) therefore contains those headings more than once (the paste, again where the old writer repeats the message, and the real header). The whole-file count is not one, so the receipt is not linked. `session s-spoof` does not list it. The same holds when the message's first line is `# Agent Receipt` (the old writer quotes that line and leaves the rest raw) and when a blank line sits after `x`. Only the author of that old receipt, or whoever holds the key that signs it, can put that message in the hashed body. The rule makes every pre-1.0.28 receipt unlinkable. It does not stop the author of a 1.0.28 receipt from writing link fields; those fields are what `--session` and `--parent` are for.
- On a 1.0.28+ receipt, a hash match is not enough when the receipt id (`r-` + 16 hex), parent (`r-` id or sha256), or host fails the strict check: `verify` exits 2. Those checks do not run for pre-1.0.28 receipts. Generated session ids are `s-` + 16 hex when created. Free-form agent and session text is checked at capture (length and control characters) and is not a verify-time tamper failure. Length and control-character checks do not run against 1.0.27 or earlier receipts. A long agent, a tab in the agent or session, or a carriage return or U+2028 in an older agent still verifies. The share mask `[REDACTED]` is a legal stored host and still verifies. The 1.0.28 writer quotes every message line in the TL;DR, first line included, and indents every continuation line of the header Message, so a message line equal to `# Agent Receipt`, `## What to review`, or `## Session` is not that heading. Commit subjects are stored as one `- <hash> <subject>` line, and a continuation that is exactly one of those headings is indented. Diff body lines from git already start with `+`, `-`, or a space; a diff line that is exactly one of those headings is indented too. A file name, a risk detail, or a notable-change line that would be exactly one of those headings is indented, and a review item is kept on one line. The receipt has no audit section (the audit log is `.agent-receipt/audit.jsonl`). `prove` and `share` do not paste a second copy of the receipt into the hashed body. A branch or workspace path containing a backtick is percent-encoded in those header fields (`%` as `%25`, `` ` `` as `%60`) so the single-backtick grammar still matches and the link is kept. Diff-stat rows whose path starts with `` ``` `` or `~~~` are indented so the row cannot close the diff-stat fence.

### Notes

- Live workflow files were not edited. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm. No new runtime dependencies.
- Still deferred: cross-host session merge and import of whole session trees, a signed session manifest, a signed HTML report / signed one-pager, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing. Share HTML had no CSP meta tag in 1.0.28. That meta was added in 1.0.30. 1.0.28 added `img-src 'none'` to the `prove --html` Content-Security-Policy. The `prove --html` page itself was not otherwise changed in 1.0.28.

## [1.0.27] — 2026-09-26

### Added

- `prove --html` writes one self-contained, offline HTML verification report beside the receipt (`foo.md` → `foo.prove.html`; a name without `.md` gets `<name>.prove.html`). It is rendered from the same prove report as stdout, `--json`, and `--page` (verification is not forked). The page opens with a clear PASS / FAIL banner (PASS is exit 0, the same condition as PROVED) and the failure reasons, then the hash check and SHA-256, the audit hash chain (present / intact / events / matched), Ed25519 signature and trust status (VALID / INVALID / UNSIGNED, fingerprint, TRUSTED / UNTRUSTED / no trust store), redaction status, a receipt summary (agent, timestamp, branch, HEAD, message, TL;DR, files, lines, risk, uncommitted, failed gate), the changed-file list, and risk findings, plus a generated-at timestamp, the agent-receipt version, and the tamper-evident disclaimer. The report is written on FAIL too; exit codes are unchanged. It does not append the audit log.
- Share-safe by default: every receipt-derived string in the HTML goes through the same secret redaction as `share` (`redactSecretsInText`), secret-bearing risk details (`isHighSecretRiskCode`) are masked as `[REDACTED]`, all text is HTML-escaped, and URL schemes in receipt text are defanged (`https[:]//`) so nothing is clickable or fetchable.
- Offline and self-contained: inline CSS only; no `<script>`, `<link>`, images, fonts, `@import`, or `url(...)`; no http(s) references; a `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ...">` and `no-referrer`. Light and dark color schemes and print styles are inline.
- `--out <file|dir/>` works with `--html` using the same rules as `--page` (an existing directory or a trailing `/` receives `<stem>.prove.html`). `--out` now requires `--page` or `--html`. `--page --html` writes both files; with both, `--out` must be a directory. The HTML is never written over the source receipt. `*.prove.html` is not a receipt (receipt scanners only read `.md`).
- JSON parity: `prove --json --html` adds optional `htmlPath` (absolute string) when the report was written. The field is omitted without `--html`. Required prove keys are unchanged. Human stdout adds one `html:` line.

### Changed

- Package version bumped to `1.0.27`.
- `agent-receipt help prove` documents `--html` (and drops "HTML export of this page is deferred"); the command list mentions `--html writes foo.prove.html`.
- [`docs/business.md`](docs/business.md) documents `prove --html` under Prove and moves it from Deferred to landed. The lead sentence tracks 1.0.27.
- [`README.md`](README.md) and [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) document `prove --html`, with a tip to upload `*.prove.html` as a CI artifact for reviewers. Pin comments that track the current cut are `v1.0.27`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.27. A smoke runs `prove --json --html`, checks `htmlPath`, the PASS banner and sha256, and asserts no scripts, links, or http(s) references. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.27`. No new action input.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- The HTML report is not itself signed. Still not a CA. No new runtime dependencies. `prove --html` is a rendering of the prove result; re-run `prove` or `verify --require-sig` on the receipt to re-check.
- Landed on main directly after 1.0.26 (auto-prune, PR #39). It was not stacked on #39.
- Still deferred: a signed HTML report / signed one-pager, full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config, multi-agent receipt linking, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.26] — 2026-09-23

### Added

- Config `autoPrune: true` and CLI `--prune` / `--no-prune`. When `autoPrune` is true **and** retention is enabled (`maxCount` and/or `maxAgeDays`), a successful `capture`, `wrap`, or `watch` write runs the same trusted prune as `agent-receipt prune` (no `--force`, no dry-run). One `prune` audit line is appended per deleted receipt. Resolution matches `sign`: `--no-prune` wins, then `--prune`, then config. Absent or `autoPrune: false` leaves capture, wrap, and watch non-deleting. `autoPrune: true` with no retention limit deletes nothing. An invalid non-boolean is reported by `validateConfig` / `doctor`. `init --retention` does not turn `autoPrune` on. `init --auto-prune` sets only `autoPrune: true` (combine with `--retention` when you want both) and does not replace `ignore`, `redact`, or the limits.
- Audit safety on that auto path: a broken `.agent-receipt/audit.jsonl` chain deletes nothing, prints a stderr warning (and names `prune --force` / fixing the chain), and does **not** change the capture, wrap, or watch exit code. The receipt just written stays. If prune throws (invalid retention, unsafe `outDir`, broken index), the command warns on stderr and still exits with the capture result. Manual `agent-receipt prune` still exits 1 on a broken chain. share, export, verify, prove, import, doctor, and a capture that wrote nothing do not auto-prune.
- Auto-prune runs only after a **successful** run. A `capture` or `watch` capture that matches `--fail-on` (exit 2), or a `wrap` that matches `--fail-on` or fails verify (exit 2), deletes nothing and appends no `prune` audit line. `--json` reports `autoPrune: true`, `pruned: 0`, and `pruneReason: "failed-run"`, and human output prints `pruned: skipped (failed run)`. The exit code is unchanged.
- `doctor` adds an `autoPrune` row: INFO when unset or false, PASS when true and a retention limit is set, WARN when true but `maxCount` and `maxAgeDays` are unset (names `init --retention`). That WARN does not fail default `doctor` or `doctor --strict`. Unset `autoPrune` does not fail `--strict`.
- capture and wrap `--json` add optional `autoPrune`, `pruned`, and `pruneReason` only when this run attempted auto-prune. `pruneReason` is null when trusted prune ran, or `failed-run`, `retention-off`, `chain-broken`, or `error`. The fields are omitted when auto-prune was off. Human stdout prints `pruned: N receipt(s)` when something was deleted, and a short skip line when the chain broke. Quiet when auto-prune is off.

### Changed

- Package version bumped to `1.0.26`.
- [`docs/business.md`](docs/business.md) documents `autoPrune` under Retention. The first cut of the background deleter (auto-prune after capture) is landed. A long-running prune daemon or cron is still deferred. The lead sentence tracks 1.0.26.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) note that `autoPrune: true` plus a retention limit deletes after capture, wrap, and watch. Pin comments that track the current cut are `v1.0.26`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.26. Smoke with retention and `autoPrune` checks that a wrap over `maxCount` deletes older receipts and appends prune audit lines, and that a broken audit chain still exits 0 and deletes nothing. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.26`. No new action input. `examples/org-policy.yml` comments `# autoPrune: true` next to retention.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents optional `autoPrune`, `pruned`, and `pruneReason`. Required gate keys are unchanged.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. No new runtime dependencies. Auto-prune is not a daemon and not cron. It reuses trusted prune and does not pass `--force`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config (signing stays opt-in via config `sign: true` or `--sign`), a signed one-pager, unsigned HTML prove export (`prove --html`), multi-agent receipt linking, a long-running prune daemon or cron, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.25] — 2026-09-23

### Added

- `verify --package` (alias `--pack`) checks a share package from `share --package` in one command. Pass the directory (`foo.share/`) or `manifest.json` (resolved to the parent). A directory whose `manifest.json` has kind `agent-receipt-share` is detected without the flag. `--package` forces package mode and exits 1 when the path is not a package. A normal `.md` path stays a plain receipt verify. Checks, fail closed: manifest shape (kind, version 1, required fields, lowercase hex) is exit 1 when malformed; every `manifest.files` byte hash must match (`signed: true` requires `receipt.sig.json`, `signed: false` rejects that sidecar); `receipt.md` is verified with the existing hash path and its canonical sha256 must equal `manifest.sha256`; a present `receipt.sig.json` is inspected (valid is reported, invalid exits 2 even without `--require-sig`; missing is fine when unsigned); `--require-sig` requires a valid sidecar and, when a known-keys allowlist is active, a trusted fingerprint; a present `manifest.sig.json` must verify over the hex SHA-256 of the current `manifest.json` bytes (absent is fine, invalid exits 2). HTML is a file hash only. The HTML body is not signed. Human stdout prints VERIFIED or FAILED, the package path, sha256, signed, fingerprint, file hashes, receipt verify, signature, manifestSig, and a tip to open `receipt.html`. `--json` keeps command `"verify"` and adds `packagePath`, `signed`, `fingerprint`, `filesOk`, `manifestOk`, `manifestSig`, and `signature`. Required gate keys are unchanged. Plain `verify --json` omits those fields. Exit 2 is integrity or signature policy. Exit 1 is usage, missing, or malformed.
- `import <packageDir>` runs the same package check, then copies `receipt.md` and `receipt.sig.json` (when present) into the local outDir as `receipt-import-<sha256-12>.md` plus a sibling `.sig.json`. HTML and `manifest.json` are not copied. A failed verify copies nothing. `--dry-run` prints the planned paths and writes nothing. `--json` uses command `"import"` and adds `importPath`, `importSigPath`, and `dryRun` (null paths when verify failed). Import does not append the audit log and does not add an index row. It is verify plus copy, not a local capture. The copied file keeps the source integrity footer, so it is a receipt under outDir. `history` lists `index.json` when that catalog has rows, so the import does not appear there until the index is empty. `last` follows mtime and can show a fresh import.

### Changed

- Package version bumped to `1.0.25`.
- [`docs/business.md`](docs/business.md) documents peer `verify --package` and `import` under share / handoff. Both are landed. The lead sentence tracks 1.0.25.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) tip peers to run `verify --package` on `*.share/`. Pin comments that track the current cut are `v1.0.25`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.25. After `share --package`, smoke runs `verify --package --json` (exit 0) and `verify --package --require-sig` (exit 0 when keys signed the package). Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.25`. No new action input. A comment names `verify --package`.
- [`docs/share-package.schema.json`](docs/share-package.schema.json) notes that peers run `verify --package`. [`docs/gate.schema.json`](docs/gate.schema.json) documents the optional package fields and command `"import"`.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The HTML body is unsigned. Import does not append the audit log.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config (signing stays opt-in via config `sign: true` or `--sign`), a signed one-pager, unsigned HTML prove export (`prove --html`), a background deleter, multi-agent receipt linking, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.24] — 2026-09-22

### Added

- `share --package` (alias `--pack`) writes a portable handoff directory. `foo.md` becomes `foo.share/` beside the receipt. `--out` overrides that directory when it names an existing directory or ends with `/`. Any other `--out` leaves the sibling `<stem>.share/`. The package always contains `receipt.html` and `receipt.md` (it implies `--md`; a separate `--md` path is not a second file) plus `manifest.json`. `receipt.sig.json` is copied or re-signed with the same Markdown sidecar handoff as `share --md` / export. A rewrite with no local keys leaves the Markdown unsigned and does not copy a stale sidecar (the existing `keygen` / `sign` tip; that does not exit 2). When local keys load, `manifest.sig.json` is the same Ed25519 `SignatureDocument` as `sign`, over the UTF-8 hex SHA-256 of the `manifest.json` bytes. Missing keys omit `manifest.sig.json` and do not exit 2. The HTML body stays unsigned. The package is signed via the Markdown sidecar and the optional manifest sidecar. Human stdout prints `package: <dir>` plus the html / md / sig lines, and tips peers to open the HTML and run `verify`, `prove`, or `verify --require-sig` on `receipt.md`. `--json` adds optional `packagePath` (omitted when not packaging). `htmlPath`, `markdownPath`, and `sigPath` point at the files inside the package. Required gate keys are unchanged. A source that fails verify is not rewritten. Redact stays the default. `--no-redact` still works. One `share` audit event (the inner export is not a second line). `last`, `history`, and `prune` ignore `*.share/` directories. `manifest.json` and the files inside the package are not receipts. `*.prove.md` stays ignored. Without `--package`, share is unchanged (HTML by default; Markdown only with `--md`; HTML unsigned). Not a CA. Schema: [`docs/share-package.schema.json`](docs/share-package.schema.json).

### Changed

- Package version bumped to `1.0.24`.
- [`docs/business.md`](docs/business.md) documents the share package under share / handoff. HTML/share signed package is landed. A signed one-pager and `prove --html` stay deferred. The lead sentence tracks 1.0.24.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) note that `share --package` ships HTML and signed Markdown together. Pin comments that track the current cut are `v1.0.24`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.24. After keygen, smoke runs `share --package --json` and checks `packagePath`, `receipt.md`, `receipt.html`, and `receipt.sig.json`, then `verify --require-sig` on the package Markdown exits 0. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.24`. No new action input. A comment names `share --package`.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents optional `packagePath`.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The HTML body is unsigned. Peers verify `receipt.md`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config (signing stays opt-in via config `sign: true` or `--sign`), a signed one-pager, unsigned HTML prove export (`prove --html`), a background deleter, multi-agent receipt linking, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.23] — 2026-09-22

### Added

- `trust show` (alias: `trust status`) is a read-only status report for the known-keys allowlist and the local keygen key. It prints `active`, `count`, `file` (`.agent-receipt/trusted-keys.txt`), `sources` (the same union as `trust list`), the fingerprints when the store is active, `local` (the 64-hex keygen fingerprint, or `(none — run keygen)` when keys do not load), and `localListed` (`true`, `false`, or `n/a` when there is no local key). Missing keys do not exit 1. An invalid or unreadable store exits 1 with the same reason as `trust list`. `trust show <fingerprint>` exits 1 (show takes no fingerprint). `--json` prints one trust object with `action: "show"` and adds `path`, `localFingerprint` (string or null), and `localListed` (boolean or null). The command does not create keys, does not edit the allowlist, and does not edit config. When a local key loads and is not listed, the report names `trust add --self`. `trust list` stays the fingerprint dump. Not a CA.

### Changed

- Package version bumped to `1.0.23`.
- [`docs/business.md`](docs/business.md) documents `trust show` under the trust / signing recipe. `trust show` is landed. The lead sentence tracks 1.0.23.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) note that `trust show` reports the allowlist and whether the local key is listed. Pin comments that track the current cut are `v1.0.23`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.23. After `keygen` and `trust add --self`, `trust show --json` reports `active: true`, `localListed: true`, and a `localFingerprint` that matches keygen. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.23`. No new action input.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. `trust show` only reads the allowlist and the local public key fingerprint.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config (signing stays opt-in via config `sign: true` or `--sign`), an HTML/share signed package (and a signed one-pager), unsigned HTML prove export (`--html`), a background deleter, multi-agent receipt linking, SSO / IdP, Cloud Agents, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.22] — 2026-09-22

### Added

- Config `sign: true` and CLI `--no-sign`. When `.agent-receipt.yml` sets `sign: true`, `capture`, `wrap`, and `watch` sign after a successful write when a local Ed25519 keypair loads (the same `*.sig.json` sidecar as `sign`). Resolution matches `redact`: `--no-sign` wins, then `--sign`, then config. Bare absence of both flags uses config. Absent or `sign: false` keeps signing opt-in. An invalid non-boolean `sign` value is reported by `validateConfig` / `doctor`. Missing keys print the same tip as today's `capture --sign` / `wrap --sign` and leave the receipt unsigned. That does not exit 2. `init --org` does not set `sign` (keys may be absent). Add `sign: true` after `keygen` and `trust add --self`. `share`, `export`, `prove`, and `verify` do not read this key. The CI composite input `sign: true` stays fail-closed and is independent of config. Not a CA.
- `doctor` adds a `sign` row: INFO when unset or false, PASS when `sign: true` and the local keypair loads, WARN when `sign: true` but keys are missing (names `keygen`). That warning does not fail default `doctor` or `doctor --strict`.

### Changed

- Package version bumped to `1.0.22`.
- [`docs/business.md`](docs/business.md) documents config `sign` under org policy and the signing recipe. Config `sign: true` / `--no-sign` is landed. The lead sentence tracks 1.0.22.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) note that local or org config can set `sign: true` and that CLI `--no-sign` overrides. Pin comments that track the current cut are `v1.0.22`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.22. With `sign: true` in a temp `.agent-receipt.yml` and keys present, bare `wrap` (no `--sign` flag) writes `*.sig.json`; `--no-sign` does not; missing keys plus `sign: true` tip and leave the receipt unsigned. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.22`. No new action input. `examples/org-policy.yml` comments `# sign: true` as an optional line after keygen.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. Config `sign` is an opt-in default, not a certificate authority.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture without config (signing stays opt-in via config `sign: true` or `--sign`), `trust show`, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package (and a signed one-pager), unsigned HTML prove export (`--html`), multi-agent receipt linking, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.21] — 2026-09-22

### Added

- `prove --page` (alias `--one-pager`) writes a plain-English Markdown one-pager after the existing prove report. Exit codes are unchanged, including FAILED (exit 2). Default path: `foo.md` → `foo.prove.md` beside the receipt. A receipt whose name does not end in `.md` gets `<name>.prove.md` (`notes.txt` → `notes.txt.prove.md`). `--out <path>` overrides that destination (an existing directory, or a path ending in `/`, receives `<stem>.prove.md` inside; any other path is the file). The page lists verdict (PROVED or FAILED), path, sha256, verified, trailingIgnored, redacted, risk, tldr, agent, uncommitted, failedOn, audit (present / chain / events / matched), signature (present / ok / trusted / fingerprint / reason), and failOn or reason when set, plus a short tamper-evident footer. It is not itself signed. Human stdout keeps the PROVED/FAILED banner and prints one `page:` line when a file was written. `--json` stays one prove object and adds `pagePath` only when `--page` wrote a file. Without `--page`, prove stays stdout-only. The command does not append the audit log. `last`, `history`, and `prune` ignore `*.prove.md` so the page is not treated as a receipt.

### Changed

- Package version bumped to `1.0.21`.
- [`docs/business.md`](docs/business.md) documents the one-pager under prove. The prove-for-humans one-pager is landed. HTML/share signed package stays deferred. The lead sentence tracks 1.0.21.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`README.md`](README.md) tip `prove --page` after prove. Pin comments that track the current cut are `v1.0.21`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.21. After wrap/sign, smoke runs `prove --json --page` and checks `pagePath`, `PROVED`, and sha256 in `*.prove.md`. Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/github/action.yml`](examples/github/action.yml), [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml), and [`examples/org-policy.yml`](examples/org-policy.yml) pin comments are `v1.0.21`. No new action input.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The one-pager is not a signature and not access control.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, `trust show`, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package (and a signed one-pager), multi-agent receipt linking, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.20] — 2026-09-22

### Added

- `trust add --self` (alias: `trust add self`) loads the local Ed25519 keypair with `loadKeys` (the same pair as `sign` and `keygen`) and appends that fingerprint to `.agent-receipt/trusted-keys.txt` via `addTrustedFingerprint`. Already listed exits 0 with `added: false`. Missing keys exit 1 and name `keygen`. The command does not create a keypair, does not write private keys, and does not edit config `trustedFingerprints`. `--json` keeps the trust report (`action: "add"`) and adds `fingerprint` when the local key resolved. `trust add <64-hex>` is unchanged. This is not a CA.

### Changed

- Package version bumped to `1.0.20`.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) auto-trust, when `require-sig` is true and `trusted-keys` is empty, runs `agent-receipt trust add --self` after temp `keygen` instead of hand-writing the fingerprint file. Fail-closed semantics are unchanged: prove still requires `signature.trusted` true. A non-empty `trusted-keys` value is still installed as given. Pin comments are `v1.0.20`.
- [`examples/github/action.yml`](examples/github/action.yml) pin comments are `v1.0.20`. A comment names `trust add --self`. No new action input.
- Recommended local recipe in [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) and [`docs/business.md`](docs/business.md): `keygen` → `trust add --self` → `wrap --sign --fail-on high --json` → `prove` → `verify --require-sig`. Still not a CA.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) version-range comments include 1.0.20 and smoke `trust add --self` (allowlist activates, prove `signature.trusted` true, `verify --require-sig` exits 0, second call is idempotent). Live [`.github/workflows/*`](.github/workflows) was not edited.
- [`examples/org-policy.yml`](examples/org-policy.yml) pin comment is `v1.0.20`.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package, a prove-for-humans one-pager, multi-agent receipt linking, `trust show`, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.19] — 2026-09-22

### Added

- CI signed gate drop-in (live [`.github/workflows/*`](.github/workflows) was not edited). [`examples/github/action.yml`](examples/github/action.yml) accepts optional `sign` (default false). When true, `wrap` is invoked with `--sign`. `share` still re-signs published Markdown when keys exist; if the gate path has no sidecar, the step runs `sign` on that path. Missing Ed25519 keys fail the step and name `keygen` (CLI `wrap --sign` still only tips and leaves the receipt unsigned). `trusted-keys` is installed before wrap, sign, prove, and verify. After `sign: true` and `require-sig: true`, the step runs `verify --require-sig` on the gate path. When prove is also on and the allowlist lists a fingerprint, prove must report `signature.trusted` true. Recommended combo: `sign: true`, `require-sig: true`, `trusted-keys: "<path-or-comma-fps>"`. Not a CA. No org secret.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) accepts optional `sign` (default false) with the same fail-closed rule. When `require-sig` is true and `trusted-keys` is empty, the job writes the temp `keygen` fingerprint to `.agent-receipt/trusted-keys.txt` and the signed prove requires `signature.trusted` true. A non-empty `trusted-keys` value is installed as given and is not appended.
- [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md) is the signed CI recipe: `keygen` (or restore keys) → trusted-keys allowlist → `wrap --sign --fail-on high --json` → `prove` → `verify --require-sig`. Linked from the README and [`docs/business.md`](docs/business.md).

### Changed

- Package version bumped to `1.0.19`.
- Pin comments in the GitHub examples, [`docs/business.md`](docs/business.md), and [`examples/org-policy.yml`](examples/org-policy.yml) are `v1.0.19`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the 1.0.18 trust-store smoke and adds a `wrap --sign` smoke: a sidecar is written, prove `signature.ok` is true, and with that fingerprint allowlisted prove `signature.trusted` is true and `verify --require-sig` exits 0. Version-range comments include 1.0.19. Live [`.github/workflows/*`](.github/workflows) was not edited.
- `capture --sign` / `wrap --sign` help names the CI fail-closed difference in one line. The CLI flags themselves are unchanged.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, config `sign: true` (and `--no-sign`) so org policy can default capture/wrap to sign, `trust add --self`, SSO / IdP, Cloud Agents, a background deleter, an HTML/share signed package, a prove-for-humans one-pager, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.18] — 2026-09-22

### Added

- Fingerprint trust store / known-keys allowlist. Not a CA. `.agent-receipt/trusted-keys.txt` holds one lowercase 64-hex fingerprint per line (`#` comments and blank lines ignored; trailing whitespace stripped). An invalid line fails closed when the store is loaded for a gate. Config key `trustedFingerprints` (YAML list) unions with the file. Either source alone is enough. Empty or missing both leaves the allowlist inactive: `verify --require-sig` still accepts any cryptographically valid sidecar (1.0.17 behavior). The default path stays under gitignored `.agent-receipt/` so local lists stay private. Teams may commit a copy under `examples/` or `docs/` and copy it in.
- `verify --require-sig` checks the sidecar fingerprint after the hash matches and the signature verifies, when the allowlist is non-empty. A missing fingerprint exits 2 with `fingerprint not trusted` and the fingerprint. `--trusted-key <fp>` (repeatable or comma-separated) unions with the file and config for that invocation only. `verify --json` signature gains additive `trusted` (`true`, `false`, or `null`). Required gate keys are unchanged.
- `prove` uses the same allowlist when a sidecar is present and cryptographically valid. A fingerprint that is not listed sets `signature.ok` false, `signature.trusted` false, and exits 2. The reason mentions the trust store. When the store is inactive, `signature.trusted` is null and prove stays as in 1.0.17 (a missing sidecar still does not fail).
- `doctor` adds a `trust` row: INFO when no store is configured, PASS with the fingerprint count when the store is readable, WARN when the store is present but empty or unreadable or has an invalid line. A missing store does not fail default `doctor` or `doctor --strict`. Invalid lines FAIL under `--strict`.
- `trust list`, `trust add <fp>`, and `trust rm <fp>` edit `trusted-keys.txt` (`--json` prints one object).
- `capture --sign` and `wrap --sign` are opt-in. After a successful write, local keys produce `*.sig.json` (the same sidecar as `sign`). Missing keys print a tip and leave the receipt unsigned. That does not exit 2. The flags are off by default. Share still re-signs published Markdown when keys exist.

### Changed

- Package version bumped to `1.0.18`.
- CI examples (live [`.github/workflows/*`](.github/workflows) was not edited). Pin comments are `v1.0.18`. [`examples/github/action.yml`](examples/github/action.yml) and [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) accept optional `trusted-keys` (a file path or comma-separated fingerprints) installed as `.agent-receipt/trusted-keys.txt` before prove / `verify --require-sig`. Empty leaves the allowlist inactive.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) keeps the 1.0.17 `verify --require-sig` smoke and adds a trust-store smoke: a matching fingerprint exits 0, a non-matching fingerprint exits 2 on verify and prove. Version-range comments include 1.0.18. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. No key escrow. The private key stays under `.agent-receipt/keys/`. The thin known-keys allowlist landed; full PKI/CA is still deferred.
- Still deferred: full PKI/CA, minisign, GPG/OpenPGP, default auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.17] — 2026-09-22

### Added

- `verify --require-sig` (alias `--require-signature`) is opt-in. Default `verify` stays hash-only: unsigned receipts still pass, and a missing or invalid sidecar does not fail. With the flag, the existing Markdown hash check runs first (hash failure still exits 2). After a matching hash, a valid `*.sig.json` beside the receipt is required (`inspectReceiptSignature` / `verifySignature`). A missing sidecar exits 2 with reason `signature required: signature absent`. A present sidecar that is invalid, mismatched, or malformed exits 2 with the signature reason. A valid sidecar for the current sha256 exits 0 unless `--fail-on` also trips. `verify --json --require-sig` adds optional `signature` `{ present, ok, alg, fingerprint, reason }` on the gate. The field is omitted when `--require-sig` was not passed. No config key. `capture`, `wrap`, and `share` do not turn the flag on.
- Share and export Markdown sidecar handoff. `foo.md` → `foo.sig.json`. HTML stays unsigned. When the published Markdown sha256 equals the source and a valid source sidecar exists, that sidecar is copied. When redact (or any rewrite) changes the sha256, the old sidecar is not copied. Local keys (`loadKeys`, the same pair as `sign`) re-sign the published Markdown. Missing keys leave it unsigned, remove any destination sidecar, and print a short `keygen` / `sign` tip. That tip does not exit 2. `share --json` adds optional `sigPath` (string or null). Private keys are never written into a receipt or sidecar.
- CI examples (live [`.github/workflows/*`](.github/workflows) was not edited). [`examples/github/action.yml`](examples/github/action.yml) gains optional `require-sig` (default false). When true, after a green gate it runs `verify --require-sig` on the receipt path. The job must `keygen` and `sign` (or restore keys) first. [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) gains optional `require-sig` (default false) that temp-`keygen`s, `sign`s, and checks `prove` `signature.ok` plus `verify --require-sig`. No org secret. Pin comments are `v1.0.17`.
- `doctor --strict` always fails unset retention (`maxCount` / `maxAgeDays`) on any `outDir`, including a small or empty one. Default `doctor` stays pressure-gated (INFO until 100 receipts or 20 MB, then WARN). A configured limit that would still delete stays a warning. `init --retention` still sets the two limits.

### Changed

- Package version bumped to `1.0.17`.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents optional `signature` and `sigPath`. Required gate keys are unchanged.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) runs `verify --require-sig` on the signed receipt (exit 0) and on an unsigned copy (exit 2) after `keygen` → `sign` → `prove`. `doctor --strict` on the small smoke repo fails unset retention until `init --retention`. Version-range comments include 1.0.17. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This cut does not publish to npm.
- Still not a CA. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, a fingerprint trust store, minisign, GPG/OpenPGP, auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing.

## [1.0.16] — 2026-09-22

### Added

- `keygen [--force] [--json]` writes a local Ed25519 keypair under `.agent-receipt/keys/` using Node `crypto` only (`ed25519.private` PKCS8 PEM mode `0600`, `ed25519.public` SPKI PEM). The key fingerprint is the lowercase hex SHA-256 of the DER SPKI bytes. Existing keys are left unchanged (exit 0). `--force` rotates. No network, no CA, no key escrow. The private key is never printed.
- `sign [path] [--json]` resolves a receipt the same way `verify` does, hash-checks it, and writes `foo.sig.json` beside `foo.md`. The signature is over the UTF-8 bytes of the receipt sha256 hex string (the same hex `verify` uses), not the raw Markdown. The sidecar is `{ alg: "ed25519", version: 1, sha256, fingerprint, signature, publicKey }` with the SPKI PEM embedded so a peer can verify without the local keys directory. Hash failure exits 2 and does not write a sidecar. Missing keys exit 1 and name `keygen`. Capture, wrap, and share do not sign.
- `prove` (and `prove --json`) gains a `signature` object: `{ present, ok, alg, fingerprint, reason }`. A missing sidecar is `present: false`, `ok: null`, and does not change the exit. A valid sidecar that matches the current receipt sha256 is `ok: true`. A present sidecar that is invalid, mismatched, or malformed JSON is `ok: false` and prove exits 2. Human output adds one signature line. `verify` stays hash-only.
- [`docs/signature.schema.json`](docs/signature.schema.json) documents the sidecar. No new npm dependency validates it. Receipt capture omits `.agent-receipt/keys/` and `ed25519.private` / `ed25519.public` paths so a local key is not copied into a receipt.
- `doctor` adds an optional `keys` row: INFO when no keys, PASS with the key fingerprint when the pair is readable, WARN when the pair is incomplete or unreadable. Missing keys do not fail default `doctor` or `doctor --strict`.

### Changed

- Package version bumped to `1.0.16`.
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) smokes `keygen`, `sign`, and `prove --json` (`signature.ok === true`) after wrap. Unsigned prove still expects `signature.present === false`. Version-range comments include 1.0.16. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- This is a thin local Ed25519 attest of the receipt hash. It is not a CA and not PKI. The private key stays under `.agent-receipt/keys/`.
- Still deferred: full PKI/CA, auto-sign on capture, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), npm Trusted Publishing (this cut does not publish), and `doctor --strict` always-fail for unset retention (retention stays pressure-gated at 100 receipts or 20 MB).

## [1.0.15] — 2026-09-22

### Added

- Drop-in CI/PR gate polish in examples only (live `.github/workflows/*` was not edited). [`examples/github/action.yml`](examples/github/action.yml) is a composite action to copy to `.github/actions/agent-receipt/`. Optional `install` (default false) runs `npm install -g` from `from` (default `github:pramodreddyboddu/agent-receipt`, pin `#v1.0.15`). Optional `prove` (default false) runs `prove --json` after a green wrap/share gate and fails the step unless `ok` is true, `verified` is true, and `exitCode` is 0. Step outputs: `ok`, `exit-code`, `sha256`, `path`, `gate-json`. The exit rule is unchanged (`exitCode !== 0` or `ok !== true` fails), including the `trailingIgnored` boolean-when-set check. [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) keeps an explicit `--fail-on`, bumps the install pin comment to `v1.0.15`, adds `workflow_call` input `prove` (boolean, default true), runs `prove --json` after a green gate (share proves the latest receipt), and uploads `receipt-gate.json` plus the receipt Markdown with `actions/upload-artifact@v4` (name `agent-receipt-gate`). A missing receipt file does not fail the job.
- [`docs/gate.schema.json`](docs/gate.schema.json) documents the CI `GateReport` object (`command` `capture|wrap|share|verify`, `ok`, `version`, `exitCode` 0|1|2, `verified`, `failedOn`, `failOn`, `redacted`, `uncommitted`, `path`, `jsonPath`, `htmlPath`, `markdownPath`, `tldr`, `sha256`, `risk`, `ignored`, `trailingIgnored`, `reason`). No new npm dependency validates it.
- `init --retention` merges opt-in retention defaults onto `.agent-receipt.yml`: `maxCount: 100` and `maxAgeDays: 30` (the same numbers as the disk-pressure and org-policy tips). A missing file is written like `init` with those keys set. An existing file rewrites only those two keys (`ignore`, `redact`, `failOn`, `outDir`, and comments stay). Re-running when both are already set exits 0 and does not rewrite them. Prints the config path and whether each key was set or unchanged, then suggests `prune --dry-run`. No network.
- Trusted prune. When `.agent-receipt/audit.jsonl` exists, `prune` runs `verifyAuditChain` before deleting. A broken chain exits 1, deletes nothing, and appends no audit line. Dry-run exits 1 as well: the plan may still list candidates, with `ok: false`, `exitCode: 1`, `reason`, `chainOk: false`, and `auditPresent: true`. A missing audit log is unchanged (absence is fine). `prune --force` skips the trust gate and deletes even when the chain is broken.

### Changed

- Package version bumped to `1.0.15`
- [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) checks that `docs/gate.schema.json` exists and that every required gate key is present on the wrap JSON smoke. Version-range comments include 1.0.15. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- `doctor --strict` retention pressure-gating is unchanged. Unset retention still fails only when `outDir` is under pressure (100 receipts or 20 MB). Always-fail for unset retention stays deferred.
- Still deferred: cryptographic signing / signed receipts (PKI) and any attest or key-management slice (no minisign, GPG, or signing keys in this cut), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.14] — 2026-09-22

### Added

- `init --org` (alias `init --policy`) sets org policy on `.agent-receipt.yml`: `redact: true` and `failOn: high`. A missing config is written in the same shape as `init`, with those two keys enabled. An existing file is merged in place: active `redact` / `failOn` lines are rewritten, a commented key is uncommented when no active key exists, and missing keys are appended. `ignore`, `riskAllowlist`, `outDir`, retention keys, and other comments stay. Re-running when the keys are already set exits 0 and does not rewrite them. The command prints the config path and whether each key was set or unchanged, and suggests `doctor --strict`. No network. Full example remains [`examples/org-policy.yml`](examples/org-policy.yml); `init --org` does not copy that file over a local ignore list.

### Changed

- Package version bumped to `1.0.14`
- `doctor --strict` fails unset org policy (`redact: true` and a valid `failOn`) on every `outDir`, including a small or empty one (exit 1). `doctor --json` reports that policy check as `fail`. Default `doctor` is unchanged: unset policy stays INFO and does not change the exit code. A broken audit chain still fails `--strict` always and stays WARN by default. Unset retention stays pressure-gated (100 receipts or 20 MB). A configured limit that would still delete files stays a warning.
- CI examples: [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) pins the install comment to `github:pramodreddyboddu/agent-receipt` (with a `v1.0.14` tag note) and records that the job passes `--fail-on` so a missing config cannot weaken the gate. After a successful wrap or share it checks `trailingIgnored` is a boolean when that field is set. [`examples/github/action.yml`](examples/github/action.yml) documents `trailingIgnored` (`boolean | null`) and keeps the same `exitCode` / `ok` failure rule. [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml) proves fail-closed policy: `--strict` fails before `init --org` and passes the policy row after. Live [`.github/workflows/*`](.github/workflows) was not edited.

### Notes

- Live workflow files were **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Still deferred: cryptographic signing / signed receipts (PKI), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), npm Trusted Publishing (this cut does not publish), and always-fail unset retention under `doctor --strict` (retention stays pressure-gated). No signing slice in this cut.

## [1.0.13] — 2026-09-22

### Added

- `prove [path]` is a thin prove-this-run report. It resolves the receipt the same way `verify` does, checks the same Markdown hash, and prints path, sha256, verified, trailingIgnored, redacted, risk, TL;DR, agent, uncommitted, and failedOn. The audit link is best-effort and still not a signature: a missing `.agent-receipt/audit.jsonl` is `present: false` with `chainOk: null`; a present log runs `verifyAuditChain` (`chainOk`, event count, reason on break). `matched` is true when any event `path` equals the receipt (repo-relative, the form the log stores). `uncommitted` and `failedOn` prefer the index row, then the companion `.json`. A stored boolean wins. Otherwise `failedOn` is high severity only, the same rule as `history --failed` for older rows. `--json` prints one object (`command: "prove"`). `ok` is true only when `exitCode` is 0. Exit 0 when the hash matches and the log is absent or intact. Exit 2 when verify fails, the chain is broken, or explicit `--fail-on` trips (`failedOn` becomes true even if the hash matches). Exit 1 on a missing receipt or a bad flag. Config `failOn` is not applied.
- `last --json` prints one object (`command: "last"`): `ok`, `version`, `path`, `sha256`, `agent`, `message`, `timestamp`, `failedOn`, `uncommitted`, `tldr`. The index row wins for agent, failedOn, uncommitted, and sha256 when that receipt is listed; otherwise the Markdown glance. No receipt still exits 1. Human `last` is unchanged. `--json` wins over `--path` when both are set.
- CI gate JSON gains `trailingIgnored` (`boolean | null`). `verify --json` sets the boolean (true when content after `## Integrity` was ignored). `wrap` and `share` set it when they verified a body. `capture` and usage errors leave it null.

### Changed

- Package version bumped to `1.0.13`
- `doctor --strict` promotes a broken audit chain from WARN to FAIL (exit 1), including on a small `outDir`. Unset org policy and retention stay pressure-gated. Default `doctor` still warns on a broken chain and does not fail for that row. `doctor --json` reports the audit check as `fail` under `--strict`.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `prove --json` and `last --json` after wrap.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Prove-this-run UX landed in this cut. Still deferred: cryptographic signing / signed receipts (PKI), SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.12] — 2026-09-22

### Added

- `history --failed` and `ls --failed` keep receipts that failed the gate. An index row with `failedOn` uses that boolean: `true` is kept, and a stored `false` stays out even when the risk summary is high. Rows written before 1.0.12 omit `failedOn` and match when `risk.high > 0` or `risk.maxSeverity` is `high`. A scan (no index) matches when the glance has a high-severity risk row. Medium or low alone does not match. Combines with `--agent`, `--uncommitted`, `--limit`, and `--json`. No matches is exit 0 and an empty listing (`[]` with `--json`). An empty receipt store still errors. `--failed` takes no value.
- New captures store `failedOn: true` or `false` on `.agent-receipt/index.json` (the gate result, computed before the index update). The companion receipt `.json`, when written, carries the same boolean. Older index rows without the field stay valid.
- Human history rows that failed the gate show a `[failed]` badge.
- `history` / `ls` `--json` stays a JSON array. Every row includes `failedOn` (the stored bit when the index has it, otherwise the same boolean the filter uses). Scan-path rows also include `uncommitted` (boolean).

### Changed

- Package version bumped to `1.0.12`
- Known `history` / `ls` flags: `--limit`, `--json`, `--agent`, `--uncommitted`, `--failed`, `--cwd`. Unknown flags still exit 1. `--agent` still requires a name.
- Listing filter order: load receipts (index when present, otherwise scan `outDir`), then `--agent` (if set), then `--uncommitted` (if set), then `--failed` (if set), then `--limit` (newest N of the filtered set).
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `history --failed --json` and `history --agent ci --failed --json`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing / prove-this-run signatures, SSO / IdP, Cloud Agents, a background deleter, live workflow sync (no `workflow` OAuth scope), and npm Trusted Publishing (this cut does not publish).

## [1.0.11] — 2026-09-22

### Added

- `history --agent <name>` and `ls --agent <name>` keep receipts whose `agent` field equals that name (exact string, case-sensitive). Receipts with `agent: null` or a missing agent do not match any `--agent` filter. Combines with `--limit` and `--json`. No matches is exit 0 and an empty listing (`[]` with `--json`), not an error. An empty receipt store still errors, as before.
- `history --uncommitted` and `ls --uncommitted` keep receipts where `uncommitted` is true. Combines with `--agent`, `--limit`, and `--json`. Same empty-result exit.
- Listing filter order: load receipts (index when present, otherwise scan `outDir`), then `--agent` (if set), then `--uncommitted` (if set), then `--limit` (newest N of the filtered set). Human listing stays newest first. `--json` is that same slice.

### Changed

- Package version bumped to `1.0.11`
- `history` / `ls` exit 1 on an unknown flag (for example `--failed` or `--agents`) instead of ignoring it. Known flags: `--limit`, `--json`, `--agent`, `--uncommitted`, `--cwd`. `--agent` requires a name.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `history --agent ci --json` and `history --uncommitted --json`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish). `history` does not gain `--failed` in this cut.

## [1.0.10] — 2026-09-22

### Added

- `audit --agent <name>` and `log --agent <name>` keep events whose `agent` field equals that name (exact string, case-sensitive). Events with `agent: null` do not match any `--agent` filter. Combines with `--event`, `--failed`, `--limit`, and `--json` (still a JSON array, oldest first). No matches is exit 0 and an empty listing (`[]` with `--json`), not an error. `--verify` ignores `--agent` and checks the whole chain; a short stderr note says so.
- `audit --failed` and `log --failed` keep events where `failedOn` is true or `exitCode` is not 0. Same combination rules, empty-result exit, and `--verify` behavior as `--agent`.
- Listing filter order: load events, then `--event` (if set), then `--agent` (if set), then `--failed` (if set), then `--limit` (newest N of the filtered set). Human output is newest last. `--json` is that same slice, oldest first.

### Changed

- Package version bumped to `1.0.10`
- `audit` / `log` exit 1 on an unknown flag (for example `--agents`) instead of ignoring it. Known flags: `--limit`, `--json`, `--event`, `--agent`, `--failed`, `--verify`, `--cwd`.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `audit --agent ci --failed`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish). `history` does not gain `--agent` in this cut.

## [1.0.9] — 2026-09-22

### Added

- `doctor --json` prints one object on stdout for CI and scripts: `ok` (true when the exit code is 0), `command` (`doctor`), `version`, `exitCode`, `strict`, and `checks` (`id`, `status`, `detail`). Status labels stay `pass` / `fail` / `warn` / `info`. The rows match the human checklist (Environment, then Prod ready). Exit codes are unchanged: 0 when nothing FAILs, 1 on FAIL or a `--strict` pressure failure. Human output stays the default when `--json` is omitted.
- `audit --event <name>` and `log --event <name>` filter the listing to one event: `capture`, `watch`, `wrap`, `share`, `export`, or `prune`. Works with `--limit` and `--json` (still a JSON array, oldest first). An unknown name exits 1. `--event` is listing-only — `audit --verify` ignores it and checks the whole chain.

### Changed

- Package version bumped to `1.0.9`
- [`examples/org-policy.yml`](examples/org-policy.yml) comments point at `doctor --strict` and `doctor --json`. `maxCount` / `maxAgeDays` stay commented; retention remains opt-in.
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) smokes `doctor --json` and `audit --event wrap`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, a background deleter, live workflow sync, and npm Trusted Publishing (this cut does not publish).

## [1.0.8] — 2026-09-22

### Added

- `prune` / `retain` append one `.agent-receipt/audit.jsonl` line per receipt actually deleted. Same fields as wrap/share/capture (`path`, `sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`, `prev`). No diff body and no `--message`. The sibling `.json` is not a second event. `--dry-run` and a run that deletes nothing do not append. `audit --verify` checks the same hash chain.
- `doctor --strict` exits 1 when org policy (`redact` + `failOn`) and/or retention is unset **and** `outDir` is under pressure (100 receipts or 20 MB). Below that threshold those rows stay INFO/WARN. Default `doctor` is unchanged: WARN/INFO do not fail the process. CI `--fail-on` is still the risk gate — `--strict` does not scan diffs.
- `prune --json` rows carry the same identity fields as an audit line (`sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`) plus `reasons` and `bytes`. The report adds `command`, `version`, `exitCode`, and `audited` (lines appended; 0 on dry-run). `audit --verify --json` includes `command` and `version`.
- Redaction and risk hints for Groq `gsk_` keys and xAI `xai-` keys (long alphanumeric form; hyphenated model names are left alone).

### Changed

- Package version bumped to `1.0.8`

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The checkout token has no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, and a background deleter. `doctor --strict` does not fail merely because a configured limit would still delete files — that stays a warning until you run `prune`.

## [1.0.7] — 2026-09-22

### Added

- Audit log coverage for `capture`, `watch`, and `export` / `html`. Same line shape as wrap/share (`path`, `sha256`, `agent`, `redacted`, `verified`, `failedOn`, `exitCode`, `prev`). No diff body and no `--message`. `wrap` still records one `wrap` line (not a second capture). `share` still records one `share` line (not a second export). `watch` records one `watch` line per capture. `audit --verify` checks the same hash chain.
- `prune` / `retain` — opt-in deletion of old receipts under `outDir`. Config keys `maxCount` and `maxAgeDays` (integers ≥ 1). Nothing is deleted until a limit is set. `--dry-run` prints the plan and does not rewrite `index.json`. Apply deletes the markdown and its sibling `.json`, then refreshes the index (temp file + rename) and drops rows whose files are already gone. Refuses a repo-root or outside-repo `outDir`, symlinks, and a broken `index.json` (no deletes). Does not touch `audit.jsonl`.
- `doctor` **retention** row: INFO when opt-in is off, WARN on disk pressure (100 receipts or 20 MB with no limit, or a limit that would delete files), FAIL on invalid keys or an unsafe `outDir`. WARN stays non-fatal.
- Redaction and risk hints for OpenAI `sk-` / `sk-proj-`, Anthropic `sk-ant-`, Hugging Face `hf_`, and `Authorization: Bearer` tokens.

### Changed

- Package version bumped to `1.0.7`
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) also runs `prune --dry-run --json` and checks that retention stays off.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. `gh auth status` scopes were `gist`, `read:org`, and `repo` — no `workflow` scope. Install the mirror after `gh auth refresh -h github.com -s workflow`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO / IdP, Cloud Agents, and a background deleter. `prune` does not append audit events.

## [1.0.6] — 2026-09-21

### Added

- `audit` / `log` — append-only `.agent-receipt/audit.jsonl` for `wrap` and `share` (path, sha256, agent, redacted, verified, exit code; no diff body and no `--message`). `prev` is the SHA-256 of the previous line. `audit --verify` exits 0 when the chain matches and 2 when a line was edited. Experimental tamper-evidence, not a signature.
- `doctor` prod checklist rows **policy** (redact + failOn, optional) and **audit** (chain OK / missing / broken). WARN/INFO stay non-fatal.
- Cloud-token redaction and risk hints: GitHub `gho_` / `ghu_` / `ghs_` / `ghr_` (with `ghp_`), GitLab `glpat-`, npm, Google `AIza` / `ya29.`, AWS `ASIA`, Stripe, SendGrid, Slack `xoxc` / `xoxe` / `xapp` / webhook URLs, Azure `AccountKey` / `SharedAccessKey`, and `sig=` query params.
- [`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) — pull-request and reusable workflow for `--fail-on` + `--json`. [`examples/github/action.yml`](examples/github/action.yml) — composite action.
- Enterprise section in [`docs/business.md`](docs/business.md): SSO-free rollout, org policy, CI gate, share defaults, audit, retention for `.agent-receipt/`.

### Fixed

- SessionEnd / `scripts/grok-wrap.sh`: prefer `node` for a multi-chunk drain; skip `timeout` when it rejects the wait value (BusyBox fractional seconds). After the drain, stdin is redirected from `/dev/null` so a host blocked on a full write gets `EPIPE` instead of stalling wrap.

### Changed

- Package version bumped to `1.0.6`
- Docs CI mirror ([`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)) runs a temp-repo `wrap --json` and `share --json` smoke plus `audit --verify`.

### Notes

- Live [`.github/workflows/ci.yml`](.github/workflows/ci.yml) was **not** updated. The `gh` token scopes were `gist`, `read:org`, and `repo` — no `workflow` scope — and GitHub rejects workflow-file pushes without it. Install the mirror after `gh auth refresh -h github.com -s workflow` (fine-grained PAT: Actions Read and write). See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Deferred: cryptographic signing, SSO, Cloud Agents, automatic receipt deletion, and audit events for capture / watch / export.

## [1.0.5] — 2026-09-21

### Added

- `share` — one shot: verify the source, apply `--redact` (default on; 1.0.3 share-safety), write HTML and optional Markdown (`--md`), verify the published body, print paths + TL;DR. Refuses to overwrite the source and does not re-hash a tampered receipt.
- CI gate JSON on stdout for `capture --json`, `wrap --json`, `share --json`, and `verify --json` (human progress on stderr). Companion receipt `.json` is unchanged. `watch --json` stays companion-file + human stdout.
- Stable `--fail-on` exits: 0 pass, 2 policy and/or verify failure, 1 usage error (invalid threshold). Config `failOn` / `redact` (see `examples/org-policy.yml`) apply to capture / wrap / watch / share. Plain `verify` ignores config `failOn` unless `--fail-on` is passed.
- `doctor` **Prod ready** checklist: hooks, redact default (optional), config, git clean, Cursor init, Grok init. WARN/INFO stay non-fatal.
- [`docs/business.md`](docs/business.md) — team rollout: install, hooks, CI gate, share-safety, SessionEnd stdin contract, what not to put in receipts.
- SessionEnd / `scripts/grok-wrap.sh` stdin drain: at most one read of `HOOK_STDIN_MAX` bytes, capped by `HOOK_STDIN_WAIT_SEC` (`timeout`, else `node`). An open pipe with no EOF cannot hang the hook. Payload is discarded.

### Changed

- Package version bumped to `1.0.5`
- `capture --json` / `wrap --json` stdout is the gate object (logs moved to stderr). Scripts that scraped “Wrote receipt” from stdout of `--json` should read stderr or the gate fields.

## [1.0.4] — 2026-09-21

### Added

- `init --grok` — writes `.grok/rules/agent-receipt.md` (Grok Build loads it every session) and a SessionEnd hook (`.grok/hooks/agent-receipt.json` + `agent-receipt-wrap.sh`) that runs `wrap --agent grok --redact --uncommitted` **only when the working tree is dirty** (non-blocking; needs `grok --trust` / `/hooks-trust`)
- [`docs/grok-cli.md`](docs/grok-cli.md) — post-session recipe for the Grok Build CLI
- `scripts/grok-wrap.sh` and npm script `wrap:grok` — `wrap --agent grok --redact` (does not force `--uncommitted`; a dirty tree is captured automatically)
- Example copies under `examples/.grok/`

### Changed

- Package version bumped to `1.0.4`
- Promote CI to `.github/workflows/ci.yml` (docs mirror retained under `docs/github-actions-ci.yml`)
- Add OIDC Trusted Publishing release workflow (`.github/workflows/release.yml`) — no long-lived `NPM_TOKEN`
- Document Trusted Publisher + GitHub Environment setup in `docs/RELEASE.md`
- Harden `npm run pack:check` against npm 11 `./bin/...` publish footgun (bin already canonical on 1.0.2)

## [1.0.3] — 2026-09-13

### Fixed

- **`--redact`**: mask credential URLs (`DATABASE_URL`, `postgres://user:pass@…`,
  Redis/Mongo URIs, `password=` query params) — passwords no longer leak while
  API/AWS keys were masked
- **`--redact`**: omit nested prior-receipt / `.agent-receipt` index diff bodies so
  truncated secrets from earlier receipts cannot re-embed
- **Risk**: skip high-entropy false positives on `.agent-receipt/` artifact paths
  and pure hex digests (sha1/sha256 footers)
- **History / index**: captures with `--out` outside configured `outDir` are no
  longer prepended as newest in `.agent-receipt/index.json`

### Changed

- Package version bumped to `1.0.3`
- Document that trailing appends after `## Integrity` are ignored by `verify`
  (canonical-body design); `verify` prints a brief note when such content exists


## 1.0.2

- Republish after 1.0.1 version was reserved/yanked on npm (installs 404'd; same version cannot be restaged).
- Keep scoped name `@pramodreddyboddu/agent-receipt`.

## [1.0.1] — 2026-09-11

### Changed

- Renamed npm package to scoped `@pramodreddyboddu/agent-receipt` (unscoped `agent-receipt` is taken on npm)
- Package version bumped to `1.0.1`
- CLI binary name remains `agent-receipt` (UX unchanged)
- README / `docs/RELEASE.md` install and publish commands updated for the scoped name

## [1.0.0] — 2026-09-11

First **stable** public-ready release. Same feature surface as 0.6.0; version and
packaging polish for npm strangers.

### Highlights (0.1 → 0.6 → 1.0)

- **Core**: `init`, `capture`, `show`, `verify` with SHA-256 tamper-evident receipts
- **Session UX**: TL;DR + “What to review”, `last`, `history` / `ls`, `compare` / `diff`
- **Automation**: `install-hooks`, `watch` (commits + dirty tree), Cursor rule via `init --cursor`
- **Risk**: high-signal diff/path heuristics, `--fail-on`, `riskAllowlist`, high-entropy scan
- **v0.6**: `wrap` (end-of-session one-shot), `export` / `html`, `--base`, `--redact`
- **Ops**: `doctor`, config `ignore` globs, JSON schema, GitHub install path

### Changed

- Package version bumped to `1.0.0`
- npm metadata: punchier description, expanded keywords, `publishConfig.access=public`
- README aimed at npm / GitHub installers; `wrap` as the hero command
- `SECURITY.md` added (reporting + heuristic scanner limits)
- `docs/RELEASE.md` updated for v1.0.0 tag / publish commands
- `npm run pack:check` asserts `npm pack --dry-run` includes `bin` + `dist`

## [0.6.0] — 2026-09-11

### Added

- `wrap` — one-shot end-of-session: capture (with `--uncommitted` if dirty) →
  print TL;DR + path → verify (`--agent`, `--message`, `--fail-on`, `--base`,
  `--redact`)
- `export` / `html` — write a self-contained HTML receipt (or export last) for
  open/share; `--out`, `--redact`, `--format html|markdown`
- `capture --base <ref>` — summarize changes vs a base branch (e.g. `main`);
  range label shows **commits ahead** + file stats
- `--redact` on capture / wrap / export — mask high/secret findings in
  Markdown/HTML for safer sharing (re-hashed so verify still passes)
- README docs for wrap / export / base / redact

### Changed

- Package version bumped to `0.6.0`

## [0.5.1] — 2026-09-11

### Added

- Text `history` / `ls` shows a yellow **`[uncommitted]`** badge on dirty-tree
  receipts (same `uncommitted` field already present in `history --json` / index)

### Changed

- Text history prefers `.agent-receipt/index.json` (like `--json`) so the badge
  and risk counts stay consistent with the index
- Package version bumped to `0.5.1`

## [0.5.0] — 2026-09-11

### Added

- `watch` dirty-tree detection — auto-capture staged/unstaged/untracked changes
  (labeled **uncommitted**); `--commits-only` restores v0.4 HEAD-only behavior
- `capture --uncommitted` — snapshot the dirty working tree explicitly
- Config `riskAllowlist` — suppress findings by rule id and/or path glob
  (`code`, `code:pathGlob`, `*:pathGlob`); documented in README
- Light **high-entropy** token scan on added diff lines (`high-entropy-secret`)
  to reduce secret false negatives without pulling gitleaks
- `history --json` — machine-readable receipt list
- Stable receipt index at `.agent-receipt/index.json` (updated on every capture)

### Changed

- Default `watch` now monitors commits **and** dirty tree
- Package version bumped to `0.5.0`

## [0.4.0] — 2026-09-11

### Added

- `history` / `ls` — list recent receipts (time, agent, risk counts, short summary)
- `watch` — poll git HEAD and auto-capture on new commits
  - default interval 5s; `--interval <sec>`; `--once` waits for the next commit then exits
  - captures `--since` the previous HEAD so the whole interval is in the receipt
  - documented as the Cursor / agent “run after session” path
- `init --cursor` — drops `.cursor/rules/agent-receipt.mdc` (`alwaysApply: true`)
  that instructs the agent to **run** capture (not only remind)
- `capture --fail-on [high|medium|low]` — write the receipt, then exit 2 if max
  severity meets the threshold (bare `--fail-on` = high). For CI scripts.
- Smarter risk engine:
  - high-signal **diff content**: AWS access key ids, AWS secret assignments,
    private key PEM/blocks, GitHub tokens, Slack tokens
  - dedicated `env-file` for committed `.env` / `.env.local` / `.env.production`
  - severity ranking (high → low) on the receipt and in `--fail-on`
- Receipt polish: one-screen **TL;DR** at top + **What to review** checklist
- JSON `summary.tldr` and `summary.review`

### Changed

- Risk false-positive trim: `src/auth/*.ts` is no longer a medium “auth-path”;
  only secret-store filenames (`tokens.json`, `htpasswd`, …) flag
- `.env.example` / `.env.sample` / `.env.template` are low `env-template`, not high
- `id_rsa.pub` is not treated as an SSH private key; common image/font binaries
  are low instead of medium
- README leads with “why this exists” + a 60-second best path
- Cursor example rule is `alwaysApply: true` and requires the agent to run capture
- Package version bumped to `0.4.0`

## [0.3.1] — 2026-09-11

### Fixed

- `install-hooks` embeds `node` + absolute path to this package's bin so local/global
  installs work without npm publish (`npx` is last resort only)
- Hook runtime prefers `AGENT_RECEIPT_BIN` → embedded bin → `npx`

### Changed

- Documented `AGENT_RECEIPT_BIN` and default hook resolution in README + `examples/hooks.md`

## [0.3.0] — 2026-09-11

### Added

- `doctor` — environment health check (Node ≥ 20, git, repo, config, hooks, outDir)
- `compare` / `diff` — show what changed between two receipts (default: last vs previous)
- Config `ignore` globs — exclude noise paths from risk / summary / file tables
  (defaults: `node_modules/**`, `dist/**`, `coverage/**`; lockfile options documented)
- `agent-receipt help <cmd>` — man-page style per-command help
- `docs/receipt.schema.json` — JSON Schema for `capture --json` companion files
- `docs/RELEASE.md` — public + npm publish checklist (manual; agents do not publish)
- Capture flags: `--diff-stat` / `--no-diff-stat`, `--top-risks <N>`
- `install-hooks --uninstall` compat alias

### Changed

- README leads with a 30-second GitHub install → init → hooks → last/verify path
- Default `.agent-receipt.yml` from `init` includes `ignore` list
- Package version bumped to `0.3.0`

## [0.2.0] — 2026-09-11

### Added

- `last` command — path + glance of the newest receipt (`--path` for scripting)
- `install-hooks` / `uninstall-hooks` — opt-in post-commit (and optional `--pre-push`) auto-capture
- Agent integration docs: Cursor, Claude Code, Aider (`docs/agents.md`, `examples/`)
- Receipt **Summary** rollup, **Notable changes**, **Diff stat**, **Risk findings** table
- Richer risk signals: auth paths, package.json / manifests, large/broad diffs, `.netrc`
- JSON receipts include a `summary` object (counts + notable)
- Clearer CLI help / success / error messages (optional ANSI color)

### Changed

- Package version bumped to `0.2.0`
- npm publish readiness: `files` allowlist includes `docs/`, `types`/`exports` refined, `prepublishOnly` runs tests

## [0.1.0] — 2026-09-11

### Added

- Initial release of `agent-receipt` CLI
- Commands: `init`, `capture`, `show`, `verify`
- Capture flags: `--since`, `--commits`, `--message`, `--agent`, `--session`, `--out`, `--full`, `--json`, `--cwd`
- Risk hints for secret-looking paths, binaries, lockfile/CI deletions
- SHA-256 tamper-evident integrity footer
- TypeScript ESM build, `node:test` suite, GitHub Actions CI (shipped under `docs/`)
- Example receipt under `examples/`
