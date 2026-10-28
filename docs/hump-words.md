# Hump-word list

`src/lib/hump-words.ts` is the dictionary a camelCase hump must hit after a truncated key. Every hump has to be a dictionary word or a documented identifier variant. A code word is not a variant and is not added on its own.

## Source and licence

The lemmas are ENABLE1, the Enhanced North American Benchmark Lexicon compiled by Alan Beale. M. Cooper released the ENABLE master list (`WORD.LST`) into the public domain: anyone may use or distribute it, with no fee and no registration. This cut checked every shipped lemma against that list (172,823 words, the enable1 file). The list is not the hermitdave FrequencyWords 2018 English 50,000 (repository code under MIT, word content under CC-BY-SA-4.0) and not first20hours/google-10000-english (the Google Web Trillion Word Corpus via Peter Norvig, not cleared for commercial redistribution). Those lists are not shipped, and there is no NOTICE file for them. SCOWL is not a source. Shipping this public-domain list inside the package's MIT licence is Pramod's sign-off at merge.

## How the cutoff was chosen

Rank is document frequency in a code and documentation walk: a lemma counts once per file. The walk reads `.md`, `.txt`, `.rst`, `.js`, `.cjs`, `.mjs`, `.ts`, and `.py`, skips symlinks and files larger than 30MB, and stops at directory depth 14. Tokens are letter runs split into camelCase humps, lowercased, length 2 to 16, and kept only when the hump is an ENABLE1 lemma. The ordered table from that walk has 10,603 lemmas.

K is that whole table: every ENABLE1 lemma the walk observed at least once, in frequency order, highest first. That is the support of the frequency distribution, about 10k words. It is not a rank picked by scoring the rq74b, held-out, or test3 corpora. A second cutoff that drops hapaxes (document frequency at least 2, 7,611 words, 98.9% of the mass) was measured and does not meet the over-mask bar: it masks 798 of 3000 on rq74b, 641 of 1876 on the held-out set, and 717 of 3000 on test3. Those three files were not used to add or remove lemmas. The shipped list is the observed table.

## Supplement

The in-repo 1500-name regression vocabulary names 8 further ENABLE1 lemmas that the walk did not observe:

`cohort`, `experiment`, `inventory`, `refund`, `rollout`, `supplier`, `tax`, `warehouse`.

They are the last 8 words in the list, alphabetical. They are included so that guard still builds names from dictionary words. The mask bound stays 135. They were not taken from the over-mask corpora. Tokens that are not ENABLE1 lemmas (`cfg`, `ctx`, `init`, `params`, and the other hand-listed code words) are not in the list.

## Stemming

A hump that is not itself an entry still counts when a light stem of it is an entry and the stem is at least 3 letters. The rules, applied independently when the suffix matches, are:

- `ies` → drop `ies`, add `y`
- `es` → drop `es`
- `s` → drop `s`
- `ed` → drop `ed`, and also drop the final `d`
- `ing` → drop `ing`, and also drop `ing` and add `e`
- `er` → drop `er`, and also drop the final `r`
- `ers` → drop `ers`
- `ly` → drop `ly`
- `ion` → drop `ion`, and also drop `ion` and add `e`

The word itself is not a stem. No other suffix is removed.
