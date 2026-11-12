# Naming rules (given to the name generator)

These rules correct what language models get wrong when they invent brand names. Most rules below are
also checked in code after generation (marked [code]); the rest rely on the model following them.

## What makes a name worth checking
1. **Distinctive beats descriptive.** Invented words (Kodak, Zalando) and arbitrary real words (Apple for
   computers) make strong trade marks. A name that describes the product (DogWalkApp, FastPay) is weak: offices
   refuse it or it cannot stop copycats. Suggestive names (Airbnb, Netflix) sit in between and are fine.
2. **Not built on the product's category word.** For a dog-walking app, avoid dog/paw/walk/leash/woof roots
   in more than a few candidates: every competitor already used them, so they collide with existing marks.
   [code: no more than a quarter of the candidates may share the same 3-letter-plus root.]
3. **No suffix clichés.** -ly, -ify, -io, -oo, -sy, -zy, -hub, -go, -ster, and a dropped vowel (Flickr) were
   overused in 2010-2020 and are crowded in software classes. [code: at most a quarter of the candidates
   may end in -ly, -ify, -io, -oo, -sy, -zy, -hub, -go or -ster.]
4. **Easy to say and spell after hearing it once**, in English and French at least: 2-3 syllables, no
   ambiguous spellings (ph/f, c/k/q, double letters that are not heard), no letter clusters a French or
   Spanish speaker cannot pronounce.
5. **4 to 10 letters, letters only.** No digits, hyphens or camel-case gimmicks. [code]
6. **Not a near-copy of a famous brand.** No one-letter changes of well-known names (Gooogle, Amazoon).
7. **No bad meanings** in English, French, German or Spanish, including slang and how it sounds aloud.
   (This is checked again separately.)
8. **Variety.** Mix the styles: invented words, fused real words or roots, a real word used out of context,
   a word from Latin/Greek or another language. Never 30 variations of one idea.

## Why this matters for the result
A name only survives if it is distinctive, so rule 1 and the trade mark check pull in the same direction: generic
or cliché names come back amber or red, and a run with few greens looks broken even when the checks are right.
