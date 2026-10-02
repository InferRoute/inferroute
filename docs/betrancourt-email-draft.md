# Bétrancourt — delivery note + the offer

**STATUS: DRAFT FOR HENRY. Not sent. Henry approves and sends. IP/legal clearance for external
distribution is open, and the client he needs is built but not released.**

Rewritten 22 Sep (third version). v1 was a cold ask — wrong, he has already agreed to both. v2 delivered
the portfolio only. This one delivers AND makes the offer, because Henry's objective is that his firm
becomes the first client, and the delivery is what earns the right to ask.

**Claims cleared with the recall-R&D session, 22 Sep. Three things are deliberately absent:**
- **"SOTA" / "state of the art"** — they will not stand behind it: the bar has not been located on any
  comparable benchmark, and claiming to target a bar we cannot define is what a careful attorney distrusts.
- **The lever percentages (+57%, +23%)** — reachability@1000 lifts, not delivered recall@100. A reader
  hears "returns 57% more", which is false.
- **Anything about agentic confirmation** — a live-model run on 22 Sep captured **0%** of the oracle
  ceiling (recall 0.08, recovered 1 of 12). It is an unrealised ceiling, not a result.

**The levers are still withheld — the letter just no longer ANNOUNCES it** (Henry, 23 Sep: don't say
"ils sont en cours d'examen de brevetabilité"). Announcing an omission draws attention to it, and to a
patent attorney "we are patenting this" is either obvious or slightly odd coming from a supplier. The
mechanisms remain undescribed, which was the IP requirement; nothing now points at the gap.

**The metric is not named at all** (Henry rejected "rappel", then "exhaustivité", 23 Sep). No French noun
works: "rappel" reads as "reminder" to a practitioner, "exhaustivité" claims a completeness we do not have,
and the English "recall" is jargon in a French letter. So the sentence describes the CAPABILITY instead —
"retrouver les antériorités pertinentes" — which is what he cares about anyway. A metric only needs a name
when you are comparing numbers; here there is one number and it is defined in the same breath.

The definition survives the simplification in plain words: "de celles que citent les examinateurs
américains, mesuré sur des dossiers tenus à l'écart de sa mise au point" carries both held-out and
non-circular, which the recall session required the figure never to appear without.

**TA-L3 is no longer named** (Henry, 23 Sep). Section 3 gives the reason for sealed delivery as "vos dépôts
et l'ensemble non déposé", which is sufficient and carries no identifier.

**More positive on exhaustivité, WITHOUT a new claim.** The number and its definition are unchanged; what
changed is where the emphasis falls — "le point important est ailleurs : les leviers qui le font monter
sont déjà mesurés, pas espérés". Measured-not-hoped is true and is the strongest honest thing available.
No figure was added, no ceiling implied, no ranking promised: inventing optimism here would undo the
calibration the whole email is built on.

**"Very high recall scores" was NOT written** (Henry, 23 Sep, asked for it). Our tests do not estimate it.
The ~0.55 is THEIR published result, reached by a technique we have not implemented; we have never measured
it ourselves, so "nos tests estiment" would be false about the tests. What IS true and says the same thing
more credibly: "la prochaine version vise le meilleur résultat publié sur ce jeu" — a named target on a
named benchmark he can look up, rather than an adjective. If Henry wants the stronger sentence, the honest
route is the one the recall session offered: implement passage-level retrieval, re-measure, and the claim
becomes a fact.

**"agent", not "assistant"** (Henry, 23 Sep), and the sentence now flows from the benchmark instead of
jumping: the next version targets the published best, AND it is what will feed the search tool the agent
uses. The architecture detail lands as a consequence rather than a non sequitur.

**"MCP" is still not written, and this time for a factual reason** rather than a stylistic one. Henry says
he knows what an MCP is — he does — but in THIS client `prior_art_search` is a Pi extension tool
registered in `ir-attested.ts`; the only occurrence of "mcp" anywhere in the package is a comment in
probant_trust.py. Writing "le MCP" to a technical reader who may later look would be wrong. "L'outil de
recherche que l'agent utilise" is true either way. If there is an MCP serving this elsewhere — sealed-
research's side — I do not have it, and Henry can tell me.

**Cut to three lines** (Henry, 23 Sep) from ninety words. What had to survive, and did: the benchmark
NAMED with its arXiv reference (a bar he can check is the whole point — the line arguing that is gone
because the reference makes it), the explicit non-comparability with the 19%, and the honest standing.
"Nous y sommes au niveau des meilleures méthodes publiées au niveau document" is the cleared phrasing —
not "égalons", not "dépassons", though we do edge them.

**DAPFAM is named; no DAPFAM number is written** (cleared 23 Sep, after they pulled the paper's tables
rather than answering from memory). The facts: paper BM25 doc-level 0.330, paper dense reference ~0.396,
paper BEST passage-level ~0.55; ours e5 dense 0.380, RRF hybrid 0.413. So we edge their document-level
baselines and sit well below their passage-level best. **We are not beating the record**, and the letter
does not say we are — it says the passage-level best is the target we work toward, which is true and
checkable. Henry's "chasing the records" survives as effort against a NAMED public bar rather than as an
achievement.

The two hard rules that shaped the wording: a DAPFAM figure must never sit beside the ~0.19 or be equated
with it (a closed 45k pool is structurally ~2x easier than the open 17.5M corpus — merging them is the
worst overclaim available here), and since we do not lead the benchmark, nothing may imply we do. Hence
the explicit "les chiffres n'y sont pas comparables à celui ci-dessus" and no number at all.

The only number in writing is **~0.19 with its definition**. Mechanisms are withheld pending IP review —
the same gate being applied to our own seven mechanisms currently in diode-runs.

---

Objet : le travail préparatoire sur le portefeuille

Cher Maître,

Un mot d'abord : ce travail et cette lettre ont été préparés par un LLM, depuis mon ordinateur ; je les ai
relus.

**1. Le travail préparatoire**

Voici deux documents pour rendre le corpus plus lisible.

**La liste des objets** : les neuf dépôts et l'ensemble non déposé ramenés à **huit inventions**, au sens où
vous les instruiriez — le mécanisme, les caractéristiques qui pèseraient dans une revendication, ce qui
n'est pas couvert, et les entrées du registre recouvertes. Les 36 entrées sont toutes rattachées, aucune
n'est restée de côté.

**Le guide de lecture** : pour chaque dépôt, où se trouve la matière de chaque invention — en pourcentage
du document et en position exacte, de sorte qu'une recherche sur les mots cités tombe sur le passage.

Un point que je ne vous aurais pas signalé si la machine ne l'avait pas rendu visible : **chaque dépôt
porte une invention et une seule**, à une vingtaine de passages près sur tout le portefeuille. Ces
passages-là sont ceux où la matière d'une invention se trouve dispersée dans le dépôt d'une autre ; ils
sont cités intégralement et localisés, parce que c'est ce qu'il faut savoir au moment de décider comment
regrouper les nouvelles demandes. C'est aussi, je crois, un élément de réponse à la question de
regroupement que vous m'aviez posée.

Chaque affirmation est rattachée à une citation littérale, vérifiée caractère par caractère contre le
document qui la porte ; une citation introuvable est supprimée avec l'affirmation qu'elle portait. Le
regroupement en huit objets, lui, est un jugement : vérifié quant à sa couverture du registre, jamais quant
à sa justesse. C'est exactement là que votre lecture est irremplaçable.

**2. L'outil**

Ces documents sortent de l'outil que nous construisons. Deux propriétés sont vraies aujourd'hui.

La recherche s'exécute dans une **enceinte matérielle scellée** : l'invention non déposée ne quitte jamais
votre poste en clair — la difficulté même d'une recherche d'antériorité avant dépôt. Et chaque recherche
produit un **certificat** : ce qui a été cherché, sur quel corpus, à quelle date d'antériorité, scellé, et
re-vérifiable par un tiers sans avoir à nous faire confiance. Si votre diligence vous est opposée dans cinq
ans, c'est cette pièce-là qui répond.

La troisième — retrouver les antériorités pertinentes — est celle que nous construisons. Le moteur en
retrouve aujourd'hui environ 19 % de celles que citent les examinateurs américains, mesuré sur des dossiers
tenus à l'écart de sa mise au point. C'est peu. Mais les leviers qui font monter ce chiffre sont déjà
mesurés, pas espérés, et leur intégration est l'affaire de quelques semaines.

Nous nous mesurons aussi sur DAPFAM (arXiv:2506.22141), un jeu d'évaluation public — chiffres non
comparables à celui ci-dessus, le corpus y est fermé. La prochaine version vise le meilleur résultat publié sur ce
jeu ; c'est elle qui alimentera l'outil de recherche que l'agent utilise dans le client.

Ce que nous voulons construire : un outil qui vous fasse gagner du temps sur ce que vous faites
aujourd'hui — c'est ce que vise la prochaine version, qui arrive — adossé à une preuve aussi solide et
aussi nette qu'une preuve peut l'être : une attestation matérielle qui remonte aux clés du fabricant, des
énoncés signés, revérifiables par un tiers sans avoir à nous croire.

**Une question** : est-ce qu'une telle pièce a une valeur juridique ? Je
l'imagine utile là où votre diligence peut être mise en cause longtemps après — une opposition, un
contentieux, une due diligence où l'on vous demande ce qui avait été cherché et à quelle date, ou un client
qui revient sur le périmètre d'une recherche facturée deux ans plus tôt.

Le client comporte un bouton qui prépare un dossier d'audit : la preuve, débarrassée de tout ce qui touche à l'invention, le vérificateur,
et la marche à suivre pour qu'un tiers — votre propre IA, par exemple — en contrôle la solidité et refasse
les vérifications lui-même.

**3. En pratique**

Vous avez déjà les dépôts. Ces deux documents-ci citent aussi l'ensemble non déposé, je ne les mets donc
pas en pièce jointe.
Ils vous parviendront chiffrés à votre seule clé, avec les huit objets, dans un même envoi scellé que vous
ouvrez sur votre poste : les objets deviennent vos propres dossiers, les documents se placent à côté, et
vous pouvez créer les vôtres à partir de là sans qu'ils se mélangent aux miens.

Il me faut pour cela votre **clé publique**. Quatre commandes dans un terminal, et la dernière l'affiche :

```
curl -LO https://inferroute.ai/client/inferroute-0.9.91-py3-none-any.whl
python3 -m venv ~/probant
~/probant/bin/pip install "./inferroute-0.9.91-py3-none-any.whl[confidential]"
~/probant/bin/ir probant identity
```

Un lien plutôt qu'une pièce jointe : les passerelles de messagerie rejettent volontiers ce type de fichier,
et un lien peut être retiré, ce qu'une pièce jointe dans une boîte aux lettres ne peut plus être. L'adresse
n'est publiée nulle part et ne mène qu'à ce fichier.

Vous me renvoyez ce qu'affiche la dernière de ces quatre commandes. Cette clé ne contient que des clés publiques : elle ne permet rien
d'autre que de vous adresser l'envoi. Nous vérifierons l'empreinte de vive voix avant que quoi que ce soit
ne parte. (Sous Windows les chemins diffèrent — dites-le-moi et je vous envoie l'équivalent.)

Le programme est du Python en clair sur votre disque : il se lit entièrement, sans avoir à nous croire.
Si vous souhaitez le faire examiner, deux commandes produisent le dossier à remettre tel quel à votre
propre IA — l'empreinte de chaque fichier, et les questions à poser au code :

```
# la copie installée, celle qui s'exécute chez vous
~/probant/bin/ir probant audit-client

# le fichier publié, tel qu'il est distribué (la même adresse que ci-dessus)
~/probant/bin/ir probant audit-client --url https://inferroute.ai/client/inferroute-0.9.91-py3-none-any.whl
```

Les deux ensemble disent quelque chose qu'aucune ne dit seule : que ce qui tourne chez vous est bien ce
qui a été publié. Les questions sont de nous ; les conclusions seront de lui, pas de nous.

Un point à consigner dès maintenant, parce qu'il ne vaut que s'il est noté avant d'en avoir besoin. Les
certificats produits par l'outil sont vérifiés contre une référence que nous signons, et cette référence ne
vaut que si la clé qui la signe est bien la nôtre. Voici son empreinte :

```
748e4c8e4ca334c5f804ffcdbd85f2dca29713e71c1c7c9c0737e3b898e2e204
```

Gardez-la avec ce courrier. Un tiers qui contrôlera un certificat plus tard vous demandera cette valeur-là,
et la prendre à ce moment sur notre site ou sur votre poste ne prouverait rien : c'est d'en avoir la trace
antérieure, chez vous, qui fait la différence. Trois vérificateurs indépendants nous l'ont signalé le même
jour — c'est le seul point sur lequel ils butent tous, et il ne se règle pas entièrement de notre côté.

Nous avons toutefois fait ce qui en dépendait. La référence elle-même est désormais horodatée par
OpenTimestamps : des serveurs indépendants, puis un bloc Bitcoin, attestent la date à laquelle ce fichier
exact existait. C'est la seule date du dossier qui ne vienne pas de nous. Elle ne dit rien du contenu de la
référence — seulement qu'il n'a pas pu être écrit après coup pour s'accorder à un certificat.

Le client vous dira, en haut de sa page d'accueil, que la recherche d'antériorité n'y est pas encore
installée : c'est exact, et c'est voulu à ce stade. Rien ne quitte votre poste tant qu'elle ne l'est pas.
Vous pouvez dès maintenant y travailler vos descriptions ; le même client vous servira pour l'essai, que je
vous proposerai quand la prochaine version du moteur sera déployée — avec un chiffre à jour et une date.

**Votre question sur l'IA.** Vous me demandiez si j'avais une contre-indication à ce que vous utilisiez
l'IA de votre côté. Plutôt qu'un avis sur Claude Team ou ChatGPT Business, je préfère vous proposer
l'assistant du client : il tourne dans une enceinte matérielle que votre poste vérifie avant le moindre
envoi, vos échanges lui sont chiffrés — à une machine que votre poste a vérifiée, jamais à une autre — et
son usage vous est offert — les frais sont pour moi.
Les textes denses dont vous parlez sont précisément ce pour quoi il est fait : l'envoi scellé arrive
directement sous forme de dossiers dans le client, et vous les travaillez avec l'assistant sans que rien
n'en reparte en clair. Il vous faudra une clé pour l'activer ; je vous la donnerai de vive voix, en même
temps que nous vérifierons l'empreinte.

Une précision, parce qu'elle décide de la comparaison : l'enceinte *lit* vos textes pour vous répondre.
Ce qu'elle apporte n'est pas qu'aucune machine ne les voie, c'est qu'aucune machine non vérifiée ne le
puisse, et que votre poste ait fait la vérification lui-même, avant d'envoyer.

Une seconde précision, du même ordre : une session n'est pas liée à une seule enceinte. Si la machine qui
la sert cesse de répondre ou échoue à un contrôle, votre poste en vérifie une autre et la session
continue là — vos textes sont alors chiffrés à la clé de cette nouvelle machine et renvoyés, de sorte que
plus d'une enceinte les aura déchiffrés. Chacune est vérifiée par votre poste *avant* le moindre envoi,
jamais après, et le reçu les nomme toutes, avec les preuves. Ce que cela coûte, c'est la phrase plus
simple « une seule machine les a vus » ; ce que cela achète, c'est qu'une machine qui tombe n'interrompt
pas votre travail et n'envoie rien vers une machine non vérifiée.

Ce qu'elle garantit et ce qu'elle ne garantit pas est écrit dans le client, à l'écran, y compris ce que
nous ne pouvons pas prouver. Si après l'avoir lu vous préférez votre serveur hébergé en France pour
l'ensemble non déposé, cela ne me pose aucune difficulté.

Vous me demandiez aussi un ordre de préférence entre les regroupements. Je vous le donnerai de vive voix :
la liste des objets change la question, et je préfère vous entendre dessus avant de la trancher. Dites-moi
un créneau qui vous convient cette semaine ou la suivante — je suis confus d'avoir laissé passer celui que
vous m'aviez proposé.

Bien à vous,
Henry Decléty
InferRoute SASU

---

## Notes for Henry, not part of the email

- **⚠ HE ASKED YOU TWO QUESTIONS ON 2026-09-04 AND HAS BEEN WAITING SINCE 09-07** (thread
  19ff13148e34a92a, then 1a07b3d9f7852fff). This letter should not go out as if that exchange did not
  happen:
  1. **Grouping preference** — he suggested concentrating on ONE grouping first and asked your order of
     preference. **The eight objects ARE an answer to that question**, which is why the finding is now
     framed as feeding the re-drafting rather than as "where scope is contested". Consider answering it
     explicitly, with an order, rather than leaving him to infer one from the list.
  2. **Whether you object to Santarelli using AI** — they hold Claude Team and ChatGPT Business licences
     plus a French private server for the most sensitive matters, and he asked directly. Still unanswered.
     Note the happy accident: this letter now OPENS by disclosing that a LLM prepared it, which answers him
     by example before he has to ask twice. Worth one explicit line either way.
- **The "périmètre" framing was wrong and Henry caught it** (23 Sep). It assumed the nine provisionals
  would be prosecuted as they stand. They will not: counsel's 2026-09-04 read is that they are not
  "régulières" for INPI (English, formalism) and a rewrite for a new filing is needed. Overlap between
  filings that are being re-drafted is not a scope question — it is an input to how the NEW applications
  get carved. Same finding, correct use.
- **The opening no longer quotes him back to himself** (Henry, 23 Sep). "Vous m'aviez dit que les dépôts
  étaient trop longs" attributed a statement to the reader in the first line of a letter — which invites
  him to correct the paraphrase instead of reading on, and can land as a reproach when the filings are his.
  "Voici deux documents pour rendre le corpus plus lisible" says what the documents are FOR and lets the
  work justify itself.
- **Why one email and not two.** The delivery is what earns the right to make the offer. Sending the
  pre-work and then a separate pitch would waste the credibility the pre-work buys.
- **The closing hedge was cut** (Henry, 23 Sep): "sur la recherche elle-même, je ne prétends pas encore
  être devant" and the "aucune solution existante" comparison. Checked what that costs before agreeing it
  is safe: the honesty is still carried THREE times earlier — "C'est peu." on the figure, "le meilleur
  résultat publié … est la cible sur laquelle nous travaillons" on DAPFAM, and "les chiffres n'y sont pas
  comparables" on the two quantities — and the two differentiating properties are already stated as their
  own paragraph ("Deux propriétés sont vraies aujourd'hui"). Nothing is claimed here that is not
  established above, and the fourth admission was the one that had started to sound like pleading.
- **"Plus efficace que tout" was NOT written, and it is the one place I softened Henry's instruction**
  (23 Sep: useful because more efficient than anything by the next version, with a proof as solid and clean
  as it gets). The PROOF half is written as asked and is defensible: hardware attestation chaining to the
  manufacturer's keys, signed statements, third-party re-verifiable is about as strong as evidence gets
  here. The "more efficient than anything" half would contradict the DAPFAM paragraph TWO LINES ABOVE,
  where the letter says the published passage-level best is the target we work toward — and a reader who
  catches that is the reader we most need to keep. So the ambition is "vous fasse gagner du temps sur ce
  que vous faites aujourd'hui", which is the useful claim, and superiority stays where it is true: nothing
  else searches without the invention leaving in the clear, nothing else leaves a proof of that nature.
  Say the word and I will write it flat — it would just be the one sentence a careful reader could falsify.
- **The ambition and the no-ranking refusal sit on DIFFERENT AXES, deliberately** (Henry, 23 Sep: don't
  say "I'm not selling you a finished product"; say we want to build something useful and better than what
  exists). Claiming to beat others on RECALL would be the SOTA overclaim the R&D session vetoed. Claiming
  it on confidentiality and provability is not a claim about degree at all — nothing else does the search
  without the invention leaving in the clear, and nothing else leaves a third-party-verifiable certificate.
  "Ce ne sont pas des degrés sur la même échelle" is the sentence that keeps both true in one paragraph.
- **The honest-weakness paragraph is the commercial move, not a concession.** He is a professional who will
  re-measure us. A firm told 19% that sees 19% trusts the next number; a firm that inferred more and sees
  19% does not take the second meeting. Naming it before the test converts a weak number into evidence that
  we report accurately — which is the actual product claim.
- **"Je ne vous promets pas un rang" is deliberate.** Refusing to claim a ranking is more persuasive to
  counsel than claiming one, and it is what the R&D session will stand behind.
- **What is NOT in here, and why:** no lever percentages (they are reachability@1000, a reader hears
  delivered recall), no mechanism names (IP gate), nothing about agentic confirmation (a live run captured
  0% of its oracle ceiling on 22 Sep), no "SOTA".
- **TA-L3 is named.** Still your ruling — EPO has no grace period, he is the counsel who would advise, and
  asking him is circular. Delete the clause if you would rather raise it by voice.
- **The paragraph explaining WHY the trial waits was cut (Henry, 23 Sep).** It said the same thing twice —
  once apologetically in the offer, once factually in section 3 — and repeating the weak number at the
  moment of the ask dwells on it. The deferral now appears ONCE, as a fact with a timescale attached, where
  a reader looks for what happens next.
- **The search trial is HELD for Build 2, at Henry's call (22 Sep), and he was right for a reason beyond
  timing: the search enclave does not currently exist — `ir-sealed-search.eastus2.azurecontainer.io` no
  longer resolves — so a session could not be scheduled today even if he said yes. Asking a professional to
  put a client's unfiled invention through a one-fifth-recall engine is asking him to carry the cost of a
  version we know is incomplete, and it spends the first impression on the weakest thing we have.
- **But the distribution-shift question is NOT held**, and that is the split that matters. We do not need
  him to RUN anything to learn what a real unfiled disclosure looks like as an input — a description does
  it. If we wait for Build 2 to ask, Build 2 gets built blind to the one thing the recall session calls its
  principal unknown. So the trial waits; the requirements question goes now, at zero cost to him.
- **"je les ai relus", full stop** (Henry, 23 Sep, cut "et je les assume"; he had already cut "j'en
  réponds" before it). Both were saying out loud what signing a letter says by itself. A man who rereads
  something and then sends it under his own name has assumed it — announcing the assumption is the part
  that sounded like a man expecting to be doubted.
- **(earlier: "je les assume", not "j'en réponds")** (Henry queried it, 23 Sep). "Répondre de quelque chose" is
  correct and is legal register, but as the letter's FIRST sentence it protests slightly — it answers an
  accusation nobody has made yet. "Je les assume" states the same responsibility flatly and gets out of the
  way, which is what an opening line should do.
- **"un LLM, depuis mon ordinateur"** (Henry, 23 Sep), not "l'agent que nous construisons" — more concrete,
  and it stops the letter-writer being conflated with the product being sold. One word changed from his
  wording: "DEPUIS mon ordinateur", not "SUR". The agent runs on his machine; the model does not. To a
  reader, "un LLM sur mon ordinateur" states local inference, which is false for this letter (a hosted
  model) and false for the portfolio work (a sealed enclave). In a letter whose whole argument is that the
  invention never leaves the machine in the clear, a careless claim about where computation happens is the
  one inaccuracy that would cost most if he noticed it. Say "sur" instead if you prefer — but it would not
  be true.
- **The agent disclosure is FIRST and one sentence** (Henry, 23 Sep; I had put it last and he moved it).
  At the top it has to be short, flat and unapologetic or it becomes a disclaimer the reader weighs
  everything against — so it states the fact and stops, and the letter that follows is the evidence. "Je les ai relus" keeps the responsibility yours: an agent drafted it, a professional stands
  behind it, and he is told which is which before he reads a word of it.
- **He already HAS the filings** (Henry, 23 Sep; sent 2026-09-04, he read them within hours). So the
  sealed envelope is not protecting the filings from him, and saying so would have been transparently
  hollow. The reason stands on what he does NOT have: these two documents also quote the unfiled set. The
  sentence now says that — "Vous avez déjà les dépôts. Ces deux documents-ci citent aussi l'ensemble non
  déposé" — which is true, is a reason he can check, and incidentally shows we remember what we sent him.
- **"nos dépôts", not "vos"** (Henry, 23 Sep — the filings are his, Bétrancourt is counsel on them).
  Checked every second-person form in the body rather than only that one: 24 others, all correct — "votre
  diligence", "votre lecture", "au sens où vous les instruiriez", "votre poste", "vos propres dossiers"
  (the matters he opens), "votre clé publique", "votre propre IA". Only the one was misattributed, and it
  was in the sentence explaining why the delivery is sealed — the place where getting whose material it is
  wrong would read worst.
- **No "si vous préférez me croire ou vérifier"** (Henry, 23 Sep). The opener presumed a doubt he has not
  expressed, and putting trust on the table is what makes a reader weigh it. The button is now stated as a
  plain feature; that it can be used to check us is evident from what it does, and needs no framing.
- **He is pointed at the audit button** (Henry, 23 Sep), which answers the question by demonstration
  rather than by assertion — and is the only honest way to ask a sceptic to assess evidence. Three things
  make it worth the four lines: the pack is evidence-ONLY, so nothing about a client's invention travels
  with it; it ships the verifier and the instructions, so he is not taking our word for the checking
  either; and "votre propre IA" lands directly on his own open question of 2026-09-04, where he asked
  whether Henry objects to Santarelli using Claude Team and ChatGPT Business. The letter now invites him to
  point that exact tooling at our evidence.
- **Note for when he does it:** the audit brief tells the auditor to treat the shipped verifier as
  untrusted and to compare it against the published package. That comparison now has something to compare
  against — 0.9.38 is served at the link above, and its sha256 is beside it — but note the limit the brief
  itself states: the published copy is InferRoute's too, and it is published from the same machine the
  records are made on. It answers "was this minted here?" only for someone who can rule that out, which
  today nobody can. The value he records from THIS letter at first use is the copy that carries weight;
  that is why the publication key fingerprint is in the letter rather than only on the page.
- **The question asks about LEGAL VALIDITY, not about value** (Henry, 23 Sep). "Est-ce que le certificat
  vaut ce que je crois qu'il vaut ?" asked him to rate our self-assessment — vague, and it invites a polite
  answer. "Est-ce qu'une telle pièce a une valeur juridique ?" is a question inside his competence that has
  a real answer, possibly no. It is also the only question whose answer we cannot get anywhere else: we can
  measure retrieval ourselves, we cannot determine admissibility ourselves. The closing "c'est mon
  hypothèse, pas votre expérience" went with it — having asked a precise question, inviting him to correct
  the premise weakens it.
- **One question, and it SUGGESTS the contexts rather than asking for them** (Henry, 23 Sep). An open
  "in what context?" makes a busy practitioner do the work of answering; naming three plausible ones and
  inviting correction costs him a yes, a no, or a better answer. It also shows we have thought about his
  practice rather than asking him to explain it.
- **It validates the LEAD claim.** If the one professional we have is lukewarm about the certificate, that
  is worth knowing before more is built on top of it.
- **The distribution-shift question was cut at Henry's instruction.** Consequence, stated once and not
  argued: unless it is obtained another way — a call, or the trial at Build 2 — the next engine version
  gets built without the one input the recall session calls its principal unknown. Worth raising by voice
  when he replies.
- **The link in this letter is now the same one an audit pack names.** It was a per-recipient token path;
  a pack's `client_wheel_url` points at the generic one, so Bétrancourt and anyone he hands the record to
  are sent to the same file by the same URL. `robots.txt` keeps `/client/` out of search indexes either
  way. The token path still serves 0.9.18 and is left alone rather than broken.
- **Blocked on:** IP clearance only. The install blocker is gone — 0.9.38 is live at the link and installs
  with the two commands above, verified by fetching it back and comparing hashes on 24 Sep. The email's
  "dès que la version est prête" can therefore be dropped or kept; keeping it commits you to nothing, and
  dropping it removes a hedge that no longer describes the state.
