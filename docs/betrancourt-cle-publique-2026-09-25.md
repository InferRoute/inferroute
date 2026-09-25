# Bétrancourt — demande de clé publique (envoi du 25 sept.)

**STATUT : PROJET. Henry relit et envoie.** Volontairement étroit : il ne décrit ni l'offre, ni les
documents, ni aucun mécanisme — il ne demande qu'une clé et donne les commandes pour la produire. Rien
ici ne touche à l'ensemble non déposé, donc rien ici n'attend la revue PI. Le client complet part en
début de semaine prochaine.

Objet : **Votre clé publique, avant l'envoi**

---

Maître,

Un mot d'abord, comme la dernière fois : cette lettre a été préparée par un LLM, depuis mon ordinateur ;
je l'ai relue.

J'ai rencontré un ingénieur de l'INPI au sujet de la brevetabilité de concepts figurant dans les dépôts
provisoires. Ces matières — l'informatique, et l'IA en particulier — peuvent être délicates ; il me
semble néanmoins que les nôtres se situent plutôt du bon côté, et l'ingénieur partageait le sentiment
qu'il fallait tenter. Cela ne change rien à ce dont nous étions convenus, puisque ces dépôts ne seront
pas valables et qu'il faut les reprendre : je vous confirme ma volonté d'y aller.

L'outil de recherche d'antériorité dont nous avions parlé devrait être prêt en début de semaine
prochaine. Si vous souhaitez y jeter un œil, j'aimerais beaucoup vous le mettre entre les mains. Il
viendrait avec le travail préparatoire, qui porte notamment l'ordre de préférence des regroupements que
vous m'aviez demandé. L'envoi est chiffré à votre seule clé et s'ouvre sur votre poste : il porte de
l'ensemble non déposé, et ne peut donc pas partir en pièce jointe ordinaire.

Comme nous en étions convenus l'un et l'autre, je vous propose de signer un accord de confidentialité
avant cet envoi. Dites-moi si vous préférez le vôtre, ou si je vous en adresse un.

Il m'aura demandé plus de temps que prévu : obtenir des résultats performants d'une part, pouvoir
prouver comment ils ont été obtenus d'autre part, ont chacun demandé beaucoup de travail.

Deux choses seront donc vraies. L'invention non déposée ne quitte pas votre poste en clair : la
recherche s'exécute dans une enceinte matérielle scellée, et rien sur le trajet ne peut la lire. Et
chaque recherche laisse une pièce qui atteste ce qui a été cherché, quand, sur quel corpus et avec
quelle borne d'antériorité — revérifiable par un tiers des années plus tard, sans passer par nous.
Cette pièce n'atteste pas que les résultats soient bons : cela restera votre jugement, et c'est une
première version, avec ses angles morts. Je préfère vous le dire avant que vous les trouviez.

Si vous êtes partant, il me faudrait une chose d'ici là : votre **clé publique**. Sans elle je ne peux
rien vous adresser à vous seul.

Vous n'avez rien à installer. Un fichier d'une centaine de lignes fait cela et rien d'autre :

**https://inferroute.ai/client/cle-probant.py**

Ouvrez-le d'abord dans votre navigateur : il s'y affiche comme du texte et se lit en entier avant qu'on
décide de l'exécuter. Un lien plutôt qu'une pièce jointe, que les passerelles de messagerie rejettent
volontiers. Puis, depuis le dossier où vous l'avez enregistré :

```
python3 -m venv /tmp/cle && /tmp/cle/bin/pip install 'cryptography>=50' && /tmp/cle/bin/python cle-probant.py
```

Un dossier jetable dans `/tmp`, la seule bibliothèque nécessaire (ML-KEM-768 n'est pas dans Python par
défaut), puis le script. Le détour par `/tmp` évite le Python du système, qui refuse ce genre
d'installation sur macOS et Linux récents ; effacez-le aussitôt après, votre clé est ailleurs. Si
`cryptography` est déjà chez vous, `python3 cle-probant.py` suffit.

Il crée deux clés dans votre dossier personnel et affiche la partie publique — il n'ouvre aucun réseau,
vérifiable à la lecture. **Vous me renvoyez par courriel ce qu'il affiche entre les deux lignes de
tirets, tel quel** : ce bloc ne contient que des clés publiques, les parties secrètes restent chez vous.
Relancé, il ne recrée rien et vous réaffiche la même clé. Elle attendra l'outil à la bonne place.

## Une valeur à conserver dès maintenant

Les certificats que l'outil produira se vérifient contre une référence que nous signons, et cette
référence ne vaut que si la clé qui la signe est bien la nôtre. Voici son empreinte :

```
748e4c8e4ca334c5f804ffcdbd85f2dca29713e71c1c7c9c0737e3b898e2e204
```

Gardez-la avec ce courrier. Un tiers qui contrôlera un certificat vous demandera cette valeur ; la
prendre alors sur notre site ne prouverait rien, puisque le site est le nôtre. C'est d'en avoir la trace
antérieure, chez vous, qui fait la différence — et cela ne se règle que par un courrier comme celui-ci.

Bien à vous,
Henry Declety

## Notes pour Henry — ne pas envoyer

- **⚠ Erreur de ma part, corrigée : j'avais écrit « pardon de ce silence depuis le 7 septembre ».**
  J'avais déduit le silence de l'absence de courriels après le 7, sans voir qu'un appel avait eu lieu.
  Une boîte aux lettres ne montre pas les appels, et l'absence de trace n'est pas l'absence de contact.
  Retiré. **Trois phrases de la lettre dépendent encore de ce qui s'est dit à cet appel** — voir
  ci-dessous.
- **Vos deux réponses intégrées.** L'ordre de préférence des regroupements n'a pas encore été donné et
  passera par l'envoi : la lettre l'annonce donc comme contenu de l'envoi, sans dater sa question (la
  dater ferait croire que vous avez oublié l'appel). L'accord de confidentialité n'est pas réglé : la
  proposition reste, appuyée sur « ce dont nous étions convenus l'un et l'autre », ce qui est exact —
  27 août de votre part, 31 août de la sienne, jamais conclu depuis.
- **⚠ « les rendre vérifiables » corrigé en « rendre la recherche elle-même vérifiable »** (votre
  question : les résultats, la confidentialité, ou les deux ?). Le « les » renvoyait aux résultats, et
  disait donc qu'un tiers peut vérifier **que les résultats sont bons**. Il ne le peut pas, et rien dans
  l'attestation ne le permettra jamais. Ce qu'un tiers peut vérifier, c'est **la recherche** : qu'elle
  s'est exécutée dans une enceinte scellée authentique (donc la confidentialité), et que l'énoncé signé
  — requête, résultat, date, corpus, borne d'antériorité — n'a pas bougé depuis (donc l'intégrité du
  compte rendu). Les deux, donc, mais jamais la qualité de ce qui est trouvé. La phrase suivante
  détaille exactement ces deux-là, et elle est juste.
- **« performants » plutôt que « compétitifs »** : compétitif appelle un contre qui, et c'est
  exactement la comparaison que la revue du 22 sept. interdisait de faire (pas de « état de l'art », pas
  de barre qu'on ne sait pas situer). Performant qualifie sans comparer — devant un lecteur qui
  demandera un jour « par rapport à quoi ? », c'est la version qui tient.
- **Une tension à connaître, à vous d'arbitrer** : la phrase affirme des résultats performants et, deux
  phrases plus loin, la lettre annonce « une première version, avec ses angles morts ». Les deux peuvent
  coexister — performant n'est pas parfait — mais c'est vous qui savez si le premier mot est mérité.
  S'il devait être défendu un jour, il le serait sur le chiffre que cette lettre ne donne pas.
- **Rien ne lui est dû sur ses deux questions du 4 septembre** (confirmé par vous). L'usage de l'IA de
  son côté trouve sa réponse dans l'envoi lui-même — lui remettre l'outil, c'est répondre à la question
  qu'il posait ; les éléments à garder secrets ont déjà été traités. Le paragraphe qui promettait d'y
  revenir est donc sorti, et ne doit pas être remis.
- **Option non prise, à un mot près.** La lettre pourrait relier explicitement l'outil à sa question :
  il demandait s'il pouvait passer vos textes à son IA, et la réponse est un outil qui le fait sans que
  la matière quitte son poste. Ce serait la phrase la plus vendeuse de la lettre, parce qu'elle répond
  à un besoin qu'il a formulé lui-même plutôt qu'à un besoin supposé. Je ne l'ai pas ajoutée : vous
  avez dit que la réponse était implicite, et l'expliciter peut sonner comme un argumentaire. Dites
  « ajoute » si vous la voulez.
- **Ce que je ne peux pas retrouver** : l'appel lui-même. Pas de scope Calendar sur les jetons
  (annuaire, gmail.send, gmail.readonly), et en ajouter un suppose un consentement au navigateur. La
  boîte ne garde aucune trace côté Santarelli après le 7 septembre — cohérent avec un appel
  téléphonique. Si vous lui avez déjà donné l'ordre de préférence, ou déjà signé un accord, dites-le et
  je coupe la phrase correspondante.
- **Le rendez-vous INPI est daté par un courriel** : confirmation de Philippe Benoist (INPI) le
  14 septembre pour une consultation de 30 minutes avec un ingénieur brevets **le 15/09 à 10h40**. Je ne
  l'ai pas mis dans la lettre — dites-moi si vous préférez « le 15 septembre » plutôt que le récit sans
  date, c'est vérifiable de son côté et cela ancre le propos.

- **Version à coller : `betrancourt-cle-publique-2026-09-25.txt`.** Ce fichier-ci est en Markdown ; les
  `**gras**`, les `##` et les blocs de code ne s'affichent pas dans un client de messagerie, ils s'y
  voient. Le `.txt` est engendré depuis ce document (pas réécrit à la main, donc pas de divergence
  possible), sans la section présente, avec les commandes indentées de quatre espaces. La ligne de
  commande y tient sur une seule ligne : si votre client la coupe, il faut la recoller avant envoi —
  un `&&` cassé en deux donne une erreur chez lui et pas chez vous.
- **Chaîne vérifiée une dernière fois, telle qu'il la vivra** : lien public → `curl` → la ligne exacte
  de la lettre → carte de clé imprimée, sur une machine PEP 668, dans un HOME vierge. La copie publiée
  et la copie locale du script ont le même sha256.
- **« une centaine de lignes »** et non « quatre-vingt-dix » : le script en fait 99 depuis l'ajout du
  message d'erreur. Un chiffre faux et vérifiable, devant ce lecteur-là, ne coûte rien à corriger et
  cher à laisser.

- **Pourquoi celui-ci peut partir aujourd'hui et la lettre complète non.** Le blocage était la revue PI,
  et il portait sur ce que la lettre *décrit* (l'offre, les documents qui citent l'ensemble non déposé,
  le chiffre et sa définition). Ce courrier ne décrit rien de tout cela. Il ne contient aucun mécanisme,
  aucun chiffre de performance, aucune référence aux documents. La revue PI ne s'y applique pas.
- **« provisoires », pas « provisionnels ».** Vous avez dicté « provisionels » ; en français
  « provisionnel » se rapporte à une provision (le tiers provisionnel de l'impôt), et le terme du droit
  des brevets est **provisoire** — demande provisoire, dépôt provisoire. Devant un conseil en propriété
  industrielle, le mot juste se remarque et le mot faux aussi. Corrigé ; dites-moi si vous visiez autre
  chose que les dépôts dont il a déjà connaissance.
- **⚠ L'INPI et la règle du 23 sept. — à vérifier par vous.** Vous aviez tranché : ne pas écrire « ils
  sont en cours d'examen de brevetabilité », parce qu'annoncer une omission la désigne. Ce passage-ci
  est compatible **à une condition**, et elle est respectée : il raconte un rendez-vous et ce que vous
  en avez appris, et il **ne relie jamais cela à ce que la lettre ne dit pas**. Aucune phrase du type
  « c'est pourquoi je ne détaille pas ». Si le lien apparaît dans la version complète de la semaine
  prochaine, la règle saute.
- **Ce qu'il dit exactement, et ce qu'il ne dit pas.** « C'est gris », « rien qui ferme la porte, rien
  qui l'ouvre franchement non plus » : l'ingénieur n'a ni validé ni écarté, et la lettre ne lui fait pas
  dire autre chose. Ne pas glisser vers « l'INPI a confirmé » — un avocat en brevets lirait la
  surenchère immédiatement, et c'est précisément le lecteur qui sait à quoi ressemble un avis gris.
- **DEUX accords distincts dans cette lettre, à ne pas confondre.** Le refaire-les-dépôts est **acquis**
  — vous en étiez convenus — et la lettre le traite comme tel : elle confirme votre volonté, elle ne la
  sollicite pas. L'essai de l'outil n'est **pas** acquis (intérêt implicite, léger), et la lettre s'y
  tient à une offre avec porte de sortie. Si les deux registres se mélangeaient, le plus faible
  emprunterait au plus fort et la demande deviendrait présomptueuse.
- **La demande d'avis a disparu.** « Si vous avez un avis là-dessus, je le prendrai volontiers » avait
  du sens tant que le sujet restait le vôtre ; dès lors que la reprise des dépôts est un dossier que
  vous lui confiez, demander un avis gratuit sur ce même dossier sonne faux. Remplacé par « je suis à
  votre disposition pour en reparler quand vous le voudrez », qui laisse l'initiative chez lui.
- **Qui dit quoi, dans ce paragraphe — c'est le point à relire.** Trois affirmations, trois sources
  différentes, et la phrase les garde séparées à dessein :
  « ces matières **peuvent** être délicates » = général, et non un verdict sur les vôtres (c'était
  « sont délicates », corrigé) ;
  « **il me semble** que les nôtres se situent plutôt du bon côté » = **votre** appréciation, donnée
  comme telle, pas celle de l'INPI ;
  « **l'ingénieur partageait le sentiment qu'il fallait tenter** » = ce que lui a dit, et rien de plus.
  Si ces trois-là se fondaient en une seule voix, la lettre ferait dire à l'INPI que vos concepts sont
  brevetables — ce qu'il n'a pas dit, et ce que votre lecteur vérifierait.
- **« L'échange m'a été utile… » retiré** : la phrase disait ce que vous aviez retiré de l'entretien,
  et non ce qu'il en ressortait pour lui. Devant quelqu'un dont c'est le métier, dire qu'on a appris
  des nuances invite à se demander lesquelles — et la lettre ne les donne pas. Le paragraphe va plus
  vite sans elle.
- Le verdict de l'entretien n'est toujours pas caractérisé, et pas davantage par un synonyme
  (« mitigé », « sans réponse tranchée » diraient la même chose autrement).
- **Ce que l'INPI a changé, et ce qu'il n'a pas changé** : il n'est pas à l'origine de la décision de
  reprendre les dépôts — elle est antérieure et tient à leur validité. La lettre ne lui fait porter que
  ce qu'il porte : un entretien utile, des nuances acquises.
- **Rien ne dit plus qu'il a accepté, parce qu'il n'a rien accepté** (votre précision : intérêt
  implicite, léger, aucun engagement). Les versions successives disaient « vous m'aviez dit votre
  intérêt », puis « vous aviez bien voulu vous dire prêt », puis « j'avais cru comprendre que vous
  seriez curieux » — toutes attribuaient à un tiers réel une position qu'il n'a pas prise. Il ne reste
  qu'une offre : « si vous souhaitez y jeter un œil, j'aimerais beaucoup vous le mettre entre les
  mains. » La porte de sortie explicite (« si le moment est mal choisi… ») a été retirée ensuite : le
  « si vous souhaitez » porte déjà l'absence d'obligation, et proposer un refus revient à en suggérer
  un — on n'ouvre pas la porte à quelqu'un qui n'a pas dit qu'il voulait sortir.
- **La demande est devenue conditionnelle** : « Si vous êtes partant, il me faudrait… ». Elle ne
  s'adresse plus qu'à quelqu'un qui a dit oui, au lieu de présumer qu'il l'a dit. Et « je vous
  l'adresserai » est passé au conditionnel pour la même raison.
- **L'entrée aussi, sur le même registre.** « Vous m'aviez dit votre intérêt » énonçait son accord comme
  un fait acquis, et « ce qui me vaut de vous écrire » s'en prévalait. Devenu « vous aviez bien voulu
  vous dire prêt » (c'était une amabilité, pas un engagement), « je me permets de vous écrire sur cette
  base », et surtout « en espérant que cet intérêt tienne toujours » — qui lui laisse la porte de
  sortie. Un accord dont on se prévaut se retire mal ; un accord qu'on lui laisse reconfirmer tient.
  La date est passée de « sera prêt » à « devrait être prêt » : un logiciel glisse, et promettre moins
  coûte moins cher que d'expliquer un retard.
- **Ton : trois corrections d'orgueil.** « Pour un cabinet, c'est la partie qui compte » disait à un
  avocat ce qui compte dans son métier — devenu « j'ai supposé que… ; vous me direz si je me suis
  trompé ». « Cela couvre ce que vous m'aviez demandé » affirmait un résultat non constaté — devenu
  « j'espère que cela couvrira ». Et « la difficulté même » revendiquait d'avoir résolu le problème
  central ; il ne reste que la description de la difficulté.
- **Un aveu ajouté, et je crois qu'il gagne plus qu'il ne coûte** : « c'est une première version, elle
  aura ses angles morts, et je préfère vous le dire avant que vous les trouviez. » Il les trouvera. Le
  dire d'avance transforme chaque défaut qu'il rencontrera en confirmation de votre franchise plutôt
  qu'en démenti de vos promesses — et c'est vrai, ce qui est la seule raison valable de l'écrire.
- **« l'essayer » n'avait pas d'antécédent** (votre remarque). C'était la deuxième phrase de la lettre,
  et l'outil n'était nommé qu'au paragraphe suivant : le lecteur voyait un pronom avant la chose. Il est
  nommé maintenant — « l'outil de recherche d'antériorité dont nous avions parlé » — et tous les « il »
  et « l' » qui suivent s'y rattachent. Nommer la capacité ne touche pas à la limite PI : c'est la
  formulation déjà retenue le 22 sept., et elle ne décrit aucun mécanisme.
- **L'entrée s'appuie sur son accord, et remercie avant de demander.** « Vous m'aviez dit votre intérêt
  à l'essayer. C'est ce qui me permet de vous écrire aujourd'hui » : la demande découle de ce qu'il a
  déjà accordé au lieu de tomber sans raison. Les remerciements sont placés devant l'effort demandé,
  pas après — après, ils se lisent comme une formule. Deux ouvertures « Un mot » et deux « début de
  semaine prochaine » se télescopaient dans la version précédente ; il n'en reste qu'une de chaque.
- **« un outil pour le traiter », et non « l'outil qui l'a produit »** (votre correction). La nuance
  n'est pas de style : l'outil n'a pas fabriqué le travail préparatoire, il sert à le travailler. Le
  présenter comme la source de ce qu'il reçoit serait faux, et le placerait du mauvais côté — un
  générateur à vérifier plutôt qu'un instrument entre ses mains.
- **Le rappel produit : ce qu'il dit et ce qu'il ne dit pas.** Il reste au niveau des PROPRIÉTÉS (la
  recherche sans exposition, la pièce revérifiable), jamais des mécanismes — c'est exactement la limite
  posée le 22 sept. Pas de chiffre, pas de « état de l'art », pas de pourcentages de leviers, rien sur la
  confirmation agentique, et surtout aucune mention de ce qui est omis : annoncer une omission la
  désigne. Les deux propriétés citées sont celles de la lettre d'origine, reprises telles quelles.
- **Un blanc à combler, si vous voulez** : « ce que vous m'aviez demandé » reste volontairement vague,
  parce que je ne sais pas de quoi il s'agissait. Si c'était la question de regroupement, nommez-la —
  une phrase qui montre que vous vous en souvenez vaut plus que tout le reste du paragraphe.
- **Le chiffre (~0,19) n'y est pas, alors qu'il était autorisé par écrit.** Dans une lettre complète il
  est honnête parce qu'il est cadré (« c'est peu », et pourquoi). Dans un rappel de quatre phrases il
  n'a pas la place d'être cadré, et un chiffre non cadré se retient mal. Il appartient à l'envoi de la
  semaine prochaine.
- **« plus de travail que je ne le pensais »** est vrai et vérifiable : les dernières semaines sont
  effectivement passées dans le contrôle plutôt que dans le moteur. Ce n'est pas une formule.
- **Ce qui avait été perdu et qui est revenu** (vous l'aviez repéré) : la mention que la lettre est
  préparée par un LLM, qui ouvre chacune des précédentes ; la raison d'être de la clé (l'envoi porte de
  l'ensemble non déposé, donc il ne part pas en pièce jointe ordinaire) ; et l'argument lien-plutôt-que-
  pièce-jointe, qui vient de la lettre d'origine. Restent volontairement dehors : les deux documents,
  l'outil, le chiffre et sa définition, l'offre d'audit — ils attendent la revue PI.
- **Plus d'installation du tout.** Le script reproduit exactement le format d'identité du client :
  ML-KEM-768 dérivée d'une graine conservée, Ed25519, empreinte
  `sha256("probant-identity-v1" ‖ pub_kem ‖ pub_ed)`, écrit dans `~/.inferroute/confidential/identity/`.
- **L'aller-retour est vérifié, pas supposé.** Une charge scellée à la carte qu'il imprime s'ouvre avec
  la graine qu'il a stockée, et le client relit son identité avec la même empreinte. Des empreintes
  identiques ne prouveraient que l'accord des parties PUBLIQUES ; ce test-ci prouve qu'il pourra ouvrir
  l'envoi.
- **Le format existe désormais en deux exemplaires, et c'est le vrai risque.** Ils ne peuvent pas être
  fusionnés — l'intérêt du script est de ne dépendre de rien chez nous — donc la dérive est rendue
  DÉTECTABLE : quatre tests la cassent, et les trois dérives plausibles ont été introduites
  volontairement pour vérifier qu'ils les attrapent.
- **Découvert en le testant** : `public_card()` republie l'empreinte stockée sans la recalculer. Une
  identité portant une mauvaise empreinte serait propagée telle quelle par le client. Sans conséquence
  ici, mais c'est une faiblesse réelle à corriger.
- **Lien et non pièce jointe, pour une raison pratique** : une passerelle de cabinet rejette
  couramment un `.py`. Le fichier est publié et servi en `text/plain` — vérifié — de sorte qu'il
  s'affiche dans le navigateur au lieu d'être téléchargé. C'était `application/octet-stream` au premier
  essai, ce qui annulait exactement l'intérêt du lien.
- **Plus de vérification d'empreinte de vive voix** (vous l'avez demandé) : il renvoie sa clé par
  courriel, point. À noter une fois : l'empreinte est ce qui attraperait une clé substituée en route.
  Elle reste imprimée et conservée des deux côtés, donc la comparer reste possible à tout moment si vous
  vous parlez avant l'envoi — dix secondes, et rien ne l'impose.
- **⚠ La version précédente de cette lettre ne marchait probablement pas chez lui.** Elle disait
  « une seule commande la fournit : `python3 -m pip install 'cryptography>=50'` ». Sur macOS avec
  Homebrew, sur Debian et sur Ubuntu récents, cette commande **échoue** (PEP 668,
  `externally-managed-environment`). Vérifié sur cette machine : elle refuse. Remplacée par la forme
  `venv` jetable, testée de bout en bout sur une machine PEP 668 — la clé se crée et atterrit bien dans
  le dossier personnel, pas dans le venv. Le script lui-même affiche désormais cette ligne-là quand la
  bibliothèque manque, et non plus celle qui échoue.
- **`cryptography` reste nécessaire** et c'est la seule dépendance : ML-KEM-768 n'est pas dans la
  bibliothèque standard. Le script refuse proprement sans elle, sans rien écrire — comportement vérifié.
- **Pas de script hébergé, délibérément.** Un `curl … | bash` ferait la même chose en moins de lignes et
  serait exactement le contraire de ce que cette lettre promet. C'est dit dans le courrier en une phrase.
- **0.9.50 est la version du jour.** Celle de la semaine prochaine sera plus récente ; la clé qu'il
  produit aujourd'hui reste valable, c'est une paire de clés sur son disque et non un artefact de version.
- **Ce qu'il n'a pas** : aucune mention de l'offre, du calendrier de l'essai, ni des huit objets au-delà
  de « les objets dont nous avons parlé ». Si vous voulez qu'il en sache plus dès aujourd'hui, c'est un
  ajout à faire *après* la revue PI, pas avant.
