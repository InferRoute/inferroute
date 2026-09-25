# Bétrancourt — demande de clé publique (envoi du 25 sept.)

**STATUT : PROJET. Henry relit et envoie.** Volontairement étroit : il ne décrit ni l'offre, ni les
documents, ni aucun mécanisme — il ne demande qu'une clé et donne les commandes pour la produire. Rien
ici ne touche à l'ensemble non déposé, donc rien ici n'attend la revue PI. Le client complet part en
début de semaine prochaine.

Objet : **Une clé publique de votre part, avant l'envoi de la semaine prochaine**

---

Maître,

Un mot d'abord, comme la dernière fois : cette lettre a été préparée par un LLM, depuis mon ordinateur ;
je l'ai relue.

J'ai rencontré un ingénieur de l'INPI pour faire examiner la brevetabilité de concepts figurant dans les
dépôts provisoires. Sa réponse, en substance : c'est gris. Rien qui ferme la porte, rien qui l'ouvre franchement non plus —
et il m'a expliqué pourquoi l'informatique, et l'IA en particulier, s'y prêtent mal. J'en suis ressorti
avec des nuances que je n'avais pas, et avec l'idée qu'il valait mieux tenter que renoncer. C'est ce que
nous allons faire.

Je vous en parle parce que c'est votre métier et que ce n'est pas le mien. Si vous avez un avis
là-dessus, je le prendrai volontiers.

L'outil de recherche d'antériorité dont nous avions parlé devrait être prêt en début de semaine
prochaine. Si vous souhaitez y jeter un œil, j'aimerais beaucoup vous le mettre entre les mains ; et si
le moment est mal choisi, dites-le-moi sans façon.

Il viendrait avec le travail préparatoire dont nous avons parlé, qu'il sert aussi à traiter. L'envoi est
chiffré à votre seule clé et s'ouvre sur votre poste — il porte de l'ensemble non déposé, et c'est la
raison pour laquelle il ne peut pas partir en pièce jointe ordinaire.

Il m'aura demandé plus de temps que prévu, et pas du côté où je l'attendais : l'essentiel des dernières
semaines est passé non pas à produire le résultat, mais à le rendre contrôlable — à faire en sorte qu'un
tiers puisse refaire les vérifications lui-même, sans avoir à nous croire sur parole. J'ai supposé que
c'était la partie qui comptait le plus pour un cabinet ; vous me direz si je me suis trompé.

Deux choses seront vraies le jour où vous l'ouvrirez. La recherche s'exécute sans que l'invention non
déposée quitte votre poste en clair, ce qui est la difficulté propre à une recherche avant dépôt. Et
chaque recherche laisse une pièce datée et scellée, qu'un tiers peut revérifier plus tard sans nous.

J'espère que cela couvrira ce que vous m'aviez demandé, et peut-être un peu plus — mais c'est une
première version, elle aura ses angles morts, et je préfère vous le dire avant que vous les trouviez.
C'est pourquoi je suis impatient que vous la mettiez à l'épreuve : votre lecture dira si c'est utile, et
je n'ai pas de meilleur juge.

Si vous êtes partant, il me faudrait une chose de votre part d'ici là, et je vous remercie par avance
des quelques minutes qu'elle demande : votre **clé publique**. Sans elle je ne peux rien vous adresser à
vous seul, et c'est la seule chose qui me manque.

Vous n'avez rien à installer. Un fichier de quatre-vingt-dix lignes fait cela et rien d'autre :

**https://inferroute.ai/client/cle-probant.py**

Ouvrez-le d'abord dans votre navigateur : il s'y affiche comme du texte, et vous pouvez le lire en entier
avant de décider de l'exécuter. C'est la raison de sa taille, et la raison pour laquelle je vous l'envoie
sous cette forme plutôt qu'en installant un programme chez vous. Un lien plutôt qu'une pièce jointe
parce que les passerelles de messagerie rejettent volontiers ce type de fichier — et parce qu'un lien
peut être retiré, ce qu'une pièce jointe dans une boîte aux lettres ne peut plus être.

Puis, dans un terminal, depuis le dossier où vous l'avez enregistré, cette ligne :

```
python3 -m venv /tmp/cle && /tmp/cle/bin/pip install 'cryptography>=50' && /tmp/cle/bin/python cle-probant.py
```

Elle fait trois choses, dans cet ordre : un dossier de travail jetable dans `/tmp`, la seule bibliothèque
dont le script a besoin (ML-KEM-768 n'est pas dans Python par défaut), puis le script. Le détour par
`/tmp` n'est pas une précaution de style : sur macOS comme sur Linux récents, installer directement dans
le Python du système est refusé, et cette forme-là marche partout sans y toucher. Vous pouvez effacer
`/tmp/cle` aussitôt après ; votre clé, elle, est ailleurs et reste.

Si `cryptography` est déjà présente chez vous, `python3 cle-probant.py` suffit — et si elle ne l'est pas,
le script vous le dit et vous réaffiche la ligne ci-dessus, sans rien écrire.

Il crée deux clés dans votre dossier personnel et affiche la partie publique. Il n'ouvre aucun réseau et
ne contacte aucun serveur : vous pouvez le vérifier à la lecture, il n'importe même pas de quoi le faire.

**Vous me renvoyez par courriel ce qu'il affiche entre les deux lignes de tirets, tel quel.** Ce bloc ne
contient que des clés publiques : qui le lit n'apprend rien et ne peut rien ouvrir. Les parties secrètes
restent sur votre disque et ne sont jamais affichées.

Relancé une seconde fois, il ne recrée rien : il vous réaffiche la même clé. Une clé écrasée rendrait
illisible tout ce qui lui aurait déjà été adressé.

La clé qu'il produit est exactement celle qu'attend l'outil de la semaine prochaine, et elle l'attendra à
la bonne place : elle s'écrit dans votre dossier personnel, pas dans une installation.

## Une valeur à conserver dès maintenant

Un point qui ne vaut que s'il est noté **avant** d'en avoir besoin, et c'est pourquoi il part aujourd'hui
plutôt qu'avec le reste.

Les certificats que l'outil produira se vérifient contre une référence que nous signons. Cette référence
ne vaut que si la clé qui la signe est bien la nôtre. Voici son empreinte :

```
748e4c8e4ca334c5f804ffcdbd85f2dca29713e71c1c7c9c0737e3b898e2e204
```

Gardez-la avec ce courrier. Un tiers qui contrôlera un certificat plus tard vous demandera cette
valeur-là ; la prendre à ce moment sur notre site ne prouverait rien, puisque le site est le nôtre.
C'est d'en avoir la trace antérieure, chez vous, qui fait la différence. Plusieurs vérificateurs
indépendants ont buté sur exactement ce point, et il ne se règle pas entièrement de notre côté : il se
règle par ce courrier-ci.

Bien à vous,
Henry Declety

---

## Notes pour Henry — ne pas envoyer

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
- **« Si vous avez un avis là-dessus, je le prendrai volontiers »** : c'est son métier, vous le lui
  reconnaissez, et cela ouvre une porte professionnelle sans rien demander. À retirer si vous préférez
  ne pas solliciter d'avis gratuit.
- **Rien ne dit plus qu'il a accepté, parce qu'il n'a rien accepté** (votre précision : intérêt
  implicite, léger, aucun engagement). Les versions successives disaient « vous m'aviez dit votre
  intérêt », puis « vous aviez bien voulu vous dire prêt », puis « j'avais cru comprendre que vous
  seriez curieux » — toutes attribuaient à un tiers réel une position qu'il n'a pas prise. Il ne reste
  qu'une offre : « si vous souhaitez y jeter un œil, j'aimerais beaucoup vous le mettre entre les
  mains ; et si le moment est mal choisi, dites-le-moi sans façon. » Le refus proposé porte sur le
  MOMENT et non sur l'outil : il peut décliner sans rien juger.
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
