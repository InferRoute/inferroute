# Bétrancourt — demande de clé publique (envoi du 25 sept.)

**STATUT : PROJET. Henry relit et envoie.** Volontairement étroit : il ne décrit ni l'offre, ni les
documents, ni aucun mécanisme — il ne demande qu'une clé et donne les commandes pour la produire. Rien
ici ne touche à l'ensemble non déposé, donc rien ici n'attend la revue PI. Le client complet part en
début de semaine prochaine.

Objet : **Une clé publique de votre part, avant l'envoi de la semaine prochaine**

---

Maître,

Je vous adresse en début de semaine prochaine le client complet, avec les objets dont nous avons parlé.
L'envoi sera chiffré à votre seule clé et s'ouvrira sur votre poste.

Il me faut pour cela votre **clé publique**. Vous n'avez rien à installer : le fichier joint,
`cle-probant.py`, ne fait que cela. Il tient en quatre-vingt-dix lignes que vous pouvez lire en entier
avant de l'exécuter — c'est précisément pourquoi je vous l'envoie sous cette forme plutôt qu'en
installant un programme chez vous.

```
python3 cle-probant.py
```

Il crée deux clés dans votre dossier personnel et affiche la partie publique. Il n'ouvre aucun réseau,
ne contacte aucun serveur et n'installe rien : vous pouvez le vérifier à la lecture, il n'importe même
pas de quoi le faire. Si la bibliothèque `cryptography` manque sur votre machine, il vous le dit et
s'arrête **sans rien écrire** ; une seule commande la fournit :

```
python3 -m pip install 'cryptography>=50'
```

Vous me renvoyez ce que le script affiche entre les deux lignes de tirets. **Ce bloc ne contient que des
clés publiques** : qui le lit n'apprend rien et ne peut rien ouvrir. Les parties secrètes restent sur
votre disque et ne sont jamais affichées. Le script imprime aussi une empreinte courte, de la forme
`1234-abcd-5678-ef90`, que nous relirons de vive voix avant que quoi que ce soit ne parte.

Relancé une seconde fois, il ne recrée rien : il vous réaffiche la même clé. Une clé écrasée rendrait
illisible tout ce qui lui aurait déjà été adressé.

La clé qu'il produit est exactement celle qu'attend le client complet de la semaine prochaine, et elle
l'attendra à la bonne place : elle s'écrit dans votre dossier personnel, pas dans une installation.

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
- **Plus d'installation du tout.** Le script joint (`docs/handout/cle-probant.py`) reproduit exactement
  le format d'identité du client : ML-KEM-768 dérivée d'une graine conservée, Ed25519, empreinte
  `sha256("probant-identity-v1" ‖ pub_kem ‖ pub_ed)`, écrit dans `~/.inferroute/confidential/identity/`.
- **L'aller-retour est vérifié, pas supposé.** Une charge scellée à la carte qu'il imprime s'ouvre avec
  la graine qu'il a stockée, et le client relit son identité avec la même empreinte. C'est le point qui
  compte : des empreintes identiques ne prouvent que l'accord des parties PUBLIQUES ; ce test-ci prouve
  qu'il pourra ouvrir l'envoi.
- **Le format existe désormais en deux exemplaires, et c'est le vrai risque.** Ils ne peuvent pas être
  fusionnés — l'intérêt du script est de ne dépendre de rien chez nous — donc la dérive est rendue
  DÉTECTABLE : quatre tests la cassent, et les trois dérives plausibles ont été introduites
  volontairement pour vérifier qu'ils les attrapent. Si le format bouge avant l'envoi, la suite rougit.
- **Découvert en le testant** : `public_card()` republie l'empreinte stockée sans la recalculer. Une
  identité portant une mauvaise empreinte serait propagée telle quelle par le client. Sans conséquence
  ici (le test la recalcule à partir des clés brutes), mais c'est une faiblesse réelle à corriger.
- **`cryptography` reste nécessaire** et c'est la seule dépendance : ML-KEM-768 n'est pas dans la
  bibliothèque standard. Le script refuse proprement sans elle, sans rien écrire — comportement vérifié.
- **Pas de script hébergé, délibérément.** Un `curl … | bash` ferait la même chose en moins de lignes et
  serait exactement le contraire de ce que cette lettre promet. C'est dit dans le courrier en une phrase.
- **0.9.50 est la version du jour.** Celle de la semaine prochaine sera plus récente ; la clé qu'il
  produit aujourd'hui reste valable, c'est une paire de clés sur son disque et non un artefact de version.
- **Ce qu'il n'a pas** : aucune mention de l'offre, du calendrier de l'essai, ni des huit objets au-delà
  de « les objets dont nous avons parlé ». Si vous voulez qu'il en sache plus dès aujourd'hui, c'est un
  ajout à faire *après* la revue PI, pas avant.
