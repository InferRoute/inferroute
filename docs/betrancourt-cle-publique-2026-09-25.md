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

Je vous adresse en début de semaine prochaine le travail préparatoire dont nous avons parlé, avec l'outil
qui l'a produit. L'envoi sera chiffré à votre seule clé et s'ouvrira sur votre poste — il porte de
l'ensemble non déposé, et c'est la raison pour laquelle il ne part pas en pièce jointe ordinaire.

Il me faut donc votre **clé publique**, et c'est tout ce que demande cette lettre-ci. Vous n'avez rien à
installer. Un fichier de quatre-vingt-dix lignes fait cela et rien d'autre :

**https://inferroute.ai/client/cle-probant.py**

Ouvrez-le d'abord dans votre navigateur : il s'y affiche comme du texte, et vous pouvez le lire en entier
avant de décider de l'exécuter. C'est la raison de sa taille, et la raison pour laquelle je vous l'envoie
sous cette forme plutôt qu'en installant un programme chez vous. Un lien plutôt qu'une pièce jointe
parce que les passerelles de messagerie rejettent volontiers ce type de fichier — et parce qu'un lien
peut être retiré, ce qu'une pièce jointe dans une boîte aux lettres ne peut plus être.

Puis, dans un terminal, depuis le dossier où vous l'avez enregistré :

```
python3 cle-probant.py
```

Il crée deux clés dans votre dossier personnel et affiche la partie publique. Il n'ouvre aucun réseau et
ne contacte aucun serveur : vous pouvez le vérifier à la lecture, il n'importe même pas de quoi le faire.
Si la bibliothèque `cryptography` manque sur votre machine, il vous le dit et s'arrête **sans rien
écrire** ; une seule commande la fournit :

```
python3 -m pip install 'cryptography>=50'
```

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
- **`cryptography` reste nécessaire** et c'est la seule dépendance : ML-KEM-768 n'est pas dans la
  bibliothèque standard. Le script refuse proprement sans elle, sans rien écrire — comportement vérifié.
- **Pas de script hébergé, délibérément.** Un `curl … | bash` ferait la même chose en moins de lignes et
  serait exactement le contraire de ce que cette lettre promet. C'est dit dans le courrier en une phrase.
- **0.9.50 est la version du jour.** Celle de la semaine prochaine sera plus récente ; la clé qu'il
  produit aujourd'hui reste valable, c'est une paire de clés sur son disque et non un artefact de version.
- **Ce qu'il n'a pas** : aucune mention de l'offre, du calendrier de l'essai, ni des huit objets au-delà
  de « les objets dont nous avons parlé ». Si vous voulez qu'il en sache plus dès aujourd'hui, c'est un
  ajout à faire *après* la revue PI, pas avant.
