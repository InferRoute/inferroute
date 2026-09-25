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

Il me faut pour cela votre **clé publique**. Elle se produit sur votre machine en trois commandes :

```
python3 -m venv ~/probant
~/probant/bin/pip install https://inferroute.ai/client/inferroute-0.9.50-py3-none-any.whl cryptography
~/probant/bin/ir probant identity
```

La première crée un dossier isolé, la deuxième y installe le programme, la troisième fabrique votre paire
de clés et affiche la partie publique. Rien n'est touché ailleurs sur votre poste, et rien n'est envoyé :
ces trois lignes ne font que créer deux clés sur votre disque et en imprimer une.

Vous me renvoyez ce que la dernière commande affiche entre les deux lignes de tirets. **Elle ne contient
que des clés publiques** : qui la lit n'apprend rien et ne peut rien ouvrir. Elle affiche aussi une
empreinte courte, de la forme `1234-abcd-5678-ef90`, que nous relirons de vive voix avant que quoi que ce
soit ne parte.

Je ne vous envoie pas de script à exécuter : trois lignes que vous lisez valent mieux qu'un fichier qui
en fait autant sans que vous le voyiez.

Si `uv` est installé chez vous, une seule ligne suffit et fait exactement la même chose :

```
uvx --from https://inferroute.ai/client/inferroute-0.9.50-py3-none-any.whl --with cryptography ir probant identity
```

(Sous Windows les chemins diffèrent : dites-le-moi et je vous envoie l'équivalent.)

Votre clé restera en place pour l'envoi de la semaine prochaine : elle s'écrit dans votre dossier
personnel et non dans l'installation, de sorte que le client complet la retrouvera telle quelle.

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
- **Passé de six commandes à trois**, et vérifié dans les deux formes depuis un HOME vierge sur 0.9.50.
  Ce qui a sauté : les deux `curl` (pip installe directement depuis l'adresse) et l'extra
  `[confidential]`, qui tirait fastapi, uvicorn et httpx — **la fabrication de la clé n'a besoin que de
  `cryptography`**. Testé explicitement : sans `cryptography` le programme refuse proprement et ne touche
  à rien ; avec, et rien d'autre, il fonctionne.
- **La ligne `sha256sum -c` a disparu avec les `curl`.** Elle valait moins qu'elle n'en avait l'air :
  l'empreinte et le fichier viennent du même serveur, donc elle écartait une altération en route et rien
  de plus. Le vrai contrôle est `ir probant audit-client`, qui compare la copie installée au fichier
  publié — il appartient à la lettre complète, pas à celle-ci.
- **La variante `uvx` en une ligne a été testée, y compris l'aller-retour** : la clé produite par la
  forme éphémère est relue à l'identique par une installation normale (même empreinte). C'est ce qui
  autorise à lui proposer les deux formes sans risque pour l'envoi de la semaine prochaine.
- **Pas de script hébergé, délibérément.** Un `curl … | bash` ferait la même chose en moins de lignes et
  serait exactement le contraire de ce que cette lettre promet. C'est dit dans le courrier en une phrase.
- **0.9.50 est la version du jour.** Celle de la semaine prochaine sera plus récente ; la clé qu'il
  produit aujourd'hui reste valable, c'est une paire de clés sur son disque et non un artefact de version.
- **Ce qu'il n'a pas** : aucune mention de l'offre, du calendrier de l'essai, ni des huit objets au-delà
  de « les objets dont nous avons parlé ». Si vous voulez qu'il en sache plus dès aujourd'hui, c'est un
  ajout à faire *après* la revue PI, pas avant.
