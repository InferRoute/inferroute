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

Il me faut pour cela votre **clé publique**. Elle se produit sur votre machine en six commandes, que
voici telles quelles :

```
curl -LO https://inferroute.ai/client/inferroute-0.9.50-py3-none-any.whl
curl -LO https://inferroute.ai/client/inferroute-0.9.50-py3-none-any.whl.sha256
sha256sum -c inferroute-0.9.50-py3-none-any.whl.sha256
python3 -m venv ~/probant
~/probant/bin/pip install "./inferroute-0.9.50-py3-none-any.whl[confidential]"
~/probant/bin/ir probant identity
```

La troisième ligne vérifie que le fichier téléchargé est bien celui que nous publions ; elle doit
répondre `OK`. Je vous la donne pour que rien ne se fasse à l'aveugle, en précisant ce qu'elle vaut :
l'empreinte et le fichier viennent du même serveur, donc cette ligne écarte une altération en route,
pas une tromperie de notre part. Ce qui écarte la seconde est plus bas.

La dernière commande affiche votre clé. Vous me renvoyez ce qu'elle imprime entre les deux lignes de
tirets. **Elle ne contient que des clés publiques** : qui la lit n'apprend rien et ne peut rien ouvrir.
Elle affiche aussi une empreinte courte, de la forme `1234-abcd-5678-ef90` ; nous la relirons de vive
voix avant que quoi que ce soit ne parte.

Rien de tout cela ne lance de recherche ni n'envoie quoi que ce soit : ces commandes installent le
programme et fabriquent une paire de clés sur votre disque. Le programme est du Python en clair — il se
lit entièrement, sans avoir à nous croire.

(Sous Windows les chemins diffèrent : dites-le-moi et je vous envoie l'équivalent.)

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
- **Chaîne vérifiée de bout en bout le 25 sept. sur 0.9.50**, depuis un HOME vierge : les six commandes
  passent, `sha256sum -c` répond `OK`, et `ir probant identity` imprime bien une carte de contact et une
  empreinte courte. Ce n'est pas une chaîne recopiée d'un brouillon : elle a été exécutée telle quelle.
- **La ligne `sha256sum -c` est nouvelle** par rapport au brouillon précédent, et elle n'aurait pas
  fonctionné avant aujourd'hui : le fichier d'empreinte publié était écrit en format nu et faisait
  échouer la commande d'une manière qui ressemble exactement à une altération. Corrigé ce matin, vérifié
  depuis l'adresse publique.
- **Ce que la ligne d'empreinte ne prouve pas** est dit dans le courrier, en une phrase. Ne pas le
  retirer : un destinataire qui la croit indépendante se croira couvert par elle.
- **0.9.50 est la version du jour.** Celle de la semaine prochaine sera plus récente ; la clé qu'il
  produit aujourd'hui reste valable, c'est une paire de clés sur son disque et non un artefact de version.
- **Ce qu'il n'a pas** : aucune mention de l'offre, du calendrier de l'essai, ni des huit objets au-delà
  de « les objets dont nous avons parlé ». Si vous voulez qu'il en sache plus dès aujourd'hui, c'est un
  ajout à faire *après* la revue PI, pas avant.
