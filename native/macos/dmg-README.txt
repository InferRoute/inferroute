ANTERIORA @VERSION@ pour Mac / for Mac                  (Apple silicon : M1 ou plus récent / M1 or later)

=== FRANÇAIS ===

Installer
  Faites glisser Anteriora dans le dossier Applications, puis ouvrez-le depuis Applications.

Le premier lancement : l'avertissement d'Apple
  Anteriora n'est pas signé avec un certificat de développeur Apple et n'a pas été « notarié » par Apple.
  Au premier lancement, macOS refuse donc de l'ouvrir et affiche un message du type
  « Apple n'a pas pu vérifier que Anteriora ne contient pas de logiciel malveillant ». C'est attendu.
  Pour l'ouvrir quand même, une seule fois :
    1. Cliquez sur « OK » (ou « Terminé ») dans ce message.
    2. Ouvrez Réglages Système > Confidentialité et sécurité, descendez jusqu'à la section Sécurité :
       une ligne indique que Anteriora a été bloqué. Cliquez sur « Ouvrir quand même », puis confirmez
       (mot de passe du Mac ou Touch ID).
       (macOS 12 : Préférences Système > Sécurité et confidentialité > Général.)
  Les fois suivantes, Anteriora s'ouvre normalement.

Ce que fait l'application
  Elle démarre Anteriora et ouvre sa page dans votre navigateur. L'icône de Anteriora reste dans le Dock
  tant qu'il tourne : un clic sur cette icône rouvre la page. Pour arrêter Anteriora (et toute session
  en cours), choisissez Quitter dans le menu de l'icône du Dock ou appuyez sur Cmd-Q.
  Anteriora fait travailler son assistant dans une petite machine virtuelle Linux sur ce Mac, et refuse de
  la démarrer si ses fichiers ne portent pas la signature d'InferRoute.

Ce que cet avertissement NE prouve PAS, et ce qui le remplace
  Apple n'a pas examiné cette application. Le fait que macOS l'ouvre après « Ouvrir quand même » ne
  dit rien sur qui l'a construite. La confiance repose sur autre chose : les fichiers de la machine
  virtuelle (programme de lancement, noyau, image) sont fixés par leur empreinte dans un manifeste signé
  par la clé d'InferRoute, que Anteriora vérifie avant chaque démarrage ; les bibliothèques incluses ont
  été installées seulement si leur empreinte correspondait à la liste figée de la version @VERSION@.

=== ENGLISH ===

Install
  Drag Anteriora into the Applications folder, then open it from Applications.

First launch: Apple's warning
  Anteriora is not signed with an Apple Developer certificate and has not been notarized by Apple. On
  first launch macOS therefore refuses to open it, with a message such as "Apple could not verify
  Anteriora is free of malware". This is expected. To open it anyway, once:
    1. Click "OK" (or "Done") in that message.
    2. Open System Settings > Privacy & Security and scroll down to the Security section: a line says
       Anteriora was blocked. Click "Open Anyway", then confirm (your Mac's password or Touch ID).
       (macOS 12: System Preferences > Security & Privacy > General.)
  After that, Anteriora opens normally.

What the app does
  It starts Anteriora and opens its page in your browser. Anteriora's icon stays in the Dock while it runs:
  click the icon to reopen the page. To stop Anteriora (and any session in progress), choose Quit from the
  Dock icon's menu or press Cmd-Q.
  Anteriora runs its assistant inside a small Linux virtual machine on this Mac, and refuses to start that
  machine unless its files carry InferRoute's signature.

What this warning does NOT prove, and what stands in its place
  Apple has not examined this app. macOS opening it after "Open Anyway" says nothing about who built it.
  Trust rests elsewhere: the virtual machine's files (launcher, kernel, image) are pinned by their
  fingerprints in a manifest signed with InferRoute's key, which Anteriora checks before every start; the
  bundled libraries were installed only if their fingerprints matched the fixed list of release @VERSION@.
