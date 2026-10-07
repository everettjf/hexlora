# Hexlora

[Discord](https://discord.gg/eGzEaP6TzR)

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Deutsch](README.de.md) · **Français** · [Español](README.es.md) · [Italiano](README.it.md) · [Português (Brasil)](README.pt-BR.md) · [Русский](README.ru.md) · [Tiếng Việt](README.vi.md)

Hexlora est un atelier multiplateforme écrit en Rust pour le triage statique, la comparaison et l’audit de publication d’applications et de fichiers binaires. Il représente les applications, dossiers, paquets et fichiers comme des artefacts logiques et examine leur structure, leurs métadonnées, signatures et dépendances ainsi que les formats PE, Mach-O et ELF sans exécuter le contenu.

L’application propose des cartes de taille interactives, des courbes et cartes thermiques d’entropie avec navigation hexadécimale, un graphe de dépendances, des chronologies de signature, des matrices d’architecture et de confidentialité IPA, des filtres de gravité, des panneaux redimensionnables, un contraste élevé et l’export de rapports Markdown, PDF et SVG ainsi que de captures de fenêtre.

Le README anglais est la référence et contient la matrice de compatibilité détaillée. Cette édition résume l’installation, les fonctions principales et les limites de sécurité.

## Langues de l’interface

Hexlora prend en charge l’anglais, le chinois simplifié, le japonais, le coréen, l’allemand, le français, l’espagnol, l’italien, le portugais du Brésil, le russe et le vietnamien. Le menu de langue dans la barre de menus ou au bas de la fenêtre change l’interface immédiatement et mémorise le choix. Au premier lancement, la langue suit celle du système. La navigation, les boutons, les titres de panneaux et les en-têtes courants sont traduits. Le contenu des artefacts, les diagnostics techniques et les rapports exportés conservent leur texte original.

## Captures d’écran

[![Hexlora inspectant Hexlora.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/hexlora/fr/#gallery)

La galerie présente la structure des applications, les détails Mach-O, les dépendances, les chaînes extraites et la vue hexadécimale à lecture limitée.

## Installation avec Homebrew

```sh
brew install --cask everettjf/tap/hexlora
```

Outil en ligne de commande facultatif :

```sh
brew install everettjf/tap/hexlora-cli
```

L’application macOS est signée avec un certificat Developer ID, notariée par Apple et accompagnée de son ticket agrafé. Les publications vérifient la signature stricte, le ticket et Gatekeeper.

## Fonctions principales

| Domaine | Compatibilité actuelle |
|---|---|
| macOS / iOS | Applications macOS, bundles, frameworks, Mach-O universel, DMG et PKG/XAR ; audit IPA de l’identité, des tailles, des cibles intégrées, architectures, langues, déclarations de confidentialité, profils, droits et constats. |
| Android | Manifestes APK, identité du paquet et du SDK, autorisations, composants exportés, liens profonds, statistiques DEX, bibliothèques natives, ABI, indices de signature et constats. |
| Windows | En-têtes, sections, imports, exports, symboles, dépendances et métadonnées Authenticode PE/COFF ; identité, capacités, applications, points d’entrée et état de signature APPX/MSIX. |
| Linux | En-têtes ELF, architectures, interpréteur, sections, segments, relocalisations, symboles et dépendances ; métadonnées DEB, fichiers, taille installée, scripts de maintenance et fichiers privilégiés. |
| Conteneurs et données | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, images et texte. Les formats 7z, RAR et les flux compressés autonomes sont reconnus mais ne disposent pas encore d’une navigation complète de leurs membres. |
| Analyse générale | Arborescence des artefacts, métadonnées, en-têtes, tranches d’architecture, sections, segments, symboles, dépendances, chaînes, vue hexadécimale à la demande, empreintes, entropie, signatures et constats. |
| Comparaison et CI | Identité exacte SHA-256 ; fichiers ajoutés, supprimés, modifiés ou déplacés, croissance et doublons ; JSON, Markdown, HTML, SARIF, politiques de publication, seuils de gravité et codes de sortie stables. |

[Matrice de compatibilité détaillée (anglais)](README.md#detailed-support-matrix) · [Schéma des rapports (anglais)](docs/report-schema.md) · [Matrice de tests (anglais)](docs/testing.md)

## Utilisation de l’application

Ouvrez ou déposez un fichier, une application, un paquet, un dossier ou un espace de travail. Redimensionnez les panneaux et explorez les grandes tables virtualisées. Les espaces de travail conservent les chemins, la vue sélectionnée, les signets, les notes et le cache d’analyse. Les outils externes compatibles s’exécutent uniquement à votre demande.

Raccourcis macOS : `⌘N` nouvelle fenêtre, `⌘O` fichier, `⇧⌘O` dossier, `⌥⌘O` espace de travail, `⌘S` enregistrer, `⌘F` rechercher.

## CLI

```sh
hexlora-cli inspect ./SomeApp.app --pretty
hexlora-cli inspect ./MyApp.ipa --depth deep --format sarif --output hexlora.sarif
hexlora-cli inspect ./package --hash sha256 --strings --entropy
```

Les profondeurs d’analyse sont `lightweight`, `standard` et `deep`. Codes de sortie : erreur fatale `1`, échec de politique ou de seuil `2`, annulation `4`, rapport partiel exploitable `5`.

## Plateformes et prérequis

macOS 13 Ventura ou ultérieur sur Apple silicon (`arm64`) ; Windows x64 ; Linux amd64. Homebrew est nécessaire pour les commandes macOS ci-dessus.

Les téléchargements GitHub proposent MSI et ZIP portable pour Windows ainsi que DEB et tar.gz portable pour Linux. Ces paquets Windows et Linux ne sont pas encore signés ; vérifiez SHA256SUMS avant installation. Le moteur peut inspecter PE et ELF sur toutes les plateformes prises en charge.

[Téléchargements](https://github.com/everettjf/hexlora/releases/latest) · [SHA256SUMS](https://github.com/everettjf/hexlora/releases/latest/download/SHA256SUMS)

## Limites de sécurité

Hexlora travaille de manière statique et en lecture seule. Il n’exécute pas les programmes importés, ne monte pas les images disque, n’installe pas les paquets et n’extrait pas automatiquement les archives. Il ne décompile pas, ne débogue pas et ne modifie pas les octets. Il ne suit pas les liens symboliques. Les entrées, la récursion, les fichiers, les chaînes et les sorties des commandes ont des limites explicites. Les constats heuristiques sont des indices, pas des verdicts de logiciel malveillant.

## Validation automatisée

La CI vérifie le workspace Rust, Clippy, Rust 1.88 comme version minimale, les contrats CLI et des rapports, ainsi que la construction et le lancement de l’application macOS. Un corpus public fixé par taille et SHA-256 couvre 16 artefacts réels. Les publications macOS valident aussi la signature Developer ID, la notarisation, le ticket, Gatekeeper, l’installation Homebrew et le test de la formule.

## Documentation

[Stratégie produit](docs/product-strategy.md) · [Matrice de compatibilité détaillée (anglais)](README.md#detailed-support-matrix) · [Schéma des rapports (anglais)](docs/report-schema.md) · [Matrice de tests (anglais)](docs/testing.md) · [Site web](https://xnu.app/hexlora/fr/)
