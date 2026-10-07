# Hexlora

[Discord](https://discord.gg/eGzEaP6TzR)

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Español](README.es.md) · **Italiano** · [Português (Brasil)](README.pt-BR.md) · [Русский](README.ru.md) · [Tiếng Việt](README.vi.md)

Hexlora è un ambiente multipiattaforma scritto in Rust per il triage statico, il confronto e l’audit dei rilasci di applicazioni e file binari. Organizza applicazioni, cartelle, pacchetti e singoli file come artefatti logici, esaminando struttura, metadati, firme, dipendenze e dettagli PE, Mach-O ed ELF senza eseguirne il contenuto.

L’app offre mappe ad albero interattive delle dimensioni, grafici e mappe termiche dell’entropia collegati alla vista esadecimale, un grafo delle dipendenze, cronologie delle firme, matrici di architettura e privacy IPA, filtri per gravità, pannelli ridimensionabili e contrasto elevato. Esporta rapporti Markdown, PDF e SVG e schermate della finestra.

Il README inglese è la fonte di riferimento e contiene la matrice dettagliata del supporto. Questa edizione riassume installazione, funzioni principali e limiti di sicurezza.

## Lingue dell’interfaccia

Hexlora supporta inglese, cinese semplificato, giapponese, coreano, tedesco, francese, spagnolo, italiano, portoghese brasiliano, russo e vietnamita. Il menu della lingua nella barra dei menu o in fondo alla finestra cambia subito l’interfaccia e salva la scelta. Al primo avvio viene usata la lingua del sistema. Navigazione, pulsanti, titoli dei pannelli e intestazioni comuni sono tradotti. Contenuti degli artefatti, diagnosi tecniche e rapporti esportati conservano il testo originale.

## Schermate

[![Hexlora durante l’ispezione di Hexlora.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/hexlora/it/#gallery)

La galleria mostra struttura delle app, dettagli Mach-O, dipendenze, stringhe estratte e lettura esadecimale a intervalli limitati.

## Installazione con Homebrew

```sh
brew install --cask everettjf/tap/hexlora
```

Strumento da riga di comando facoltativo:

```sh
brew install everettjf/tap/hexlora-cli
```

L’app macOS è firmata con Developer ID, notarizzata da Apple e dotata del ticket allegato. Ogni rilascio verifica la firma rigorosa, il ticket e la valutazione Gatekeeper.

## Funzioni principali

| Ambito | Supporto attuale |
|---|---|
| macOS / iOS | App macOS, bundle, framework, Mach-O universali, DMG e PKG/XAR; audit IPA di identità, dimensioni, destinazioni incorporate, architetture, lingue, privacy, provisioning, diritti e risultati. |
| Android | Manifesti APK, identità del pacchetto e dell’SDK, permessi, componenti esportati, collegamenti profondi, statistiche DEX, librerie native, ABI, indicatori di firma e risultati. |
| Windows | Intestazioni, sezioni, importazioni, esportazioni, simboli, dipendenze e metadati Authenticode PE/COFF; identità, capacità, app, punti di ingresso e stato della firma APPX/MSIX. |
| Linux | Intestazioni ELF, architetture, interprete, sezioni, segmenti, rilocazioni, simboli e dipendenze; metadati DEB, file, dimensione installata, script di manutenzione e file privilegiati. |
| Contenitori e dati | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, immagini e testo. 7z, RAR e flussi compressi autonomi sono riconosciuti ma non offrono ancora l’esplorazione completa dei membri. |
| Analisi generale | Albero degli artefatti, metadati, intestazioni, slice di architettura, sezioni, segmenti, simboli, dipendenze, stringhe, vista esadecimale su richiesta, hash, entropia, firme e risultati. |
| Confronto e CI | Identità esatta SHA-256; file aggiunti, rimossi, modificati e spostati, crescita e duplicati; JSON, Markdown, HTML, SARIF, criteri di rilascio, soglie di gravità e codici di uscita stabili. |

[Matrice dettagliata del supporto (inglese)](README.md#detailed-support-matrix) · [Schema dei rapporti (inglese)](docs/report-schema.md) · [Matrice dei test (inglese)](docs/testing.md)

## Flusso di lavoro desktop

Apri o trascina file, app, pacchetti, cartelle o aree di lavoro. Ridimensiona i pannelli ed esplora le grandi tabelle virtualizzate. Le aree di lavoro conservano percorsi, vista selezionata, segnalibri, note e cache di analisi. Gli strumenti esterni compatibili si avviano solo su richiesta.

Scorciatoie macOS: `⌘N` nuova finestra, `⌘O` file, `⇧⌘O` cartella, `⌥⌘O` area di lavoro, `⌘S` salva, `⌘F` cerca.

## CLI

```sh
hexlora-cli inspect ./SomeApp.app --pretty
hexlora-cli inspect ./MyApp.ipa --depth deep --format sarif --output hexlora.sarif
hexlora-cli inspect ./package --hash sha256 --strings --entropy
```

Le profondità di analisi sono `lightweight`, `standard` e `deep`. Codici di uscita: errore fatale `1`, criterio o soglia non rispettati `2`, annullamento `4`, rapporto parziale utilizzabile `5`.

## Piattaforme e requisiti

macOS 13 Ventura o successivo su Apple silicon (`arm64`), Windows x64 o Linux amd64. I comandi macOS sopra richiedono Homebrew.

GitHub Releases offre MSI e ZIP portatile per Windows, DEB e tar.gz portatile per Linux. Questi pacchetti Windows e Linux non sono ancora firmati: verifica SHA256SUMS prima dell’installazione. Il motore esamina PE ed ELF su tutte le piattaforme supportate.

[Download](https://github.com/everettjf/hexlora/releases/latest) · [SHA256SUMS](https://github.com/everettjf/hexlora/releases/latest/download/SHA256SUMS)

## Limiti di sicurezza

Hexlora opera staticamente e in sola lettura. Non esegue programmi importati, non monta immagini disco, non installa pacchetti e non estrae automaticamente archivi. Non decompila, non esegue debug e non modifica byte. Non segue collegamenti simbolici. Input, ricorsione, file, stringhe e output dei comandi hanno limiti espliciti. I risultati euristici sono indizi, non verdetti di malware.

## Validazione automatizzata

La CI verifica il workspace Rust, Clippy, Rust 1.88 come versione minima, i contratti CLI e dei rapporti e la compilazione e l’avvio dell’app macOS. Un corpus pubblico fissato per dimensione e SHA-256 copre 16 artefatti reali. I rilasci macOS verificano inoltre Developer ID, notarizzazione Apple, ticket, Gatekeeper, installazione Homebrew e test della formula.

## Documentazione

[Strategia del prodotto](docs/product-strategy.md) · [Matrice dettagliata del supporto (inglese)](README.md#detailed-support-matrix) · [Schema dei rapporti (inglese)](docs/report-schema.md) · [Matrice dei test (inglese)](docs/testing.md) · [Sito web](https://xnu.app/hexlora/it/)
