# Hexlora

[Discord](https://discord.gg/eGzEaP6TzR)

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · **한국어** · [Deutsch](README.de.md) · [Français](README.fr.md) · [Español](README.es.md) · [Italiano](README.it.md) · [Português (Brasil)](README.pt-BR.md) · [Русский](README.ru.md) · [Tiếng Việt](README.vi.md)

Hexlora는 Rust로 작성된 크로스 플랫폼 앱 및 바이너리 검사 도구입니다. 앱, 디렉터리, 패키지와 개별 파일을 논리적 아티팩트로 구성하고, 내용을 실행하지 않은 채 구조, 메타데이터, 서명, 종속성과 PE, Mach-O, ELF 정보를 분석하여 정적 분류, 비교 및 릴리스 감사를 수행합니다.

데스크톱 앱은 대화형 크기 트리맵, 16진수 탐색과 연동되는 엔트로피 차트 및 히트맵, 종속성 그래프, 서명 타임라인, IPA 아키텍처 및 개인정보 행렬, 심각도 필터, 크기 조절 패널, 고대비 모드를 제공합니다. Markdown, PDF, SVG 보고서와 윈도우 스크린샷을 내보낼 수 있습니다.

영문 README가 기준 문서이며 자세한 지원 목록을 포함합니다. 이 번역본은 설치, 주요 기능과 보안 경계를 설명합니다.

## 인터페이스 언어

영어, 중국어 간체, 일본어, 한국어, 독일어, 프랑스어, 스페인어, 이탈리아어, 브라질 포르투갈어, 러시아어와 베트남어를 지원합니다. 메뉴 막대 또는 윈도우 하단의 언어 메뉴에서 즉시 전환할 수 있으며 선택은 다음 실행에도 유지됩니다. 첫 실행에는 시스템 언어를 따릅니다. 탐색, 버튼, 패널 제목과 일반적인 표 머리글이 번역되어 있습니다. 아티팩트 내용, 기술 진단과 내보낸 보고서는 원문을 유지합니다.

## 스크린샷

[![Hexlora.app을 검사하는 Hexlora](docs/assets/screenshots/overview.jpg)](https://xnu.app/hexlora/ko/#gallery)

갤러리에서 앱 구조, Mach-O 정보, 종속성, 추출된 문자열과 제한된 범위의 16진수 보기를 확인할 수 있습니다.

## Homebrew로 설치

```sh
brew install --cask everettjf/tap/hexlora
```

선택 사항: 명령줄 도구 설치

```sh
brew install everettjf/tap/hexlora-cli
```

macOS 앱은 Developer ID 인증서로 서명되고 Apple 공증을 받으며 공증 티켓이 첨부됩니다. 릴리스 시 엄격한 서명 검사, 티켓 검증과 Gatekeeper 평가를 수행합니다.

## 주요 기능

| 분야 | 현재 지원 |
|---|---|
| macOS / iOS | macOS 앱, 번들, 프레임워크, 범용 Mach-O, DMG와 PKG/XAR. IPA 식별 정보, 크기, 내장 대상, 아키텍처, 언어, 개인정보 선언, 프로비저닝, 권한 및 발견 사항 감사. |
| Android | APK 매니페스트, 패키지 및 SDK 정보, 권한, 외부 공개 구성 요소, 딥 링크, DEX 통계, 네이티브 라이브러리, ABI, 서명 지표 및 발견 사항. |
| Windows | PE/COFF 헤더, 섹션, 가져오기와 내보내기, 심볼, 종속성 및 Authenticode 메타데이터. APPX/MSIX 식별 정보, 기능, 앱, 진입점 및 서명 상태. |
| Linux | ELF 헤더, 아키텍처, 인터프리터, 섹션, 세그먼트, 재배치, 심볼 및 종속성. DEB 메타데이터, 파일, 설치 크기, 유지 관리 스크립트와 특권 파일. |
| 컨테이너 및 데이터 | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, 이미지와 텍스트. 7z, RAR와 독립 압축 스트림은 식별만 지원하며 전체 항목 탐색은 아직 제공하지 않습니다. |
| 일반 분석 | 아티팩트 트리, 메타데이터, 헤더, 아키텍처 슬라이스, 섹션, 세그먼트, 심볼, 종속성, 문자열, 필요 시 읽는 16진수 보기, 해시, 엔트로피, 서명 및 발견 사항. |
| 비교 및 CI | 정확한 SHA-256 식별, 추가·삭제·수정·이동된 파일, 크기 증가 및 중복. JSON, Markdown, HTML, SARIF, 릴리스 정책, 심각도 기준과 안정적인 종료 코드. |

[상세 지원 목록 (영문)](README.md#detailed-support-matrix) · [보고서 스키마 (영문)](docs/report-schema.md) · [테스트 목록 (영문)](docs/testing.md)

## 데스크톱 사용 흐름

파일, 앱, 패키지, 폴더 또는 작업 공간을 열거나 끌어 놓으세요. 패널 크기를 조절하고 가상화된 대규모 표를 탐색할 수 있습니다. 작업 공간은 경로, 선택한 보기, 북마크, 메모와 분석 캐시를 보존합니다. 호환되는 외부 도구는 요청할 때만 실행됩니다.

macOS 단축키: `⌘N` 새 윈도우, `⌘O` 파일, `⇧⌘O` 폴더, `⌥⌘O` 작업 공간, `⌘S` 저장, `⌘F` 검색.

## CLI

```sh
hexlora-cli inspect ./SomeApp.app --pretty
hexlora-cli inspect ./MyApp.ipa --depth deep --format sarif --output hexlora.sarif
hexlora-cli inspect ./package --hash sha256 --strings --entropy
```

분석 깊이는 `lightweight`, `standard`, `deep`입니다. 종료 코드: 치명적 오류 `1`, 정책 또는 발견 사항 기준 실패 `2`, 취소 `4`, 사용 가능한 부분 보고서 `5`.

## 플랫폼 및 요구 사항

Apple silicon (`arm64`)에서 macOS 13 Ventura 이상, Windows x64 또는 Linux amd64. 위 macOS 설치 명령에는 Homebrew가 필요합니다.

GitHub Releases에서 Windows MSI 및 포터블 ZIP, Linux DEB 및 포터블 tar.gz를 받을 수 있습니다. Windows와 Linux 패키지는 아직 코드 서명되지 않았으므로 설치 전에 SHA256SUMS를 확인하세요. 모든 지원 플랫폼에서 PE와 ELF를 검사할 수 있습니다.

[다운로드](https://github.com/everettjf/hexlora/releases/latest) · [SHA256SUMS](https://github.com/everettjf/hexlora/releases/latest/download/SHA256SUMS)

## 보안 경계

Hexlora는 정적 읽기 전용 분석을 수행합니다. 가져온 프로그램을 실행하거나 디스크 이미지를 마운트하거나 패키지를 설치하거나 아카이브를 자동으로 추출하지 않습니다. 디컴파일, 디버깅 또는 바이트 수정도 수행하지 않습니다. 심볼릭 링크를 따라가지 않으며 입력, 재귀, 파일, 문자열과 명령 출력에 명시적인 제한을 둡니다. 휴리스틱 발견 사항은 단서이며 악성코드 판정이 아닙니다.

## 자동 검증

CI는 Rust 작업 공간, Clippy, 최소 Rust 1.88, CLI 및 보고서 규약, macOS 앱 빌드와 실행을 검증합니다. 크기와 SHA-256으로 고정된 공개 코퍼스에는 실제 아티팩트 16개가 포함됩니다. macOS 릴리스는 Developer ID 서명, Apple 공증, 티켓, Gatekeeper, Homebrew 설치와 Formula 테스트를 추가로 검증합니다.

## 문서

[제품 전략](docs/product-strategy.md) · [상세 지원 목록 (영문)](README.md#detailed-support-matrix) · [보고서 스키마 (영문)](docs/report-schema.md) · [테스트 목록 (영문)](docs/testing.md) · [웹사이트](https://xnu.app/hexlora/ko/)
