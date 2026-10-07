//! Desktop interface localization. Artifact data and machine-readable reports are unchanged.
use std::{
    collections::BTreeMap,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

pub const LANGUAGES: [(&str, &str); 11] = [
    ("en", "English"),
    ("zh-CN", "简体中文"),
    ("ja", "日本語"),
    ("ko", "한국어"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("es", "Español"),
    ("it", "Italiano"),
    ("pt-BR", "Português (Brasil)"),
    ("ru", "Русский"),
    ("vi", "Tiếng Việt"),
];
const SOURCES: [&str; 11] = [
    include_str!("../locales/en.json"),
    include_str!("../locales/zh-CN.json"),
    include_str!("../locales/ja.json"),
    include_str!("../locales/ko.json"),
    include_str!("../locales/de.json"),
    include_str!("../locales/fr.json"),
    include_str!("../locales/es.json"),
    include_str!("../locales/it.json"),
    include_str!("../locales/pt-BR.json"),
    include_str!("../locales/ru.json"),
    include_str!("../locales/vi.json"),
];
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static CATALOGS: OnceLock<Vec<BTreeMap<String, String>>> = OnceLock::new();
fn catalogs() -> &'static [BTreeMap<String, String>] {
    CATALOGS.get_or_init(|| {
        SOURCES
            .iter()
            .map(|source| {
                serde_json::from_str(source).expect("validated embedded translation catalog")
            })
            .collect()
    })
}

/// Normalize OS locale identifiers. Unsupported locales fall back to English;
/// Traditional Chinese does not silently select Simplified Chinese.
pub fn resolve_locale(locale: &str) -> &'static str {
    let normalized = locale
        .split('.')
        .next()
        .unwrap_or(locale)
        .split('@')
        .next()
        .unwrap_or(locale)
        .replace('_', "-")
        .to_lowercase();
    let parts: Vec<_> = normalized.split('-').collect();
    match parts[0] {
        "zh" if !parts
            .iter()
            .any(|p| matches!(*p, "hant" | "tw" | "hk" | "mo")) =>
        {
            "zh-CN"
        }
        "pt" if parts.contains(&"br") => "pt-BR",
        "ja" => "ja",
        "ko" => "ko",
        "de" => "de",
        "fr" => "fr",
        "es" => "es",
        "it" => "it",
        "ru" => "ru",
        "vi" => "vi",
        _ => "en",
    }
}
pub fn set_language(code: &str) {
    let code = resolve_locale(code);
    ACTIVE.store(
        LANGUAGES.iter().position(|l| l.0 == code).unwrap_or(0),
        Ordering::Relaxed,
    );
}
pub fn language() -> &'static str {
    LANGUAGES[ACTIVE.load(Ordering::Relaxed)].0
}
pub fn translate_for<'a>(code: &str, text: &'a str) -> &'a str {
    let index = LANGUAGES
        .iter()
        .position(|l| l.0 == resolve_locale(code))
        .unwrap_or(0);
    catalogs()[index]
        .get(text)
        .map(String::as_str)
        .unwrap_or(text)
}
pub fn t(text: impl AsRef<str>) -> String {
    translate_for(language(), text.as_ref()).to_owned()
}
pub fn system_language() -> String {
    for key in ["HEXLORA_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
            && value != "C"
            && value != "POSIX"
            && !value.starts_with("C.")
        {
            return resolve_locale(&value).to_owned();
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(first) = text
            .lines()
            .skip(1)
            .map(|line| line.trim().trim_matches(|c| c == '"' || c == ','))
            .find(|s| !s.is_empty() && *s != ")")
        {
            return resolve_locale(first).to_owned();
        }
    }
    #[cfg(target_os = "windows")]
    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-UICulture).Name"])
        .output()
    {
        return resolve_locale(String::from_utf8_lossy(&output.stdout).trim()).to_owned();
    }
    "en".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_language_has_a_complete_nonempty_catalog() {
        assert_eq!(LANGUAGES.len(), 11);
        let english = &catalogs()[0];
        for catalog in catalogs() {
            assert_eq!(
                catalog.keys().collect::<Vec<_>>(),
                english.keys().collect::<Vec<_>>()
            );
            assert!(catalog.values().all(|value| !value.trim().is_empty()));
        }
    }
    #[test]
    fn locale_resolution_handles_regions_scripts_and_fallback() {
        for (input, expected) in [
            ("zh_Hans_CN.UTF-8", "zh-CN"),
            ("zh-TW", "en"),
            ("zh-Hant", "en"),
            ("pt_BR.UTF-8", "pt-BR"),
            ("pt-PT", "en"),
            ("ja-JP", "ja"),
            ("vi_VN", "vi"),
            ("xx", "en"),
        ] {
            assert_eq!(resolve_locale(input), expected);
        }
    }
    #[test]
    fn translations_preserve_unknown_technical_values() {
        assert_eq!(translate_for("zh-CN", "Open File…"), "打开文件…");
        assert_eq!(translate_for("vi", "File"), "Tệp");
        assert_eq!(translate_for("ru", "arm64"), "arm64");
        assert_eq!(translate_for("xx", "File"), "File");
    }
}
