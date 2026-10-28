//! File-based UI translations. Diagnostic messages always remain in English.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

thread_local! {
    static ACTIVE: RefCell<Option<Arc<Language>>> = const { RefCell::new(None) };
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    locale: String,
    name: String,
    messages: BTreeMap<String, String>,
}

struct Language {
    pack: Pack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Text(String),
    Field(String),
}

fn parts(text: &str) -> Result<Vec<Part>> {
    let mut result = Vec::new();
    let mut rest = text;
    let mut position = 0;
    while let Some(start) = rest.find('{') {
        if start > 0 {
            result.push(Part::Text(rest[..start].into()));
        }
        rest = &rest[start + 1..];
        let end = rest.find('}').context("unclosed translation placeholder")?;
        let name = rest[..end].split(':').next().unwrap_or_default();
        let name = if name.is_empty() {
            let name = position.to_string();
            position += 1;
            name
        } else {
            name.into()
        };
        ensure!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid translation placeholder"
        );
        result.push(Part::Field(name));
        rest = &rest[end + 1..];
    }
    ensure!(!rest.contains('}'), "unexpected closing translation brace");
    if !rest.is_empty() {
        result.push(Part::Text(rest.into()));
    }
    Ok(result)
}

fn fields(parts: &[Part]) -> BTreeMap<&str, usize> {
    let mut result = BTreeMap::new();
    for part in parts {
        if let Part::Field(name) = part {
            *result.entry(name.as_str()).or_default() += 1;
        }
    }
    result
}

impl Language {
    fn new(mut pack: Pack, english: &Pack) -> Result<Self> {
        pack.locale = normalize(&pack.locale);
        ensure!(
            !pack.locale.is_empty()
                && pack.locale.len() <= 35
                && pack.locale.split('-').all(|part| !part.is_empty()
                    && part.bytes().all(|byte| byte.is_ascii_alphanumeric())),
            "invalid language tag"
        );
        ensure!(
            !pack.name.trim().is_empty()
                && pack.name.chars().count() <= 80
                && !pack.name.chars().any(char::is_control),
            "invalid language name"
        );
        // Older packs may contain retired diagnostic keys; keep their UI translations.
        pack.messages
            .retain(|source, _| english.messages.contains_key(source));
        for (source, translated) in &pack.messages {
            let source_parts = parts(source)?;
            let translated_parts = parts(translated)?;
            ensure!(
                fields(&source_parts) == fields(&translated_parts),
                "translation placeholders differ: {source}"
            );
        }
        Ok(Self { pack })
    }

    fn text(&self, message: &str) -> String {
        self.pack
            .messages
            .get(message)
            .cloned()
            .unwrap_or_else(|| message.into())
    }
}

#[derive(Clone)]
pub struct Localizer {
    languages: BTreeMap<String, Arc<Language>>,
    system: Vec<String>,
    preference: String,
    selected: Arc<Language>,
}

impl Localizer {
    pub fn load() -> Self {
        let mut directories = Vec::new();
        if let Ok(executable) = std::env::current_exe()
            && let Some(parent) = executable.parent()
        {
            directories.push(parent.join("locales"));
        }
        if let Ok(config) = crate::storage::config_directory() {
            directories.push(config.join("locales"));
        }
        let preference = preference_file()
            .and_then(std::fs::read_to_string)
            .unwrap_or_else(|_| "system".into());
        Self::from_directories(&directories, system_languages(), preference.trim())
    }

    fn from_directories(directories: &[PathBuf], system: Vec<String>, preference: &str) -> Self {
        let english: Pack = serde_json::from_str(include_str!("../locales/en.json"))
            .expect("valid English language pack");
        let russian: Pack = serde_json::from_str(include_str!("../locales/ru.json"))
            .expect("valid Russian language pack");
        let mut languages = BTreeMap::new();
        for pack in [english.clone(), russian] {
            let language =
                Arc::new(Language::new(pack, &english).expect("valid built-in language pack"));
            languages.insert(language.pack.locale.clone(), language);
        }
        for directory in directories {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            let mut files: Vec<_> = entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                })
                .collect();
            files.sort();
            for file in files {
                let loaded = (|| -> Result<Language> {
                    let bytes = crate::storage::read_limited(
                        std::fs::File::open(&file)?,
                        1024 * 1024,
                        "language pack exceeds 1 MiB",
                    )?;
                    let text = std::str::from_utf8(&bytes)?.trim_start_matches('\u{feff}');
                    Language::new(serde_json::from_str(text)?, &english)
                })();
                match loaded {
                    Ok(language) => {
                        languages.insert(language.pack.locale.clone(), Arc::new(language));
                    }
                    Err(error) => crate::log!(
                        Warning,
                        "locale",
                        "Could not load {}: {error:#}",
                        file.display()
                    ),
                }
            }
        }
        let selected = languages["en"].clone();
        let mut result = Self {
            languages,
            system,
            preference: String::new(),
            selected,
        };
        result.select(preference);
        result
    }

    pub fn select(&mut self, preference: &str) {
        self.preference = if preference == "system" {
            "system".into()
        } else {
            normalize(preference)
        };
        let requested = if self.preference == "system" {
            self.system.first().map(String::as_str).unwrap_or("en")
        } else {
            &self.preference
        };
        let locale = normalize(requested);
        self.selected = self
            .languages
            .get(&locale)
            .or_else(|| self.languages.get(locale.split('-').next().unwrap_or("en")))
            .unwrap_or(&self.languages["en"])
            .clone();
    }

    pub fn preference(&self) -> &str {
        &self.preference
    }
    pub fn language(&self) -> &str {
        &self.selected.pack.locale
    }
    pub fn name(&self) -> &str {
        &self.selected.pack.name
    }
    pub fn languages(&self) -> Vec<(String, String)> {
        self.languages
            .iter()
            .map(|(id, language)| (id.clone(), language.pack.name.clone()))
            .collect()
    }
    pub fn enter(&self) -> LanguageGuard {
        LanguageGuard {
            previous: ACTIVE.with(|active| active.replace(Some(self.selected.clone()))),
            thread: PhantomData,
        }
    }
    pub fn save_preference(&self) -> Result<()> {
        write_preference(&preference_file()?, &self.preference)
    }
}

pub struct LanguageGuard {
    previous: Option<Arc<Language>>,
    thread: PhantomData<Rc<()>>,
}
impl Drop for LanguageGuard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.replace(self.previous.take()));
    }
}

pub fn text(message: impl AsRef<str>) -> String {
    let message = message.as_ref();
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .map_or_else(|| message.into(), |language| language.text(message))
    })
}

/// Translate a known template before inserting already formatted, opaque values.
pub fn format(message: &str, values: &[&str]) -> String {
    let source = parts(message).expect("valid source translation template");
    let names: Vec<_> = source
        .iter()
        .filter_map(|part| match part {
            Part::Field(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let translated = text(message);
    let parts = parts(&translated).expect("validated translation template");
    let mut result = String::new();
    for part in parts {
        match part {
            Part::Text(text) => result.push_str(&text),
            Part::Field(name) => {
                let Some(value) = names
                    .iter()
                    .position(|candidate| *candidate == name)
                    .and_then(|index| values.get(index))
                else {
                    return message.into();
                };
                result.push_str(value);
            }
        }
    }
    result
}

fn normalize(locale: &str) -> String {
    locale
        .trim()
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .replace('_', "-")
        .to_ascii_lowercase()
}

fn preference_file() -> std::io::Result<PathBuf> {
    crate::storage::config_directory()
        .map(|directory| directory.join("language"))
        .map_err(std::io::Error::other)
}

fn write_preference(path: &Path, preference: &str) -> Result<()> {
    crate::storage::write_atomic(path, preference.as_bytes())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn system_languages() -> Vec<String> {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let mut count = 0;
    let mut size = 0;
    if unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            std::ptr::null_mut(),
            &mut size,
        )
    } == 0
        || !(1..=65536).contains(&size)
    {
        return Vec::new();
    }
    let mut buffer = vec![0; size as usize];
    if unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            buffer.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        return Vec::new();
    }
    buffer
        .split(|unit| *unit == 0)
        .filter(|name| !name.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[cfg(not(windows))]
fn system_languages() -> Vec<String> {
    for name in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return value.split(':').map(String::from).collect();
        }
    }
    Vec::new()
}

#[cfg(test)]
#[path = "../tests/unit/localization.rs"]
mod tests;
