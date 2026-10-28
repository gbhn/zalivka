# Language packs

English is the base language. Russian is included. The interface follows the
system language unless the user selects a language in Settings → Language.
Application log messages, saved journals and CLI diagnostics always use English.
Device replies, file names, account names and other diagnostic data are preserved.

To add a language without changing Rust code or rebuilding the application:

1. Copy `en.json` to a new UTF-8 JSON file, for example `fr.json`.
2. Set `locale` to the language tag, such as `fr` or `pt-BR`, and `name` to its
   native display name, such as `Français`.
3. Translate the **values** in `messages`. Keep the English keys unchanged.
4. Put the file in `locales/` beside the executable, or in the user's settings
   folder: `%LOCALAPPDATA%\zalivka\locales` on Windows, and
   `$XDG_CONFIG_HOME/zalivka/locales` or `~/.config/zalivka/locales` on Unix.
5. Restart the app. The new language appears in Settings and is eligible for
   automatic selection from the system language.

A partial pack works too; missing messages fall back to English:

```json
{
  "locale": "fr",
  "name": "Français",
  "messages": {
    "Settings": "Paramètres",
    "Language": "Langue",
    "Technical details": "Détails techniques"
  }
}
```

English text is the lookup key, including templates such as `Version {}, build {}`.
Keep all `{placeholders}` in the translation. Unnamed placeholders keep their
original order; use explicit indices such as `{1}` and `{0}` to reorder them.
Named placeholders, for example `{name}`, keep their names. UI code selects a template before inserting values formatted by Rust.
Translations do not execute code or formatting rules; values are inserted as
opaque data and are never translated recursively.
File names and endpoint/account identifiers remain unchanged. Diagnostic log
formats are excluded from the UI catalogs.

The loader validates language names and placeholders. Unknown or retired keys
are ignored so older language packs keep working after UI catalog cleanup. An invalid pack is
skipped with an English warning in the diagnostic log; built-in languages remain
available. Packs are limited to 1 MiB. User settings packs take precedence over
packs beside the executable. Exact language tags are tried first, then the base
language (`ru-RU` → `ru`), then English.

Windows uses the first language in the user's preferred UI language list; an
unsupported system language falls back directly to English. Unix uses `LC_ALL`, `LC_MESSAGES`,
`LANGUAGE` and `LANG`. The manual language choice is saved separately from the
theme; selecting System default restores automatic detection.

The build script includes the English and Russian catalogs in the executable and
copies JSON files from this directory to `artifacts/locales/`. The executable
therefore retains English and Russian even when distributed alone.
