# Translations

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

The code holds English only; every other language is one dictionary, `web/i18n/<code>.json` (`uk.json` is the
Ukrainian one). It serves the web UI and the server's texts (errors, events, Telegram messages) alike. A new language
needs no code change: copy `uk.json` to e.g. `de.json`, set `"@name"` (the language's own name, shown in Settings →
General) and `"@locale"` (dates and numbers, e.g. `de-DE`), and translate the values:

```json
{
 "@name": "Deutsch",
 "@locale": "de-DE",
 "Password guessing": "Passwort-Raten",
 "Ignore {addr}? Its events will no longer be recorded or shown. You can undo it in Settings → Events.": "{addr} ignorieren? …",
 "ends in {n} days": {"one": "endet in {n} Tag", "other": "endet in {n} Tagen"}
}
```

- The key is the English text. `{name}` placeholders stay as they are, in any order.
- A text with a number may give the forms of its language ([CLDR plural categories](https://cldr.unicode.org/index/cldr-spec/plural-rules):
  `one`, `few`, `many`, `other`) or one text for all.
- A key with a prefix such as `button::Sign in` is the same English text in another place that may need another
  translation; the prefix is not shown.
- A missing text stays English. `python3 -m unittest tests.test_i18n` lists the texts a dictionary lacks or no
  longer needs (it runs over every file in `web/i18n/`).

The installer's own messages (English and Ukrainian) are in `install.sh`.
