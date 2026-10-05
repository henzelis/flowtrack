# Changelog

FlowTrack follows [semantic versioning](https://semver.org): MAJOR.MINOR.PATCH. The version is in `VERSION`, shown
in Settings → General, at the bottom of every page, in the collector log and by the installer.

## 1.0.0 — 2026-10-05

First numbered release.

- **Editions.** FlowTrack Community (this repository, MIT): up to 5,000 records/s, 14 days of flow details for new
  installs (older installs keep 30). FlowTrack Pro: a module plus a time-limited license key — no records/s limit,
  longer retention, Pro features as they ship. Installer: `--pro FILE|URL`, `--license KEY|FILE`.
- **Settings page** with tabs: General (language, version), Devices (exporters, interfaces, collector), Users
  (administrators), License. Replaces the Devices and Users pages; old links open the matching tab. An edition badge
  under the logo shows Community / Pro and warns before a license ends.
- **Custom periods** on every page: from / to to the minute, or drag across a traffic chart to zoom in; kept in the URL.
- **Flows:** a click on the exchange diagram highlights and shows details, Shift+click filters; clicks on the
  Services / Ports chart bands filter. Live windows no longer move when filters change.
- Collector: drops packets an exporter sends twice; counts records over the edition limit.
