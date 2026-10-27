# Backups and restore

[← FlowSphera](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

*Settings → Backups* (admins) and `sudo flowtrack backup | restore` keep the flow data and every setting safe:

- **Schedule**: a full backup once a week (or daily) and the changes since it on the other days, at the hour you set,
  run by `flowtrack-backup.timer` on the server itself. *Back up now* any time; the keeping rule removes the oldest full
  backups together with their changes. The first scheduled backup after an install or upgrade waits for its hour.
- **Where**: always a folder on the server (`/var/backups/flowtrack`, or `--backup-dir DIR` when installing or upgrading
  — e.g. a disk mounted from a NAS), plus copies to **S3** (Amazon or any S3 storage: MinIO, Backblaze B2, Wasabi,
  Cloudflare R2, Hetzner…), **SFTP** (key or password; the server's key is accepted once and then checked) and **FTP**
  (FTPS by default). A copy that fails is retried with the next backup; *Test* checks a place by writing, reading back
  and deleting a file.
- **Encryption** of the copies with a passphrase (AES-256-GCM, key from scrypt). Without the passphrase an encrypted
  copy cannot be restored. The folder on the server is readable by root only and not encrypted (the next backup of
  the changes is made against it).
- **Check**: *Check* (or `flowtrack backup verify ID`) compares every file with ClickHouse's list; `--deep` restores the
  backup into a scratch database and counts the rows.
- **Restore** (`sudo flowtrack restore [ID]`): collecting stops for the time of it, the current flow data is set aside
  until the backup is in place and comes back if the restore fails (`flowtrack restore --undo` after an interruption).
  `--only-settings`, `--only-data`; the license files only with `--with-license` (a license is bound to its server).
  On a new server: install FlowSphera, set the same place in *Settings → Backups*, then
  `sudo flowtrack restore --from s3` (or `sftp`, `ftp`, a folder with `.ftbk` files) and pick the backup.
- **Encrypted copies are trusted only encrypted.** While the server encrypts its copies, a copy on S3 / SFTP / FTP that
  is not encrypted is refused — whoever can write to that place could have put it there, and a restore runs as root.
  A copy you made yourself before turning encryption on: add `--unencrypted`.

```bash
sudo flowtrack backup [--full]                 # a backup now
sudo flowtrack backup list [--from s3|sftp|ftp|DIR]
sudo flowtrack backup verify [ID] [--deep]
sudo flowtrack restore [ID] [--from …] [--only-settings|--only-data] [--with-license] [--passphrase-file F] [--unencrypted]
```
