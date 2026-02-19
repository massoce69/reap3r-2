1. Prepare a CSV/XLSX with columns `zabbix_host` and `dat` (DAT must be 64 hex chars).
2. Open `Deployment > Zabbix DAT Deploy` and import the file.
3. Set `mode=dry_run` first, provide Zabbix URL/user/password/script and Reap3r server URL.
4. Click `Import & Create Batch`, then `Validate` to run Zabbix checks only (no remote execution).
5. Fix all `invalid` rows (`host not found`, `host ambiguous`, `script missing`) and re-import if needed.
6. Switch to `mode=live`, re-import the corrected file, then `Validate` again.
7. Click `Start` to execute Zabbix global script `Reap3rEnroll` on `ready` hosts only.
8. Monitor status, attempts, callback and errors in real time in the batch detail table.
9. Use `Retry Failed` for retryable failures (backoff 1m/5m/20m, max 3 attempts).
10. Export the per-host report and archive it with batch ID for audit evidence.
