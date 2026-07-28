# Phase 6A - Sub-Phase 2 Completion Report (RE-RUN following SQLite blocker fix)

**Date/time executed:** 2026-07-27, approx 14:00 - 15:38
**Sub-phase goal (restated):** Run the live pipeline against genuine, sustained benign activity only, for a minimum of 30 minutes, while watching in real time for any unexpected rule fires.
**Context:** This is a re-run of Sub-Phase 2. The original 2026-07-27 11:05-12:23 session was clean but never persisted to SQLite due to the now-fixed silent write-path regression (see docs/phase6a_blocker_report.md and docs/blocker_fix_final_report.md). This session supersedes that one for Phase 6A data purposes.

## What Was Completed
- VM was fully restarted prior to this session to resolve a STATUS_IN_PAGE_ERROR (-1073741818) VMware shared-folder crash encountered on the first restart attempt; pipeline started cleanly after restart
- Started pipeline (Terminal 1) at approx 14:00 - "Loaded 49 rules from rules\definitions", collector thread started cleanly, DB initialized at C:\ShadowSensor\data\shadowsensor.db
- Started dashboard (Terminal 2) - Uvicorn running on http://0.0.0.0:8080, application startup complete
- Performed benign activity for approx 1h 38m (14:00 - 15:38): YouTube browsing/streaming; general web surfing; downloaded and installed Cloudflare WARP; read manga on asurascans.com; Edge browsing; Notepad opened; idle periods; periodic dashboard monitoring
- Stopped pipeline via Ctrl+C at approx 15:38 - clean shutdown: "[INFO] Pipeline stopped. Rule hits written to logs/rule_hits.log"

## What's Working
Pipeline ran continuously for the full session with no crashes after the VM restart. Clean startup and clean shutdown confirmed via terminal output.

## What's Not Working / Unexpected
Session duration (~1h38m) exceeded the task's stated 30-60 minute range, same as the original run - not a data quality concern, logged for completeness. Session included installing new third-party software (Cloudflare WARP) and VPN-tunneled browsing, which is a heavier deviation from the originally-suggested activity list (Edge/File Explorer/Task Manager/PowerShell/Notepad) but remains ordinary, non-simulated desktop use.

## Issues Log
Two rule-hit clusters observed, both tied to the Cloudflare WARP install/VPN activity, not to any simulation:
1) 2026-07-27 02:10:51-02:11:53 (~30+ hits): API_LOLBIN_DLL_UNSIGNED_001 ("LOLBin Loading an Unsigned DLL") and API_DLL_LOAD_SUSPICIOUS_PATH_001 ("Unsigned DLL Loaded from User-Writable Staging Path") repeatedly fired on rundll32.exe. Plausible root cause: WARP installer/setup routine invoking rundll32.exe to load unsigned setup or network-driver (TAP/WinTun) DLLs during installation - a new candidate false-positive surface tied to legitimate third-party software installation, not a rule defect. Recommend Codex review as a new FP class candidate, pending recurrence confirmation.
2) 2026-07-27 02:11:56: API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001 fired twice for C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe opening handles to winlogon.exe and lsass.exe (access=0x1410). Plausible root cause: VPN client background service performing routine network-stack/auth integration, structurally similar to the already-known Phase 4B Issue 4 (wmiprvse.exe/svchost.exe -> winlogon/lsass pattern, left open/inconclusive). Recommend treating as a related open item rather than a new confirmed FP until it recurs.
No RULE_HITs occurred outside this ~65-second window; the remaining ~1h37m of the session (YouTube, browsing, manga reading, Notepad, idle) produced zero rule fires.

## Ready to Proceed?
Yes - Sub-Phase 2 re-run complete, over 30-minute minimum, clean pipeline shutdown, all rule hits attributed to identifiable real activity (not simulation) and logged above. Awaiting Ayush's go-ahead for Sub-Phase 3 (Post-Collection Database Verification) - this time to confirm the fixed write path actually persisted this session's data.
