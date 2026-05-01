# Runbook: Lateral Movement Triage

## When to use this runbook

Use this runbook when an alert indicates an authenticated user account is performing actions on a host the user does not normally access, or when EDR/SIEM flags suspicious remote-execution patterns (e.g. WMI, PsExec, scheduled tasks created remotely, Remote Desktop sessions from non-admin endpoints).

Maps to ATT&CK tactic: **TA0008 (Lateral Movement)**.

## Step 1 — Validate the alert

Confirm the alert is not a false positive before opening an incident:

- Pull the source and destination hosts. Is the source a known jumpbox or admin workstation?
- Pull the user account. Is it a service account, a privileged admin, or a regular user?
- Check the time of day. Did this happen during the user's normal working hours and from their typical geographic region?

If all three look benign, document the false positive in the SIEM and close. If any look anomalous, proceed to Step 2.

## Step 2 — Identify the technique

Map the observed activity to a specific ATT&CK technique so the response is targeted:

- **Remote Services (T1021)** — RDP, SMB/Windows Admin Shares, SSH, WinRM, VNC. Look at the network protocol used.
- **Lateral Tool Transfer (T1570)** — file copied to the destination host before execution. Check for new binaries in the user profile or ProgramData.
- **Use Alternate Authentication Material (T1550)** — Pass-the-Hash, Pass-the-Ticket, Web Session Cookie. Cross-reference with credential-access alerts in the prior 24 hours.
- **Internal Spearphishing (T1534)** — lateral movement via internal email. Check whether the source user sent unusual mail to the destination user.

## Step 3 — Contain

If the technique is confirmed:

1. Isolate the destination host via EDR (do not power it off — preserve memory).
2. Disable the user account in AD. Force a password reset and revoke all active Kerberos tickets.
3. If Pass-the-Hash or Pass-the-Ticket is suspected, also reset the krbtgt account password twice (24 hours apart) — this is critical and required.
4. Notify the on-call IR lead. Open a ticket in the IR queue with severity tier matching the host's classification.

## Step 4 — Investigate

- Pull EDR process telemetry from both source and destination for the prior 7 days.
- Pull authentication logs (4624, 4625, 4768, 4769) for the user account across the entire Windows fleet.
- If the destination is a Tier 0 asset (DC, ADCS, ADFS, PKI), escalate to incident severity 1 immediately and engage the threat-hunting team.

## Step 5 — Document

Record findings in the case management system with:

- ATT&CK technique IDs observed (be specific — T1021.001 for RDP, not just T1021)
- Indicators of compromise (file hashes, IPs, domains)
- User accounts and hosts affected
- Containment actions taken with timestamps

## Cross-references

- For credential-access alerts that often precede lateral movement, see **runbooks/credential_dumping_response.md**.
- For threat-actor attribution, consult the latest weekly threat intel brief.
