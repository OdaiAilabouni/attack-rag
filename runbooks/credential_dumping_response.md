# Runbook: Credential Dumping Response

## When to use this runbook

Use this runbook when EDR flags any of the following:

- Access to LSASS process memory by a non-Microsoft signed binary
- Reading of the SAM, SYSTEM, or SECURITY registry hives
- Suspicious access to ntds.dit on a Domain Controller
- DCSync activity (replication requests from a non-DC host)
- Creation or modification of files matching known credential-dumping tool signatures (Mimikatz, ProcDump used against LSASS, secretsdump.py, lsassy)

Maps to ATT&CK tactic: **TA0006 (Credential Access)**.

## Step 1 — Determine scope

Credential dumping is almost never an isolated event. Assume the attacker already has code execution on the host and is now harvesting credentials for lateral movement.

Identify:

- **Which technique?** Map the alert to a sub-technique:
  - **T1003.001 (LSASS Memory)** — Mimikatz, ProcDump on lsass.exe, Task Manager dump, comsvcs.dll MiniDump
  - **T1003.002 (Security Account Manager)** — reg.exe save on HKLM\SAM, copy of SAM/SYSTEM via VSS
  - **T1003.003 (NTDS)** — ntdsutil.exe, vssadmin to copy ntds.dit
  - **T1003.006 (DCSync)** — replication requests from non-DC, often via Mimikatz lsadump::dcsync
  - **T1555 (Credentials from Password Stores)** — browser saved passwords, Windows Credential Manager, Keychain

- **What credentials are exposed?** This drives the blast radius. LSASS dump on a workstation with one logged-in user exposes a few accounts. NTDS dump on a DC exposes every account in the domain.

## Step 2 — Contain (act fast)

1. Isolate the host via EDR immediately. Do not wait for full investigation.
2. If T1003.003 (NTDS) or T1003.006 (DCSync) is suspected: assume **full domain compromise**. Engage incident severity 1, notify the CISO, and begin domain rebuild planning.
3. Force password resets for all accounts that had active sessions on the affected host in the prior 30 days (pull from authentication logs, event ID 4624).
4. For domain-wide credential exposure, reset the krbtgt account password **twice**, with at least 10 hours between resets, to invalidate all existing Kerberos tickets including Golden Tickets.

## Step 3 — Investigate the entry vector

Credential dumping is post-exploitation. Find the initial access:

- Pull the parent process tree for the dumping tool. What spawned it?
- Check for recent execution of LOLBINs (rundll32, mshta, regsvr32, certutil) — common in initial access chains.
- Review the prior 7 days of email gateway logs for the user — phishing is a common entry point.
- Check VPN and external-facing service logs for anomalous logins from the affected user in the prior 30 days.

## Step 4 — Hunt for lateral movement

If credentials were dumped, assume they have been used or will be used:

- Search authentication logs (4624 type 3 for network logon, 4768/4769 for Kerberos) for the dumped accounts across the entire fleet, prior 7 days and forward.
- Look for impossible-travel patterns and logon times outside the user's normal pattern.
- For service accounts whose hashes were dumped, reset the password and redeploy the service.
- Cross-reference with **runbooks/lateral_movement_triage.md** if any suspicious authentication is found.

## Step 5 — Eradicate and recover

- Reimage the affected host. Do not attempt in-place cleanup of credential-access compromises — kernel-level persistence (rootkits, bootkits) is too easy to miss.
- After reimage, monitor authentication for the affected accounts for a minimum of 14 days.
- For domain-wide compromises (NTDS, DCSync), follow the AD recovery playbook, not this runbook.

## Why we move this fast

Credential dumping signals the attacker has shifted from initial access to harvesting tradecraft. The window between credential dump and use of the dumped credentials is typically hours, not days. Containment in Step 2 is intentionally aggressive — we accept the operational disruption of isolating a host and forcing password resets because the cost of letting harvested credentials propagate is far higher.
