# Changelog

Every released version of the agent, newest first. A version that changes
shipped code gets a section here in the same change that bumps `VERSION`.
The portal shows these notes next to each release.

## 1.12.0 - 2026-10-05

- Memory on Linux is now broken down into free memory, page cache, buffers
  and shared memory (tmpfs), so memory held by programs can be told apart
  from cache the kernel hands back on demand.
- New `processes` collector: every 30 s the ten process names holding the
  most memory (private memory on Linux, working set on Windows), summed per
  name with the number of processes, plus the total number of processes and
  (Linux) zombies. Only names are sent, never command lines.
- New `kernel` collector (Linux): pressure stall information for CPU, memory
  and I/O, OOM kills since boot, running and blocked tasks, open file
  handles and TCP sockets (in use, TIME_WAIT).

## 1.11.2 - 2026-10-05

- Windows self-update: the release manifest must carry a valid signature by
  the release key built into the agent; an unsigned or foreign-signed
  manifest is refused. Previously the MSI was only checked against the
  checksum in that same, unsigned manifest.
- Windows: the agent refuses to start when its configuration or state
  directory is not owned and writable by SYSTEM/Administrators only, or is a
  junction. The self-update writes the installer under a random name and
  starts `msiexec` from the system directory.

## 1.11.1 - 2026-10-04

- Updated dependencies (gopsutil 4.26.9, go-ole 1.3.0). No behaviour change.

## 1.11.0 - 2026-10-01

- Each filesystem now reports the stable `/dev/disk/by-id` names of the disks
  beneath it (through partitions, LVM and RAID), so the portal can map disk
  usage to the volumes of a cloud server.

## 1.10.1 - 2026-09-30

- Fixed: a successful self-update on Linux was reported as failed
  (`signal: terminated`). The `systemd-run` client dies with the old service;
  the agent now leaves that case unreported and the restarted agent confirms
  the update.

## 1.10.0 - 2026-09-28

- Metrics frames sent for live views are marked as `live`, so the portal can
  update server lists every second without storing those samples twice.

## 1.9.1 - 2026-09-28

- Source published under the Apache 2.0 licence; the Go module path is now
  `github.com/INFORENT-GmbH/host-agent`. No functional change.

## 1.9.0 - 2026-09-21

- SNMP poller for network devices (v2c and v3): ports, CPU, memory and
  sensors of routers and switches, reported like any local host. A satellite
  agent polls the devices assigned to it.

## 1.8.0 - 2026-09-21

- Windows setup script (`install.ps1`) and self-update via MSI. The MSI is
  verified against the signed channel manifest before it runs.

## 1.7.0 - 2026-09-21

- Release builds include a Windows binary and a per-brand MSI package.

## 1.6.0 - 2026-09-21

- Runs as a Windows service and logs to the Windows event log;
  `service install|uninstall|start|stop` for manual setups.
- Windows checks: services, pending Windows updates (offline search), pending
  reboot.

## 1.5.0 - 2026-09-21

- Windows support groundwork: machine ID, system info, configuration paths
  and file permissions (ACLs) on Windows; local checks run there too.

## 1.4.0 - 2026-09-20

- The apt source uses the `agent` component; package installation rewrites
  existing `main` sources.

## 1.3.2 - 2026-09-18

- Setup: `--fix-clone-id` regenerates a duplicate machine ID without asking
  (for cloned cloud servers) when enrolment is rejected because of it.

## 1.3.1 - 2026-09-18

- Setup restarts the service instead of `enable --now`, so a re-enrolment
  replaces an agent that is already running with the old token.

## 1.3.0 - 2026-09-18

- Setup: `--token-file` and `--uninstall`.

## 1.2.0 - 2026-09-17

- Clear instructions when enrolment is rejected (for example a cloned machine
  ID). Setup offers to regenerate the machine ID and supports `--reinstall`.

## 1.1.0 - 2026-09-17

- `enroll -channel stable|testing|off` and `enroll -local-checks=false` set
  the update channel and local checks during setup.

## 1.0.0 - 2026-09-17

- First release built and published by the portal.
