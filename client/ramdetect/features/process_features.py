"""
ramdetect/features/process_features.py
======================================
Extracts 25 features from EPROCESS structures to detect:
- Hidden processes (DKOM)
- Orphan processes
- Parent-child anomalies
- Path/name anomalies
- Privilege escalation
- Behavioral indicators

FIXED: Robust browser whitelisting to prevent false positives
Updated: Tags specific processes with anomalies for UI display.
Author: RAMDetect Development Team
"""

from typing import Dict, List, Any
import re
import os
from collections import defaultdict
from .feature_base import FeatureExtractor

class ProcessFeatures(FeatureExtractor):
    """
    Extract 25 process-related features for malware detection.
    Inherits from FeatureExtractor to ensure consistent interface and logging.
    """
    
    # --- CONSTANTS FOR HEURISTICS ---
    
    # Known System Processes
    SYSTEM_PROCESSES = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe'
    }
    
    # Browser processes (multi-process architecture means many "orphans")
    BROWSER_WHITELIST = {
        'msedge.exe', 'chrome.exe', 'firefox.exe', 'brave.exe',
        'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'microsoftedge.exe',
        'msedgewebview2.exe', 'chromium.exe', 'waterfox.exe'
    }

    # Known-malicious process names — presence alone is HIGH-severity evidence.
    # These are offensive tools / well-known malware binaries that should never
    # appear in a clean Windows environment.
    #
    # Naming convention: lowercase, with .exe suffix where applicable.
    # Keep entries specific; avoid generic names that legitimate software reuses.
    KNOWN_MALICIOUS_PROCESSES = {
        # Crypto miners
        'xmrig.exe',          # XMRig Monero miner (RedTail, many others)
        'xmr-stak.exe',       # XMR-Stak miner
        'minerd.exe',         # cpuminer
        'cgminer.exe',        # CGMiner
        'bfgminer.exe',       # BFGMiner
        'ethminer.exe',       # Ethminer
        'phoenixminer.exe',   # PhoenixMiner
        'nanominer.exe',      # NanoMiner
        'nbminer.exe',        # NbMiner
        'lolminer.exe',       # lolMiner
        # Credential harvesting / post-exploitation
        'mimikatz.exe',
        'mimilib.exe',
        'wce.exe',            # Windows Credential Editor
        'fgdump.exe',
        'pwdump.exe',
        'lazagne.exe',        # LaZagne
        # Remote access / C2 tools
        'meterpreter.exe',
        # nc.exe and ncat.exe intentionally omitted — too generic.
        # 'nc.exe' conflicts with legitimate Netcat usage by sysadmins and
        # security researchers; 'ncat.exe' ships with Nmap itself.
        # Flag the network connection instead, not the binary name.
        'socat.exe',
        # plink.exe intentionally omitted — PuTTY link is a standard SSH
        # tool installed by millions of legitimate users.
        # Reconnaissance
        'bloodhound.exe',
        'sharphound.exe',
        'powerview.exe',
        # Ransomware common drop names
        'wanakiwi.exe',
        'wannacry.exe',
        'notpetya.exe',
        'locky.exe',
    }
    
    # Suspicious Parent-Child Relationships
    SUSPICIOUS_PARENTS = {
        'explorer.exe': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'],
        'svchost.exe': ['cmd.exe', 'powershell.exe'],
        'winlogon.exe': ['cmd.exe', 'powershell.exe']
    }
    
    # Suspicious Paths
    SUSPICIOUS_PATHS = [
        'temp', 'tmp', 'appdata\\local\\temp', 'appdata\\roaming',
        'downloads', 'desktop', 'public', 'recycler', 'cached', 
        'prefetch', 'assembly', 'installer', 'setup', 'update'
    ]
    
    def __init__(self, logger=None):
        super().__init__(name="ProcessFeatures", logger=logger)
    
    @staticmethod
    def extract_process_basename(proc_info: Dict[str, Any]) -> str:
        """
        Robustly extract the base executable name from process info.
        Handles full paths, normalizes case.
        
        Args:
            proc_info: Process dictionary containing 'path' and/or 'image_name'
            
        Returns:
            Lowercase base name (e.g., 'msedge.exe')
        """
        # Try path first (most reliable)
        path = proc_info.get('path', '')
        if path:
            # Handle both Windows and Unix path separators
            basename = os.path.basename(path.replace('\\', os.sep))
            if basename:
                return basename.lower()
        
        # Fall back to image_name
        image_name = proc_info.get('image_name', '')
        if image_name:
            return image_name.lower()
        
        return ''
    
    @staticmethod
    def is_browser_process(proc_info: Dict[str, Any]) -> bool:
        """Check if a process is a known browser.

        IMPORTANT: check image_name FIRST, before the path-derived basename.
        When a browser DTB is swapped the path field may read as a completely
        different binary (e.g. msedge.exe showing path = FTK Imager.exe).
        extract_process_basename() prefers the path, so it would return
        'ftk imager.exe' instead of 'msedge.exe', causing the browser to fall
        out of browser_pids and hit MALWARE_PATH_PATTERNS.
        """
        # 1. Direct image_name check — most reliable; set by the EPROCESS scanner
        image_name = proc_info.get('image_name', '').lower()
        if image_name in ProcessFeatures.BROWSER_WHITELIST:
            return True
        # 2. Path-derived basename — fallback for edge-cases where image_name absent
        basename = ProcessFeatures.extract_process_basename(proc_info)
        return basename in ProcessFeatures.BROWSER_WHITELIST
    
    def extract_features(self, parsed_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Main entry point for process feature extraction.
        Extract 25 process features from parsed memory data.
        """
        processes = parsed_data.get('processes', [])
        
        if not processes:
            self.logger.warning(f"[{self.name}] No processes found in parsed_data")
            return self._get_zero_features()
        
        # Build lookup map for O(1) parent lookups
        pid_map = {p['pid']: p for p in processes}
        total_processes = len(processes)
        
        # Pre-identify browser processes for fast lookup
        browser_pids = {pid for pid, proc in pid_map.items() if self.is_browser_process(proc)}
        
        features = {}
        
        # ── Known-malicious process name check ────────────────────────────────
        # Run before all other feature extraction so that tags are present
        # for downstream propagation steps.
        known_bad_count = 0
        for proc in processes:
            proc_base = self.extract_process_basename(proc)
            if proc_base in self.KNOWN_MALICIOUS_PROCESSES:
                known_bad_count += 1
                self._tag_process(proc, f"KNOWN MALICIOUS PROCESS: {proc_base}")
                self.logger.warning(
                    f"[{self.name}] Known-malicious process detected: "
                    f"{proc_base} (PID {proc.get('pid','?')})"
                )
        if known_bad_count:
            self.logger.warning(
                f"[{self.name}] {known_bad_count} known-malicious process(es) found"
            )

        # Extract features with browser awareness
        features.update(self._extract_hidden_features(processes, total_processes, browser_pids))
        features.update(self._extract_orphan_features(processes, pid_map, total_processes, browser_pids))
        features.update(self._extract_parent_child_features(processes, pid_map, total_processes, browser_pids))
        features.update(self._extract_path_name_features(processes, total_processes, browser_pids, pid_map))
        features.update(self._extract_privilege_features(processes, total_processes))
        features.update(self._extract_behavioral_features(processes, total_processes))
        features.update(self._count_known_malicious(processes))
        
        # [FIX — Issue #3] Propagate suspicion from parent to child processes.
        # This catches e.g. rundll32.exe (PID 7732) which is a direct child of
        # oneetx.exe (PID 5896) and looks clean in isolation.
        self._propagate_parent_suspicion(processes, pid_map)
        
        return features

    def _tag_process(self, proc: Dict, anomaly_msg: str):
        """
        Helper method to tag a process dictionary with an anomaly string.
        This modifies the 'proc' object in-place so the UI can display the reason.
        """
        if 'anomalies' not in proc:
            proc['anomalies'] = []
        
        if anomaly_msg not in proc['anomalies']:
            proc['anomalies'].append(anomaly_msg)
        
        current_status = proc.get('status', 'CLEAN')
        if current_status == 'CLEAN':
            proc['status'] = 'SUSPICIOUS'
    
    def _extract_hidden_features(self, processes: List[Dict], total: int, browser_pids: set) -> Dict[str, float]:
        """Extract features related to hidden process detection.

        Reads boolean flags stamped by eprocess_scanner.find_all_processes()
        (found_by_pool, found_by_links, dkom_detected, hidden) as the primary
        signal source.  Falls back to checking anomaly strings for backwards
        compatibility with callers that have not yet been updated to stamp flags.
        """
        hidden_count    = 0
        unlinked_count  = 0
        dkom_indicators = 0
        pool_only_count = 0

        # Anomaly substrings written by detect_dkom() — used as string fallback
        _DKOM_STRINGS = {
            "DKOM",
            "unlinked from ActiveProcessLinks",
            "Unlinked (DKOM)",
            "DKOM Artifact",
            "Pool Scan Only",
        }

        for p in processes:
            pid = p.get('pid', 0)

            # Skip browsers for hidden process detection
            if pid in browser_pids:
                continue

            # ── Primary path: boolean flags set by eprocess_scanner Phase 4 ──
            is_hidden        = p.get('hidden', False)
            is_unlinked      = p.get('unlinked', False)
            is_dkom          = p.get('dkom_detected', False)
            is_pool_only     = (
                p.get('found_by_pool', False) and not p.get('found_by_links', True)
            )

            # ── Fallback: derive from anomaly strings when flags are absent ──
            # This handles callers that call detect_dkom() externally and only
            # append the anomaly string without setting the structured flags.
            if not (is_hidden or is_unlinked or is_dkom or is_pool_only):
                anomalies = p.get('anomalies', [])
                for a in anomalies:
                    if any(kw in a for kw in _DKOM_STRINGS):
                        if 'Pool Scan Only' in a:
                            is_pool_only = True
                        else:
                            is_dkom   = True
                            is_hidden = True   # DKOM hiding implies hidden
                        break

            if is_hidden:
                hidden_count += 1
                self._tag_process(p, "Hidden Process")

            if is_unlinked:
                unlinked_count += 1
                self._tag_process(p, "Unlinked (DKOM)")

            if is_dkom:
                dkom_indicators += 1
                self._tag_process(p, "DKOM Artifact")

            if is_pool_only:
                pool_only_count += 1
                self._tag_process(p, "Pool Scan Only")

        return {
            'hidden_process_count':   self.normalize_count(hidden_count,    max_threshold=3),
            'hidden_process_ratio':   self.normalize_ratio(hidden_count,    total),
            'unlinked_process_count': self.normalize_count(unlinked_count,  max_threshold=2),
            'dkom_indicator_count':   self.normalize_count(dkom_indicators, max_threshold=2),
            'pool_scan_only_count':   self.normalize_count(pool_only_count, max_threshold=3),
        }
    
    def _extract_orphan_features(self, processes: List[Dict], pid_map: Dict[int, Dict],
                                 total: int, browser_pids: set) -> Dict[str, float]:
        """
        Extract features related to orphan processes.
        FIXED: Browsers NEVER count as orphans due to multi-process architecture.
        FIXED: smss-spawned processes (csrss, wininit, winlogon) are NEVER orphans.
               smss.exe spawns session-specific child processes and then exits by design.
               Their parent PIDs (secondary smss instances) will never appear in any
               memory snapshot because those smss instances exit immediately after
               spawning. Flagging csrss/wininit/winlogon as orphans is always a FP.
        """
        orphan_count = 0
        system_orphan_count = 0

        # Safe orphans: legitimate processes whose parents exit before snapshot.
        # This list mirrors the SAFE_ORPHANS in eprocess_scanner.py — keep in sync.
        #
        # Key Windows design facts behind this list:
        #   • services.exe pages out frequently on busy Win10/11 systems (64+ procs).
        #     ALL its children (svchost, spoolsv, msdtc, etc.) then appear orphaned.
        #   • secondary smss.exe exits immediately after spawning csrss/wininit/winlogon.
        #   • userinit.exe exits by design after spawning explorer.exe.
        #   • UWP / COM-activated processes (RuntimeBroker, GameBar, Widgets …) are
        #     suspended/resumed by the UWP lifetime manager; their recorded parent
        #     PIDs frequently point to COM surrogate instances that have already exited.
        SAFE_ORPHANS = {
            # smss-spawned — parent (secondary smss) exits immediately
            'csrss.exe', 'wininit.exe', 'winlogon.exe',
            # services.exe children — services.exe pages out; all children appear orphaned
            'svchost.exe',              # MOST COMMON FALSE POSITIVE (13+ per scan)
            'spoolsv.exe',
            'msdtc.exe',
            'vds.exe',
            'vssvc.exe',
            'dllhost.exe',
            'conhost.exe',
            'taskhostw.exe',
            'taskhost.exe',
            'wmiprvse.exe',             # WMI Provider Host
            # Other transient parents
            'tiworker.exe', 'audiodg.exe', 'werfault.exe', 'wermgr.exe',
            'sgrmbroker.exe', 'useroobebroker.exe', 'searchindexer.exe',
            'smss.exe', 'registry', 'secure system', 'memcompression.exe',
            # Updater/sync — manager parents exit first
            'onedrive.exe',
            'onedrive.sync.exe',        # truncated from OneDrive.Sync.Root.exe
            'microsoftedgeu.exe',       # truncated from MicrosoftEdgeUpdate.exe
            # userinit.exe exits immediately after spawning explorer — always orphaned
            'userinit.exe',
            # UWP / Shell infrastructure — COM activation; parent PIDs frequently stale
            'runtimebroker.exe',
            'sihost.exe',               # Shell Infrastructure Host
            'ctfmon.exe',               # CTF Input Method Manager
            'startmenuexper.exe',       # truncated StartMenuExperienceHost
            'dataexchangeho.exe',       # truncated DataExchangeHost
            'shellhost.exe',
            'gamebar.exe',
            'gamebarft.exe',
            'widgets.exe',
            'crossdeviceres.exe',       # truncated CrossDeviceService
            'backgroundtran.exe',       # truncated BackgroundTransferHost
            'usoclient.exe',
            'smartscreen.exe',
            'smartscreen.ex.exe',       # truncated smartscreen.exe
            'olk.exe',                  # Outlook (new, UWP-hosted)
            'msedgewebview2.exe',
            # Search
            'searchfilterho.exe',       # truncated SearchFilterHost
            'searchprotocol.exe',       # truncated SearchProtocolHost
            # Search UI host (separate from SearchIndexer)
            'searchhost.exe',
            # Full (non-truncated) names — extract_process_basename returns these
            # when the process has a resolvable path in the snapshot
            'startmenuexperiencehost.exe',
            'dataexchangehost.exe',
            'backgroundtransferhost.exe',
            'crossdeviceservice.exe',
            'searchfilterhost.exe',
            'searchprotocolhost.exe',
            # Acquisition tools — parent (explorer) may have been frozen at snapshot
            'dumpit.exe',
            'ftkimager.exe',
            'winpmem.exe',
            'rammap.exe',
        }

        for proc in processes:
            ppid = proc.get('ppid', 0)
            pid  = proc.get('pid', 0)

            proc_base = self.extract_process_basename(proc)

            # Browsers never count as orphans
            if pid in browser_pids:
                if ppid not in pid_map and ppid > 0:
                    # [FIX P1-browser] Store as a parse note, NOT in anomalies.
                    # Downstream classifiers treat len(anomalies) > 0 as SUSPICIOUS,
                    # so adding info tags here directly caused 12 browser FPs per run.
                    proc.setdefault('info_notes', []).append("Browser Multi-Process (Normal)")
                continue

            if pid <= 4:
                continue

            # Orphan: parent PID doesn't exist in process list
            if ppid not in pid_map and ppid > 0:
                # Whitelist check
                if proc_base in SAFE_ORPHANS:
                    continue

                orphan_count += 1
                self._tag_process(proc, "Orphan Process (Parent Missing)")

                # System processes with unexpected orphan status ARE suspicious —
                # but only if they are NOT in the known-safe smss-spawn list above.
                # (csrss/wininit/winlogon are already filtered out above.)
                if proc_base in self.SYSTEM_PROCESSES:
                    system_orphan_count += 1
                    self._tag_process(proc, "System Orphan (CRITICAL)")

        return {
            'orphan_process_count': self.normalize_count(orphan_count, max_threshold=5),
            'orphan_process_ratio': self.normalize_ratio(orphan_count, total),
            'system_orphan_count':  self.normalize_count(system_orphan_count, max_threshold=2)
        }
    
    def _extract_parent_child_features(self, processes: List[Dict], pid_map: Dict[int, Dict], 
                                      total: int, browser_pids: set) -> Dict[str, float]:
        """Extract features related to parent-child relationship anomalies."""
        suspicious_parent_child = 0
        wrong_parent_path = 0
        unusual_system_children = 0
        ppid_spoofing = 0
        svchost_wrong_parent = 0
        
        # Legitimate system children (should not trigger PPID spoofing)
        LEGITIMATE_SYSTEM_CHILDREN = {
            'registry.exe', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'winlogon.exe', 'svchost.exe',
            'dwm.exe', 'fontdrvhost.exe', 'sihost.exe', 'taskhostw.exe',
            'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe', 'conhost.exe',
            'spoolsv.exe', 'audiodg.exe', 'searchui.exe', 'shellexperiencehost.exe',
            'mscorsvw.exe', 'wmiadap.exe', 'wuauclt.exe', 'explorer.exe',
            'scvhost.exe', 'memcompression.exe', 'lsaiso.exe', 'tiworker.exe'
        }

        # Processes whose parent-child create-time ordering is legitimately
        # non-deterministic and should NEVER trigger PPID spoofing alerts:
        #   - Windows Defender components start at a privileged early boot phase
        #     independently of their host service, so their timestamps may predate
        #     the services.exe entry in the snapshot.
        #   - UWP / Store apps (ShellExperienceHost, TextInputHost, RuntimeBroker,
        #     etc.) are suspended and resumed by the UWP lifetime manager; their
        #     recorded CreateTime reflects first-launch, not the current parent's
        #     start time.
        #   - Truncated names (14-char ImageFileName field): the .exe suffix was
        #     appended by the parser, so we match on the base name.
        PPID_SPOOFING_WHITELIST = {
            # Windows Defender / Security
            'msmpeng.exe', 'nissrv.exe', 'mssense.exe', 'mpcmdrun.exe',
            'securityhealthservice.exe', 'securityheal.exe',
            # UWP / Shell infrastructure (truncated names included)
            'shellexperienc.exe',   # ShellExperienceHost (truncated)
            'startmenuexper.exe',   # StartMenuExperienceHost (truncated)
            'applicationfra.exe',   # ApplicationFrameHost (truncated)
            'textinputhost.exe',
            'runtimebroker.exe',
            'searchapp.exe',
            'skypebackgroun.exe',   # SkypeBackgroundHost (truncated)
            # Outlook / Office helpers
            'hxtsr.exe',
            # Miscellaneous UWP companion processes
            'yourphone.exe', 'phone.exe',
        }
        
        for proc in processes:
            ppid = proc.get('ppid', 0)
            pid = proc.get('pid', 0)
            proc_name = self.extract_process_basename(proc)
            
            # CRITICAL: Skip browsers entirely for parent-child checks
            if pid in browser_pids:
                continue
            
            if ppid in pid_map:
                parent = pid_map[ppid]
                parent_name = self.extract_process_basename(parent)
                
                # Skip if parent is a browser (browser spawning other processes is normal)
                if ppid in browser_pids:
                    continue
                
                # Check svchost.exe parent
                if proc_name == 'svchost.exe':
                    # Valid parents: services.exe (normal), System/PID-4 (services.exe
                    # paged out — the orphan-adoption code in eprocess_scanner re-parents
                    # it to PID 4, so 'system' appearing here is NOT suspicious).
                    valid_svchost_parent = (
                        'services' in parent_name or
                        parent.get('pid') == 4 or
                        parent_name in ('system', 'registry')
                    )
                    if not valid_svchost_parent:
                        svchost_wrong_parent += 1
                        self._tag_process(proc, f"Wrong Parent: {parent_name}({ppid})")
                
                # Suspicious parent-child relationship
                if parent_name in self.SUSPICIOUS_PARENTS:
                    if any(child in proc_name for child in self.SUSPICIOUS_PARENTS[parent_name]):
                        suspicious_parent_child += 1
                        self._tag_process(proc, "Suspicious Parent")
                
                # PPID Spoofing Detection (Time Anomaly)
                proc_create_time = proc.get('create_time', 0)
                parent_create_time = parent.get('create_time', 0)
                
                if proc_create_time > 0 and parent_create_time > 0:
                    is_legitimate_system_child = proc_name in LEGITIMATE_SYSTEM_CHILDREN
                    is_ppid_spoof_exempt      = proc_name in PPID_SPOOFING_WHITELIST
                    is_parent_system = parent.get('pid') == 4
                    is_parent_idle = parent.get('pid') == 0
                    
                    if (not is_legitimate_system_child and
                        not is_ppid_spoof_exempt and
                        not is_parent_system and 
                        not is_parent_idle and
                        proc_create_time < parent_create_time):
                        ppid_spoofing += 1
                        self._tag_process(proc, "PPID Spoofing (Time Anomaly)")
        
        return {
            'svchost_wrong_parent_count': self.normalize_count(svchost_wrong_parent, max_threshold=1),
            'suspicious_parent_child_count': self.normalize_count(suspicious_parent_child, max_threshold=3),
            'wrong_parent_path_count': self.normalize_count(wrong_parent_path, max_threshold=2),
            'unusual_system_children_count': self.normalize_count(unusual_system_children, max_threshold=5),
            'ppid_spoofing_count': self.normalize_count(ppid_spoofing, max_threshold=2),
            'parent_child_anomaly_ratio': self.normalize_ratio(
                suspicious_parent_child + wrong_parent_path + ppid_spoofing, total
            )
        }
    
    @staticmethod
    def _is_garbled_path(path: str) -> bool:
        """
        Detect garbled Unicode paths caused by bad DTB reads.

        When the address translator uses a stale or wrong DTB, the PEB path
        buffer it reads contains random kernel/physical memory bytes decoded
        as UTF-16-LE. The result is a string full of CJK characters, control
        characters, or other non-path codepoints — NOT a real Windows path.

        Heuristic: if more than 15% of characters are outside the printable
        ASCII range for filesystem paths (0x20–0x7E, plus backslash U+005C),
        the path is garbled and should be silently discarded rather than
        flagged as "Unexpected Path".
        """
        if not path or len(path) < 3:
            return False
        # Allow printable ASCII + common Unicode in legitimate paths
        # (e.g. accented chars in user profile names)
        ALLOWED = set(range(0x20, 0x7F)) | {ord('\\'), ord('/'), ord(':'),
                                             ord('.'), ord(' '), ord('-'),
                                             ord('_'), ord('('), ord(')')}
        weird = sum(1 for c in path if ord(c) > 0x7E and ord(c) not in ALLOWED)
        return weird > max(2, len(path) * 0.15)

    def _extract_path_name_features(self, processes: List[Dict], total: int, browser_pids: set, pid_map: Dict[int, Dict] = None) -> Dict[str, float]:
        """Extract features related to process path and name anomalies."""
        suspicious_path_count = 0
        missing_path_count = 0
        typosquat_count = 0
        malware_path_count = 0  # [NEW] High-confidence malware paths
        
        name_counts = defaultdict(int)
        
        # Whitelist of processes that frequently lack paths in RAM
        KERNEL_NOISE = {
            'system', 'registry.exe', 'smss.exe', 'csrss.exe', 'wininit.exe', 
            'services.exe', 'lsm.exe', 'winlogon.exe', 'memcompression.exe', 
            'lsaiso.exe', 'lsass.exe', 'audiodg.exe',
            # Transient session-setup processes — always exit before snapshot:
            'userinit.exe',
            # IME loader and search indexer — path routinely paged out:
            'ctfmon.exe',
            'searchindexer.exe',
            # UWP / Shell infrastructure — PEB path paged out in most snapshots:
            'runtimebroker.exe',
            'shellexperienc.exe',   # ShellExperienceHost (truncated)
            'applicationfra.exe',   # ApplicationFrameHost (truncated)
            'skypebackgroun.exe',   # SkypeBackgroundHost (truncated)
            'hxtsr.exe',            # Outlook companion
            # dllhost / taskhostw host COM objects and tasks on demand:
            'dllhost.exe',
            'taskhostw.exe',
            # Forensic / acquisition tools:
            'ftk imager.exe',
            # [FIX P1-noise] Additional processes whose PEB path is frequently evicted.
            'vm3dservice.exe',      # VMware 3D display service (user-session copy)
            'wuauclt.exe',          # Windows Update agent
            'filecoauth.exe',       # OneDrive file co-authoring
            'mousocoreworker',      # (truncated) MoUsoCoreWorker.exe — WU orchestrator
            'aggregatorhost.exe',   # Aggregator Host for Windows telemetry
            'sppextcomobj.exe',     # Software Protection
            'sppsvc.exe',           # Software Protection service
            'searchprotocol',       # (truncated) SearchProtocolHost
            'searchfilterho',       # (truncated) SearchFilterHost
            'microsoftedgeu',       # (truncated) MicrosoftEdgeUpdate
            'securityhealths',      # (truncated) SecurityHealthService
            'securityhealtht',      # (truncated) SecurityHealthSystray
            'trustedinstall',       # (truncated) TrustedInstaller
            'tiworker.exe',         # Windows Installer worker
            'msdtc.exe',            # Distributed Transaction Coordinator
            'fontdrvhost.ex',       # (truncated) Font Driver Host
            'dwm.exe',              # Desktop Window Manager
            'sihost.exe',           # Shell Infrastructure Host
            'useroobebroker',       # (truncated) UserOOBEBroker
            'wmiprvse.exe',         # WMI Provider Host
            'conhost.exe',          # Console Host
            'vgauthservice.',       # (truncated) VGAuthService — VMware
            'vmtoolsd.exe',
            'nissrv.exe',           # Microsoft Network Inspection
            'mpdefendercore',       # (truncated) MpDefenderCoreService
            'msmpeng.exe',          # Windows Defender
            'freesshdsevic',        # (truncated) FreeSSHDService
            # Forensic / acquisition tools — PEB path is in Downloads/Desktop (normal)
            'dumpit.exe',
            'ftkimager.exe',
            'ftk imager.exe',
            'accessdata_ftk.exe',       # FTK Imager installer process (truncated name)
            'accessdata_ftk_imager.exe',
            'winpmem.exe',
            'winpmem_mini_x64.exe',
            'winpmem_x64.exe',
            'rammap.exe',
            'procdump.exe',
            'livekd.exe',
            # Windows OOBE (Out-of-Box Experience) — spawned during setup/updates,
            # always orphaned (parent is smss.exe which exits), always missing path.
            'msoobe.exe',
            'msoobebe.exe',             # variant name seen on some Win11 builds
        }

        # [FIX P1-service] Children of these processes have their PEB path routinely
        # evicted by the memory manager after initialisation.  A missing path for
        # any of their direct children is normal — flagging it generates ~32 FPs.
        SERVICE_TIER_PARENTS = {'services.exe', 'svchost.exe'}

        # [FIX] Additional processes whose paths are routinely evicted.
        # Adding them here prevents "Missing Path (Possible Hollowing)" FPs
        # for UWP/shell processes and services whose PEB is never resolved.
        _EXTENDED_KERNEL_NOISE = {
            'svchost.exe', 'taskhostw.exe', 'taskhost.exe',
            'sihost.exe', 'runtimebroker.exe', 'startmenuexper.exe',
            'shellhost.exe', 'gamebar.exe', 'gamebarft.exe', 'widgets.exe',
            'backgroundtran.exe', 'crossdeviceres.exe', 'dataexchangeho.exe',
            'usoclient.exe', 'smartscreen.exe', 'smartscreen.ex.exe',
            'olk.exe', 'msedgewebview2.exe', 'wmiprvse.exe',
            'searchfilterho.exe', 'searchprotocol.exe',
            'consent.exe',          # UAC consent host — spawned on demand
            'userinit.exe',         # exits immediately — PEB always freed
            'dumpit.exe', 'ftkimager.exe', 'ftk imager.exe',
            'accessdata_ftk.exe', 'accessdata_ftk_imager.exe',
            'winpmem.exe', 'rammap.exe',
            # Windows OOBE — always orphaned (smss.exe exits after spawning it)
            'msoobe.exe', 'msoobebe.exe',
        }
        
        # [NEW] High-confidence malware path patterns
        # These patterns are ALMOST NEVER legitimate
        MALWARE_PATH_PATTERNS = [
            # Direct execution from temp (malware hallmark)
            r'\\temp\\[^\\]+\.exe$',
            r'\\windows\\temp\\[^\\]+\.exe$',
            
            # AppData with random hex/number folders
            r'\\appdata\\[^\\]+\\[a-f0-9]{16,}\\.*\.exe$',
            r'\\users\\[^\\]+\\appdata\\local\\temp\\[a-f0-9]+\\.*\.exe$',
            
            # Downloads folder execution (malware often drops here)
            r'\\users\\[^\\]+\\downloads\\.*\.exe$',
            r'\\users\\[^\\]+\\desktop\\.*\.exe$',
            
            # Recycler/Trash folders
            r'\\recycler\\[^\\]+\.exe$',
            r'\\\$recycle\.bin\\[^\\]+\.exe$',
            
            # System folder impersonation: long random hex/alphanum name in System32.
            # GUARD: skip known-safe executables that have long legitimate names
            # (e.g. securityhealthservice.exe = 26 chars, all alpha — not a hash).
            # The pattern only fires if the name contains hex-looking chars (0-9 + a-f
            # exclusively) OR is an obvious random string (mixed digits mid-name).
            r'\\windows\\system32\\[a-f0-9]{16,}\.exe$',  # pure hex names only
            r'\\program files\\(x86\\)?[^\\]+\\[a-f0-9]{16,}\.exe$',
        ]

        # Known-safe executables with long names that could otherwise match the
        # system32 pattern.  Checked before any MALWARE_PATH_PATTERNS test.
        SYSTEM32_SAFE_NAMES = {
            'securityhealthservice.exe', 'securityheal.exe',
            'trustedinstaller.exe',
            'windowsazureguestagent.exe',
            'microsoftedgeupdate.exe',
        }
        
        # [NEW] Low-risk paths that might be false positives
        LOW_RISK_PATHS = [
            'appdata\\local\\microsoft\\edge',  # Edge user data
            'appdata\\local\\google\\chrome',   # Chrome user data
            'appdata\\local\\mozilla\\firefox', # Firefox user data
            'appdata\\roaming\\microsoft\\windows\\start menu',
            'appdata\\roaming\\microsoft\\internet explorer',
        ]

        for proc in processes:
            path = proc.get('path', '').lower()
            pid = proc.get('pid', 0)
            proc_name = self.extract_process_basename(proc)
            
            if 'anomalies' not in proc:
                proc['anomalies'] = []

            name_counts[proc_name] += 1
            
            # Typosquatting check
            if proc_name in ['svch0st.exe', 'lsasss.exe', 'csrsss.exe', 'explorrer.exe', 'scvhost.exe']:
                typosquat_count += 1
                self._tag_process(proc, "Typosquat Name")

            # Missing path detection with noise filter
            if not path or path == '-':
                # CRITICAL: Browsers are whitelisted (heavy paging)
                is_browser = pid in browser_pids
                is_kernel = proc_name in KERNEL_NOISE or proc_name in _EXTENDED_KERNEL_NOISE or pid <= 4

                # [FIX P1-service] Direct children of services.exe / svchost.exe
                # have their PEB path routinely evicted — not a suspicious signal.
                ppid = proc.get('ppid', 0)
                parent_name = pid_map.get(ppid, {}).get('image_name', '').lower() if pid_map and pid_map.get(ppid) else ''
                is_service_child = parent_name in SERVICE_TIER_PARENTS

                if is_browser:
                    # [FIX P1-browser] Store as info note, NOT in anomalies
                    proc.setdefault('info_notes', []).append("Info: Browser Memory Paged")
                elif is_kernel or is_service_child:
                    pass  # Normal for kernel processes and service-tier children
                else:
                    # Real threat: user process missing path
                    missing_path_count += 1
                    self._tag_process(proc, "Missing Path (Possible Hollowing)")
                continue

            # [FIX] Detect garbled Unicode from bad DTB reads BEFORE any other check.
            # A corrupted path (e.g. "纉䠐ꮋƠ\x00蕈...") is a parser artifact, not an
            # anomaly. eprocess_scanner may have already added "Unexpected Path" for
            # this process — strip that tag and ensure status ends up CLEAN.
            #
            # IMPORTANT: do NOT append to proc['anomalies'] here. Any downstream
            # aggregator that checks len(anomalies) > 0 would re-assert SUSPICIOUS.
            # Instead, store the diagnostic note in proc['parse_artifacts'] which is
            # ignored by all status-setting code, then hard-clear anomalies if no
            # real issues remain.
            if self._is_garbled_path(path):
                # Strip Unexpected Path added by eprocess_scanner for this garble
                proc['anomalies'] = [
                    a for a in proc.get('anomalies', [])
                    if 'Unexpected Path' not in a
                ]
                # Store diagnostic note outside anomalies
                proc.setdefault('parse_artifacts', []).append(
                    "Garbled Path (DTB Read Artifact - not a real anomaly)"
                )
                # Real anomalies = anything that is NOT a parse artifact
                real_anomalies = [
                    a for a in proc['anomalies']
                    if 'DTB Read Artifact' not in a
                    and 'Browser' not in a
                    and 'Invalid/Swapped DTB' not in a
                ]
                if not real_anomalies:
                    # Hard-clear: remove even the Invalid/Swapped DTB tag since it
                    # was caused by the same bad DTB that produced the garbled path.
                    # Empty anomalies list guarantees all downstream code sees CLEAN.
                    proc['anomalies'] = []
                    proc['status'] = 'CLEAN'
                continue
            
            # [CRITICAL] Skip browser processes entirely for path checks
            # Browsers can have weird paths but aren't malware
            if pid in browser_pids:
                continue
            
            # [NEW] High-confidence malware path detection.
            # GUARD: skip executables whose long legitimate names would otherwise
            # match the system32 hex-name pattern (e.g. SecurityHealthService.exe).
            is_malware_path = False
            # [FIX] Skip forensic / IR tools before applying MALWARE_PATH_PATTERNS.
            # DumpIt, FTK Imager, winpmem etc. legitimately run from Downloads/Desktop.
            # They match the downloads-pattern rule but are NOT malware.
            _FORENSIC_TOOL_NAMES = {
                'dumpit.exe', 'ftkimager.exe', 'winpmem.exe',
                'winpmem_mini_x64.exe', 'winpmem_mini_x86.exe',
                'winpmem_x64.exe', 'winpmem_x86.exe',
                'rammap.exe', 'procdump.exe', 'livekd.exe',
                'volatility.exe', 'volatility3.exe',
                'memorize.exe', 'belkasoft ram capturer.exe',
                'magnet ram capture.exe', 'magnetramcapture.exe',
                'rekal.exe', 'rekall.exe',
                # RAMDetect itself
                'ramdetect.exe', 'ramdetect_gui.exe',
                # FTK Imager installer/launcher variants — Windows truncates the
                # image_name to 15 chars in EPROCESS, producing these names:
                'accessdata_ftk.exe',         # AccessData_FTK_Imager_4.x.x.exe → truncated
                'accessdata_ftk_imager.exe',  # Full name when path is available
                'ftk imager.exe',             # Space-separated display name
                'ftk_imager.exe',
            }

            # Stem-prefix matching — catches versioned filenames like
            # "AccessData_FTK_Imager_4.7.1.exe" that don't exact-match the set above.
            # A forensic tool is identified if its stem starts with any known prefix.
            _FORENSIC_STEM_PREFIXES = (
                'accessdata_ftk',   # AccessData_FTK_Imager_4.7.1.exe, AccessData_FTK.exe …
                'winpmem_',         # winpmem_mini_x64_3.1.exe etc.
                'dumpit_',          # DumpIt_v3.exe etc.
                'ftk_imager_',      # ftk_imager_4.7.exe etc.
            )

            def _is_forensic_tool(name: str) -> bool:
                """Return True if name matches a known forensic tool exactly or by prefix."""
                if name in _FORENSIC_TOOL_NAMES:
                    return True
                stem = name[:-4] if name.endswith('.exe') else name  # strip .exe
                return stem.startswith(_FORENSIC_STEM_PREFIXES)

            if proc_name not in SYSTEM32_SAFE_NAMES and not _is_forensic_tool(proc_name):
                for pattern in MALWARE_PATH_PATTERNS:
                    import re
                    if re.search(pattern, path):
                        is_malware_path = True
                        break
            
            if is_malware_path:
                malware_path_count += 1
                self._tag_process(proc, "MALWARE PATH PATTERN (High Confidence)")
                continue  # Skip other checks - this is already high confidence
            
            # [NEW] Check if it's a low-risk path (possible false positive)
            # Store as an info note rather than an anomaly — this path pattern
            # appears in normal browser / Office data directories and should
            # NOT set status=SUSPICIOUS or contribute to anomaly counts.
            is_low_risk = any(low_risk in path for low_risk in LOW_RISK_PATHS)
            if is_low_risk:
                proc.setdefault('info_notes', []).append(
                    "Suspicious Path (Low Risk — Browser/Office Data, not scored)"
                )
                continue
            
            # Regular suspicious location check.
            # [FIX — TrustedInstaller FP] Test only the DIRECTORY portion of the path.
            # [FIX — Forensic tools] Skip DumpIt/FTK Imager in Downloads — not malware.
            # [FIX — Bug 4] Also exclude from the secondary SUSPICIOUS_PATHS check;
            # without this a forensic tool that passes _FORENSIC_TOOL_NAMES at the
            # MALWARE_PATH_PATTERNS stage still hits 'downloads' in SUSPICIOUS_PATHS.
            if not _is_forensic_tool(proc_name):
                path_dir = path.rsplit('\\', 1)[0] if '\\' in path else path
                if any(susp in path_dir for susp in self.SUSPICIOUS_PATHS):
                    suspicious_path_count += 1
                    self._tag_process(proc, "Suspicious Path Location")
        
        # Duplicate system process check
        duplicate_system_process_count = 0
        for name, count in name_counts.items():
            if name in self.SYSTEM_PROCESSES and count > 1:
                if name != 'svchost.exe':
                    duplicate_system_process_count += (count - 1)

        return {
            'suspicious_path_count': self.normalize_count(suspicious_path_count, max_threshold=5),
            'missing_path_count': self.normalize_count(missing_path_count, max_threshold=3),
            'typosquat_count': self.normalize_count(typosquat_count, max_threshold=2),
            'duplicate_system_process_count': self.normalize_count(duplicate_system_process_count, max_threshold=2),
            'malware_path_pattern_count': self.normalize_count(malware_path_count, max_threshold=3)  # [NEW]
        }
    
    def _extract_privilege_features(self, processes: List[Dict], total: int) -> Dict[str, float]:
        """Extract features related to privilege escalation."""
        return {
            'elevated_privilege_count': 0.0,
            'debug_privilege_count': 0.0,
            'admin_token_ratio': 0.0,
            'system_token_ratio': 0.0
        }
    
    def _extract_behavioral_features(self, processes: List[Dict], total: int) -> Dict[str, float]:
        """Extract behavioral indicators."""
        suspicious_cmdline_count = 0
        
        SUSPICIOUS_PATTERNS = [r'powershell.*-enc', r'cmd.*\/c']
        
        for proc in processes:
            cmdline = proc.get('cmdline', '').lower()
            if any(re.search(p, cmdline) for p in SUSPICIOUS_PATTERNS):
                suspicious_cmdline_count += 1
                self._tag_process(proc, "Suspicious Command Line")
                
        return {
            'code_injection_count': 0.0,
            'suspicious_cmdline_count': self.normalize_count(suspicious_cmdline_count, max_threshold=5),
            'no_gui_process_count': 0.0,
            'short_lived_process_count': 0.0
        }
    
    def _count_known_malicious(self, processes: List[Dict]) -> Dict[str, float]:
        """Return known_malicious_process_count feature (already tagged in extract_features)."""
        count = sum(
            1 for p in processes
            if any('KNOWN MALICIOUS PROCESS' in a for a in p.get('anomalies', []))
        )
        return {
            'known_malicious_process_count': self.normalize_count(count, max_threshold=2)
        }
    
    def _propagate_parent_suspicion(self, processes: List[Dict], pid_map: Dict[int, Dict]):
        """
        Tag children whose direct parent has a STRONG suspicion signal.

        One level of propagation is intentional — deep cascading would produce
        false positives across large trees (e.g. every child of explorer.exe).

        STRONG signals (worth propagating):
          - MALWARE PATH PATTERN — process is executing from a known bad location
          - Orphan Process — no legitimate parent exists (unusual for real processes)
          - DKOM / Hidden / Unlinked — active evasion detected
          - Code injection, typosquat, wrong parent path

        WEAK signals (NOT propagated):
          - Missing Path (Possible Hollowing) alone — PEB path paged out is normal
            for dozens of legitimate Windows processes. Propagating this to all
            child threads generates the majority of thread FPs seen in testing.
          - Invalid/Swapped DTB alone — page-table paging artefact, not evasion.
          - Garbled Path (DTB Read Artifact) — parser artefact, already cleaned up.
          - Info — informational only (e.g. browser process memory paged).

        Called AFTER all other feature-extraction methods so that parent status
        is fully resolved before propagation begins.
        """
        STRONG_SIGNAL_KEYWORDS = {
            'MALWARE PATH PATTERN',
            'KNOWN MALICIOUS PROCESS',   # xmrig.exe, mimikatz.exe, etc.
            # 'Orphan Process' intentionally excluded — too broad.
            # A regular orphan (missing parent) is common when services.exe pages
            # out. Propagating it to all children turns 13–20 svchost children
            # into false positives on every clean Win10/11 dump.
            # Only the CRITICAL variant (system process orphaned in wrong context)
            # warrants child propagation.
            'System Orphan (CRITICAL)',
            'Hidden Process',
            'Unlinked (DKOM)',
            'DKOM Artifact',
            'Typosquat Name',
            'Wrong Parent',
            'Code Injection',
        }

        def _is_strongly_suspicious(proc: Dict) -> bool:
            if proc.get('status') != 'SUSPICIOUS':
                return False
            anomalies = proc.get('anomalies', [])
            return any(
                any(kw in a for kw in STRONG_SIGNAL_KEYWORDS)
                for a in anomalies
            )

        strongly_suspicious_pids = {
            p['pid'] for p in processes if _is_strongly_suspicious(p)
        }

        for proc in processes:
            ppid = proc.get('ppid', 0)
            if ppid in strongly_suspicious_pids:
                self._tag_process(proc, "Parent Process Suspicious")

    def _get_zero_features(self) -> Dict[str, float]:
        """Return zeroed features."""
        keys = [
            'hidden_process_count', 'hidden_process_ratio', 'unlinked_process_count', 
            'dkom_indicator_count', 'pool_scan_only_count',
            'orphan_process_count', 'orphan_process_ratio', 'system_orphan_count',
            'svchost_wrong_parent_count', 'suspicious_parent_child_count', 'wrong_parent_path_count', 
            'unusual_system_children_count', 'ppid_spoofing_count', 'parent_child_anomaly_ratio',
            'suspicious_path_count', 'missing_path_count', 'typosquat_count', 
            'duplicate_system_process_count', 'malware_path_pattern_count',
            'elevated_privilege_count', 'debug_privilege_count', 'admin_token_ratio', 
            'system_token_ratio',
            'code_injection_count', 'suspicious_cmdline_count', 'no_gui_process_count', 
            'short_lived_process_count',
            'known_malicious_process_count',  # xmrig.exe, mimikatz.exe, etc.
        ]
        return {k: 0.0 for k in keys}