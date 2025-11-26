from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
from typing import Optional, Any
import json
import hashlib

from colorama import Fore, Style

@dataclass
class FeedCache:
    name: str
    data_path: Path
    ttl_hours: int
    logger: Any
    
    @property
    def meta_path(self) -> Path:
        return self.data_path.with_suffix(self.data_path.suffix + ".meta")
    @property
    def sha_path(self) -> Path:
        return self.data_path.with_suffix(self.data_path.suffix + ".sha256")
    
    # ----------------- Meta Handling -----------------
    
    def load_meta(self) -> Optional[dict]:
        if not self.meta_path.exists():
            return None
        try:
            return json.loads(self.meta_path.read_text(encoding='utf-8'))
        except Exception as e:
            self.logger.print_warning(
                f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Meta file for {self.name} is corrupted; ignoring: {self.meta_path}. Error Trace: {e}"
            )
            return None
    
    def save_metadata_file(self, *, source_url: str, mode: str, validated: bool, checksum_src: str):
        now = datetime.now(timezone.utc).isoformat()
        
        meta = self.load_meta() or {}
        
        
        meta["feed"] = self.name
        meta.setdefault("created_at", now)
        meta["mode"] = mode
        meta["checksum_source"] = checksum_src
        meta["source_url"] = source_url
        meta["fetched_by"] = "Vulnparse-Pin v1.0RC"
        meta["validated_against_remote"] = validated
        
        # Write File
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding='utf-8')
        tail = "/".join(self.meta_path.parts[-2:])
        self.logger.print_success(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Metadata written to .../{tail}")
        
    def update_cache_meta(self) -> None:
        
        
        now = datetime.now(timezone.utc).isoformat()
        
        
        meta = self.load_meta() or {}
        
        
        # Ensure created_at exists. If not, create it.
        meta.setdefault("created_at", now)
        
        # Always refresh 'last_updated'
        meta["last_updated"] = now
        
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding='utf-8')
        tail = "/".join(self.meta_path.parts[-2:])
        self.logger.print_success(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Metadata update written to .../{tail}")
        
    def print_cache_metadata(self) -> None:
        meta = self.load_meta()
        if not meta:
            tail = "/".join(self.meta_path.parts[-2:])
            self.logger.print_warning(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} No meta file found for feed '{self.name}' at .../{tail}")
            return
        
        # Safely extract fields to report
        last_updated = meta.get("last_updated")
        created_at = meta.get("created_at")
        
        if last_updated:
            self.logger.print_info(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} {self.meta_path.name} last updated: {meta['last_updated']}")
        elif created_at:
            self.logger.print_info(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} {self.meta_path.name} created at: {meta['created_at']} (No 'last_updated' yet)")
        else:
            # Log warning about feed's meta file
            self.logger.print_warning(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Meta file for {self.name} exists, but contains no timestamp fields.")
    
    # ----------------- TTL Logic -----------------
    def is_fresh(self) -> bool:
        if self.ttl_hours <= 0:
            self.logger.logger.debug(f"[DEBUG] ttl is less than or equal to 0 : False")
            return False
        
        meta = self.load_meta()
        if not meta:
            self.logger.logger.debug(f"[DEBUG] .meta file cannot be found : False")
            return False
        
        last_raw = meta.get("last_updated") or meta.get("created_at")
        if not last_raw:
            self.logger.logger.debug(f"[DEBUG] No last raw timestamp : False")
            return False
        
        
        try:
            dt = datetime.fromisoformat(last_raw.replace("Z", "+00:00"))
        except Exception as e:
            self.logger.logger.debug(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Invalid last_updated timestamp in meta for Feed: {self.name}, Timestamp: {last_raw}, Error Trace: {e}.")
            return False
        
        now = datetime.now(timezone.utc)
        age = now - dt
        age_hours = age.total_seconds() / 3600.0
        self.logger.logger.debug(f"[DEBUG] {self.name} cache age={age_hours:.2f}h, ttl={self.ttl_hours}h")
        return age_hours <= float(self.ttl_hours)
    
    # ----------------- Checksum Logic -----------------
    def compute_checksum(self) -> str:
        h = hashlib.sha256()
        with self.data_path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    
    def ensure_feed_checksum(self, allow_regen: bool) -> bool:
        """
        Ensure checksum + meta exist and are consistent with the feed.

        Returns:
            True -> checksum verified and valid
            False -> checksum/state regenerated in best-effort mode
        Raises:
            RunTimeError on hard mismatch when allow_regen=False
        Returns True if checksum was verified against an existing .sha256,
        False if it has to generate local state (best-effort).
        Raises error on hard mismatch.
        """
        if not self.data_path.exists():
            raise FileNotFoundError(f"Feed {self.name} not found: {self.data_path}")
        
        # If checksum file exists, Validate the checksum
        if self.sha_path.exists():
            expected = self.sha_path.read_text(encoding='utf-8').strip().split()[0]
            actual = self.compute_checksum()
            
            # Diff Check
            if expected != actual:
                if not allow_regen:
                    self.logger.print_error(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Checksum mismatch for {self.data_path.name}")
                    # Refuse to use cache on mismatch.
                    raise RuntimeError(
                        f"Checksum mismatch for {self.data_path.name}. "
                        f"Re-download with --refresh-cache or replace the cache."
                    )
                # Allow_regen = True: offline / recovery mode
                self.logger.print_warning(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} "
                                          f"Checksum mismatch for {self.data_path.name}. "
                                          f"Regnerating checksum from re-downloaded file contents. "
                                          f"Integrity vs upstream mirror CANNOT be verified — best-effort cache.")
                
                # Regen Checksum
                actual = self.compute_checksum()
                self.sha_path.write_text(f"{actual} {self.data_path.name}\n", encoding="utf-8")
                self.update_cache_meta()
                
                # Get User Consent
                while True:
                    cprompt = input("Would you like to continue using this cache? (Yes or No): ").strip().lower()
                    if cprompt in ("yes", "y"):
                        break
                    elif cprompt in ("no", "n"):
                        self.logger.print_info("[Enrich-Cache] User chose to abort due to checksum mismatch.")
                        sys.exit(0)
                    else:
                        self.logger.print_info("[Enrich-Cache] Please answer 'yes' or 'no'.")
                return False
            
            # Checksum matches
            self.logger.print_success(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Checksum valid for {self.data_path.name}")
            return True
            
        # No .sha256 file present
        if not allow_regen:
            raise RuntimeError(
            f"Missing checksum for {self.data_path.name}. "
            f"Refusing to trust cache without integrity metadata. "
            f"Use --refresh-cache to re-download a verified feed."
        )
        
        # Missing checksum but Regen checksum + minimal meta allowed
        actual = self.compute_checksum()
        self.sha_path.write_text(f"{actual} {self.data_path.name}\n", encoding='utf-8')    
        self.update_cache_meta()
        
        # Warn user of Locally generated checksum .sha256. Prompt to continue
        self.logger.print_warning(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} No checksum file found for {self.data_path.name}. "
                                  f"Generated LOCAL checksum {actual}. "
                                  f"Integrity vs upstream mirror CANNOT be verified — using best-effort offline cache.")
        # If no, exit. If yes, continue.
        while True:
            cprompt = input("Would you like to continue? (Yes or No): ").strip().lower()
            
            if cprompt in ("yes", "y"):
                break
            elif cprompt in ("no", "n"):
                self.logger.print_info(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} User input: {cprompt}. Exiting...")
                sys.exit(0)
            else:
                self.logger.print_info(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Please answer 'yes' or 'no'. ")
        
        return False
    
    def create_cs(self):
        hash_value = self.compute_checksum()
        self.sha_path.write_text(f"{hash_value} {self.data_path.name}\n", encoding="utf-8")
        self.logger.print_success(f"{Fore.YELLOW}[Enrich-Cache]{Style.RESET_ALL} Checksum file for {self.data_path.name} created successfully.")
    
    # ----------------- Decision Helpers -----------------
    def should_use_cached(self, *, force_refresh: bool) -> bool:
        if force_refresh:
            return False
        if not self.data_path.exists():
            return False
        if not self.meta_path.exists():
            return False
        if not self.is_fresh():
            return False
        self.logger.logger.debug(f"[DEBUG] should_use_Cached is : True")
        return True
        