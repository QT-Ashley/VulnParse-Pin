import os
import gzip
import json
import hashlib
import requests
from datetime import datetime, timedelta
import utils.logger_instance as log

class NVDCache:
    '''
    Feed-based NVD Cache.
    Loads yearly + modified feeds into memory for O(1) lookups.
    '''
    
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
    
    def __init__(self, cache_dir="./nvd_cache", refresh_days=1, offline=False):
        self.cache_dir = cache_dir
        self.refresh_days = refresh_days
        self.offline = offline
        self.lookup = {}
        os.makedirs(cache_dir, exist_ok=True)
        
    def _download_feed(self, fname: str):
        """Download nvd data feed if stale or is missing."""
        path = os.path.join(self.cache_dir, fname)
        if os.path.exists(path):
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            if datetime.now() - mtime < timedelta(days=self.refresh_days):
                return path # Data still fresh
            
        url = self.BASE_URL + fname
        log.log.print_info(f"Downloading NVD feed: {fname}")
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        with open(path, 'wb') as f:
            f.write(r.content)
        return path
    
    def _validate_meta(self, fname: str) -> bool:
        """Validate feed using .meta file (sha256 + lastModifiedDate)."""
        meta_url = self.BASE_URL + fname.replace(".json.gz", ".meta")
        r = requests.get(meta_url, timeout=15, headers={
            "User-Agent": "Dev.VulnParse-PinV1.0"
        })
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        meta = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
                
        # Paths
        path = os.path.join(self.cache_dir, fname)
        if not os.path.exists(path):
            return False
        
        # Check SHA256
        sha256_expected = meta.get("sha256")
        if sha256_expected:
            sha256_local = hashlib.sha256(open(path, 'rb').read()).hexdigest()
            if sha256_local != sha256_expected:
                log.log.print_warning(f"{fname} hash mismatch. Redownloading from {self.BASE_URL}")
                return False
        
        # Check lastModifiedDate
        last_mod_meta = meta.get("lastModifiedDate")
        if last_mod_meta:
            # If local file older than meta timestamp, refresh
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            last_mod_dt = datetime.fromisoformat(last_mod_meta.replace("Z", "+00:00"))
            if mtime < last_mod_dt:
                log.log.print_info(f"{fname} is outdated. Redownloading...")
                return False
            
        return True
    
    def _parse_feed(self, path: str):
        """Parse NVD 2.0 feed into lookup dict."""
        if path.endswith(".gz"):
            with gzip.open(path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
        else:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
        
        # Parse pertinent information from feeds.
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            
            # Description
            desc = ""
            if cve.get("descriptions"):
                desc = cve["descriptions"][0]["value"]
                
            # Published/LastModified
            published = cve.get("published")
            last_mod = cve.get("lastModified")
                
            # CVSS Metrics
            metrics = cve.get("metrics", {})
            cvss, vector = None, None
            
            # CVSS Prioritization
            
            if "cvssMetricV31" in metrics:
                chosen = self._choose_cvss(metrics["cvssMetricV31"])
                cvss, vector = chosen
            elif "cvssMetricV30" in metrics:
                chosen = self._choose_cvss(metrics["cvssMetricV30"])
                cvss, vector = chosen
            elif "cvssMetricV2" in metrics:
                chosen = self._choose_cvss(metrics["cvssMetricV2"])
                cvss, vector = chosen
                
            self.lookup[cve_id] = {
                "id": cve_id,
                "description": desc,
                "cvss_score": cvss,
                "cvss_vector": vector,
                "published": published,
                "last_Modified": last_mod
            }
    
    def _choose_cvss(self, metrics_list):
        """Pick Primary cvss first, fallback to Secondary."""
        primary = next((m for m in metrics_list if m.get("type") == "Primary"), None)
        if not primary and metrics_list:
            primary = metrics_list[0]
        if primary and "cvssData" in primary:
            d = primary["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
        return None, None
    
    def refresh(self, years=None):
        """
        Refresh cache with yearly + modified feeds.
        
        years: list[int] or None (defaults to current year only)
        """
        if years is None:
            years = [datetime.now().year]
            
        # Feeds
        feeds = [f"modified.json.gz"] + [f"{y}.json.gz" for y in years]
        
        missing_feeds = []
        
        for fname in feeds:
            path = os.path.join(self.cache_dir, fname)
            
            # If offline, only use local file
            if self.offline:
                if os.path.exists(path):
                    self._parse_feed(path)
                else:
                    missing_feeds.append(fname)
                continue
            
            
            # Online mode: validate + download if needed
            if not os.path.exists(path) or not self._validate_meta(fname):
                path = self._download_feed(fname)
            self._parse_feed(path)
            
        # Consolidated warning if offline and missing feeds
        if self.offline and missing_feeds:
            log.log.print_warning(f"[NVD Cache] Offline mode active - {len(missing_feeds)} feeds missing. NVD enrichment will be incomplete until feeds are downloaded in online mode.")
        
    def get(self, cve_id: str):
        """Lookup CVE from cache.
        Always return a normalized dict with expected keys, even if the CVE is missing (values default to None).
        """
        
        default_record = {
        "id": cve_id,
        "description": "",
        "cvss_score": None,
        "cvss_vector": None,
        "published": None,
        "last_Modified": None,
        "found": False,
        }
        
        record = self.lookup.get(cve_id, {})
        if record is None:
            return default_record
        
        merged = {**default_record, **record}
        merged["found"] = True
        return merged
    
    