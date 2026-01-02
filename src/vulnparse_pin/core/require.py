from typing import TYPE_CHECKING

from vulnparse_pin.core.classes.dataclass import Services

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext
    from vulnparse_pin.utils.feed_cache import FeedCacheManager
    from vulnparse_pin.utils.nvdcacher import NVDFeedCache

# ---------------------------
#       Helpers
# ---------------------------
def require_feed_cache(ctx: "RunContext") -> "FeedCacheManager":
    if not ctx.services or not ctx.services.feed_cache:
        raise RuntimeError("FeedCacheManager is required for this operation but was not initialized.")
    return ctx.services.feed_cache

def require_nvd_cache(ctx: "RunContext") -> "NVDFeedCache":
    if not ctx.services or not ctx.services.nvd_cache:
        raise RuntimeError("NVD cache required but not initialized.")
    return ctx.services.nvd_cache

def require_services(ctx: "RunContext") -> Services:
    if ctx.services is None:
        raise RuntimeError("Services not initialized on RunContext")
    return ctx.services