"""Backward-compatible import path for the shared observability module."""

import sys
from modules import observability as _observability

sys.modules[__name__] = _observability
