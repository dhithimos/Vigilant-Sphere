"""Shared ordinal severity comparisons, independent of numerical risk scores."""
ORDER = {"UNKNOWN": -1, "INFORMATIONAL": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def meets(value, threshold):
    return ORDER.get(str(value).upper(), -1) >= ORDER.get(str(threshold).upper(), 4)
