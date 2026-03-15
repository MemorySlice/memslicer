"""Protection string parsing shared between CLI and acquirer."""


def parse_protection(prot_str: str) -> int:
    """Convert protection string like 'rwx' to bit flags (R=1, W=2, X=4)."""
    bits = 0
    if len(prot_str) >= 1 and prot_str[0] == "r":
        bits |= 1
    if len(prot_str) >= 2 and prot_str[1] == "w":
        bits |= 2
    if len(prot_str) >= 3 and prot_str[2] == "x":
        bits |= 4
    return bits


def format_protection(bits: int) -> str:
    """Convert protection bit flags back to 'rwx' string."""
    r = "r" if bits & 1 else "-"
    w = "w" if bits & 2 else "-"
    x = "x" if bits & 4 else "-"
    return f"{r}{w}{x}"


# Protection bit constants
PROT_R = 1
PROT_W = 2
PROT_X = 4
PROT_RWX = PROT_R | PROT_W | PROT_X


def is_rwx(bits: int) -> bool:
    """Check if protection bits indicate read-write-execute (forensically significant)."""
    return bits & PROT_RWX == PROT_RWX
