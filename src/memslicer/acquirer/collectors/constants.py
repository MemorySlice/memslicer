"""Shared constants for investigation collectors."""

# Address family
AF_UNIX = 0x01
AF_INET = 0x02
AF_INET6 = 0x0A

# Protocol
PROTO_TCP = 0x06
PROTO_UDP = 0x11

# Handle types
HT_UNKNOWN = 0x00
HT_FILE = 0x01
HT_DIR = 0x02
HT_SOCKET = 0x03
HT_PIPE = 0x04
HT_DEVICE = 0x05
HT_REGISTRY = 0x06
HT_OTHER = 0xFF

# HandleTable FD when the entry has no descriptor number: lsof cwd/rtd/txt/mem.
# The format stores FD as uint32, so the sentinel is the all-ones value, not -1
# (which the writer cannot pack and would otherwise drop the row for).
FD_NONE = 0xFFFFFFFF
