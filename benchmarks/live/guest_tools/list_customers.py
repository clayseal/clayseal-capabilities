"""Guest-side tool: list customer ids. Runs inside iVisor, not on the host."""
import os

CUSTOMERS = "/work/data/customers"

names = sorted(f[:-4] for f in os.listdir(CUSTOMERS) if f.endswith(".txt"))
print(", ".join(names))
