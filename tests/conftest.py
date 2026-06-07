import os
import sys

# Make the installed-layout `lib` package importable from the source tree.
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "src", "opnsense", "scripts", "keaunbound"))
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
