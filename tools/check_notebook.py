import ast
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
notebook = json.loads((root / "colab.ipynb").read_text(encoding="utf-8"))
for cell in notebook["cells"]:
    if cell["cell_type"] == "code":
        assert cell.get("outputs") == [] and cell.get("execution_count") is None
        ast.parse("".join(cell["source"]))
source = "".join(notebook["cells"][1]["source"])
assert re.search(r'INSTALLER_COMMIT = "[a-f0-9]{40}"', source)
assert re.search(r'INSTALLER_SHA256 = "[a-f0-9]{64}"', source)
digest = hashlib.sha256((root / "install.py").read_bytes()).hexdigest()
assert digest in source, "Update the pinned installer digest after changing install.py."
print("Notebook code, clean outputs and installer digest: OK")
