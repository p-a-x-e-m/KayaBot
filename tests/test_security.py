import os, sys, tempfile, logging

from cryptography.fernet import Fernet

os.environ["KAYA_COOKIE_KEY"] = Fernet.generate_key().decode()
os.environ["KAYA_USERNAME"] = "u"
os.environ["KAYA_PASSWORD"] = "p"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

work = tempfile.mkdtemp()
os.chdir(work)

import main
from main import KayaAuth, DB_PATH, LOG_LEVEL, env_flag

# Keep the bot's file log out of the way of the test output.
logging.getLogger().handlers.clear()
logging.getLogger().addHandler(logging.NullHandler())

results = []


def check(label, cond, detail=""):
    results.append((label, bool(cond), detail))


check("1. env_flag default/override",
      env_flag("KAYA_NO_SUCH_VAR", True) is True and env_flag("KAYA_NO_SUCH_VAR") is False)

auth = KayaAuth(debug=False)
check("2. db created", os.path.exists(DB_PATH), DB_PATH)


class FakeDriver:
    def get_cookies(self):
        return [{"name": "token", "value": "SUPER-SECRET-SESSION-VALUE", "domain": "kaya.ir"}]


auth.driver = FakeDriver()
auth.save_cookies()

raw = open(DB_PATH, "rb").read()
check("3. plaintext NOT in db file", b"SUPER-SECRET-SESSION-VALUE" not in raw)

back = auth.get_cookies()
check("4. decrypt roundtrip", back and back[0]["value"] == "SUPER-SECRET-SESSION-VALUE")

os.environ["KAYA_COOKIE_KEY"] = Fernet.generate_key().decode()
check("5. wrong key -> None (graceful)", auth.get_cookies() is None)

os.environ.pop("KAYA_COOKIE_KEY")
try:
    auth._cipher()
    check("6. missing key -> ValueError", False)
except ValueError:
    check("6. missing key -> ValueError", True)

os.environ.pop("KAYA_USERNAME")
try:
    KayaAuth.load_credentials()
    check("7. missing creds -> ValueError", False)
except ValueError:
    check("7. missing creds -> ValueError", True)

os.environ["KAYA_USERNAME"] = "u"
creds = KayaAuth.load_credentials()
check("8. creds keys", list(creds.keys()) == ["loginNumber", "password"])

check("9. constants wired", main.BASE_URL == "https://kaya.ir" and DB_PATH == "kaya.db")

# The insecure browser flags must be gone for good.
# Build the comparison text from every string literal EXCEPT docstrings, so the
# "do not re-add" documentation notes don't trip the guard, while any real
# re-introduction of the flag as an option would.
import ast, io, tokenize

src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py"), encoding="utf-8").read()

tree = ast.parse(src)
docstrings = set()
for node in ast.walk(tree):
    if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        body = getattr(node, "body", [])
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            docstrings.add(id(body[0].value))

code = "\n".join(
    n.value for n in ast.walk(tree)
    if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
)
check("10. no --disable-web-security", "--disable-web-security" not in code)
check("11. no --allow-running-insecure-content", "--allow-running-insecure-content" not in code)
check("12. no navigator.webdriver override", "navigator', 'webdriver'" not in code)
check("13. no os.system", "os.system(" not in code)
check("14. no page_source logging", "page_source" not in code)

# The driver must not silently weaken TLS or same-origin enforcement.
import re as _re
check("15. no verify=False", not _re.search(r"verify\s*=\s*False", code))
check("16. no shell=True", "shell=True" not in code)

failed = [r for r in results if not r[1]]
for label, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + label + ("  " + str(detail) if detail else ""))
print()
print("TOTAL:", len(results), "FAILED:", len(failed))
sys.exit(1 if failed else 0)
