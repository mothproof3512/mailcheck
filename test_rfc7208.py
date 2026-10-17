#!/usr/bin/env python3
"""
Harness die de OFFICIËLE RFC 7208-testsuite tegen de SPF-evaluator van mailcheck draait.

Dit bestand bevat de testdata NIET (die wordt door openspf/pyspf onderhouden). Zet het
YAML-bestand ernaast of wijs ernaar met een omgevingsvariabele:

    # haal het op (één van beide):
    #   https://raw.githubusercontent.com/sdgathman/pyspf/master/test/rfc7208-tests.yml
    #   http://www.openspf.org/source/project/test-suite/rfc7208-tests.yml
    cp rfc7208-tests.yml .            # naast dit bestand
    #   of:
    export MAILCHECK_RFC7208=/pad/naar/rfc7208-tests.yml

    python3 -m pip install pyyaml      # eenmalig, alleen voor deze harness
    python3 -m unittest test_rfc7208

Zonder het bestand of zonder PyYAML wordt de hele suite overgeslagen (skip), niet gefaald.
Elk scenario draait als subTest, zodat je precies ziet welk scenario afwijkt.

Opmerking: de evaluator volgt RFC 7208 en gebruikt uitsluitend TXT-records (de SPF-RR-type is
door RFC 7208 §3.1 afgeschaft). Records van het type SPF in de testdata worden daarom genegeerd,
net als een conforme ontvanger doet. Alleen de uitkomst (result) wordt vergeleken, niet de
explanation-string.
"""
import importlib.util
import os
import pathlib
import unittest


def _load_mailcheck():
    here = pathlib.Path(__file__).resolve().parent
    for cand in (here / "mailcheck.py", here.parent / "mailcheck.py"):
        if cand.is_file():
            spec = importlib.util.spec_from_file_location("mailcheck", cand)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise ImportError("mailcheck.py niet gevonden naast de tests of in de bovenliggende map")


mc = _load_mailcheck()

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


def _find_suite():
    env = os.environ.get("MAILCHECK_RFC7208")
    if env and pathlib.Path(env).is_file():
        return pathlib.Path(env)
    here = pathlib.Path(__file__).parent
    for name in ("rfc7208-tests.yml", "rfc7208-tests.yaml"):
        p = here / name
        if p.is_file():
            return p
    return None


_SUITE = _find_suite()


class _SuiteResolver:
    """Vertaalt de 'zonedata' van de testsuite naar de resolver-interface (query -> DNSResult)."""

    def __init__(self, zonedata):
        self.txt = {}       # naam -> [records]
        self.a = {}
        self.aaaa = {}
        self.mx = {}
        self.ptr = {}
        self.cname = {}
        self.timeout = set()
        self.log = []
        for name, records in (zonedata or {}).items():
            key = name.lower().rstrip(".")
            for rec in records or []:
                if rec == "TIMEOUT" or rec is None:
                    self.timeout.add(key)
                    continue
                if not isinstance(rec, dict):
                    continue
                (rtype, value), = rec.items()
                rtype = rtype.upper()
                if value == "TIMEOUT":
                    self.timeout.add(key)
                    continue
                if rtype in ("TXT", "SPF"):
                    text = "".join(value) if isinstance(value, list) else str(value)
                    if rtype == "TXT":                       # SPF-RR-type bewust negeren
                        self.txt.setdefault(key, []).append(text)
                elif rtype == "A":
                    for v in (value if isinstance(value, list) else [value]):
                        self.a.setdefault(key, []).append(str(v))
                elif rtype == "AAAA":
                    for v in (value if isinstance(value, list) else [value]):
                        self.aaaa.setdefault(key, []).append(str(v))
                elif rtype == "MX":
                    self.mx.setdefault(key, []).append((int(value[0]), str(value[1]).rstrip(".")))
                elif rtype == "PTR":
                    self.ptr.setdefault(key, []).append(str(value).rstrip("."))
                elif rtype == "CNAME":
                    self.cname.setdefault(key, []).append(str(value).rstrip("."))
        self._exists = (set(self.txt) | set(self.a) | set(self.aaaa) | set(self.mx)
                        | set(self.ptr) | set(self.cname) | self.timeout)

    def query(self, name, rtype, cd=False):
        key = name.lower().rstrip(".") or "."
        if key in self.timeout:
            return mc.DNSResult("error", error="time-out")
        table = {"TXT": self.txt, "A": self.a, "AAAA": self.aaaa, "MX": self.mx,
                 "PTR": self.ptr, "CNAME": self.cname}.get(rtype, {})
        if key in table:
            return mc.DNSResult("ok", list(table[key]))
        if key in self._exists:
            return mc.DNSResult("nodata")
        return mc.DNSResult("nxdomain")

    def nameservers(self):
        return ["suite"]


@unittest.skipUnless(_HAVE_YAML, "PyYAML niet geïnstalleerd (pip install pyyaml)")
@unittest.skipUnless(_SUITE, "rfc7208-tests.yml niet gevonden; zie de docstring van dit bestand")
class TestRFC7208Suite(unittest.TestCase):
    def test_suite(self):
        with open(_SUITE, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d and "tests" in d]
        total = 0
        for doc in docs:
            resolver_data = doc.get("zonedata", {})
            for name, t in doc["tests"].items():
                total += 1
                with self.subTest(scenario=name, doc=doc.get("description", "")):
                    resolver = _SuiteResolver(resolver_data)
                    helo = t.get("helo", "")
                    mailfrom = t.get("mailfrom", "")
                    host = t["host"]
                    ev = mc.SPFEvaluator(resolver, host, sender=mailfrom, helo=helo,
                                         receiver="mx.example.com")
                    got, _ = ev.check()
                    want = t["result"]
                    allowed = want if isinstance(want, list) else [want]
                    self.assertIn(got, allowed,
                                  f"{name}: kreeg {got!r}, toegestaan {allowed} "
                                  f"(mechanisme: {ev.mechanism}, fout: {ev.error})")
        self.assertGreater(total, 0, "geen scenario's geladen uit de testsuite")


if __name__ == "__main__":
    unittest.main(verbosity=2)
