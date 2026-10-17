#!/usr/bin/env python3
"""
Testsuite voor mailcheck.py.

Draait zonder externe afhankelijkheden (geen dnspython, geen netwerk): DNS wordt
nagebootst met FakeResolver en HTTPS (MTA-STS) met een fetch-stub. Uitvoeren met:

    python3 -m unittest test_mailcheck          # stdlib, geen installatie nodig
    python3 -m pytest   test_mailcheck.py        # idem, als pytest aanwezig is

De tests dekken de SPF-evaluator (RFC 7208 check_host), DKIM-sleutelsterkte en
-ontleding, DMARC-beleid en organisatiedomein, MTA-STS, TLS-RPT, DANE (met de
Microsoft-365/niet-DNSSEC-regressie), DNSSEC, het opbouwen van het rapport,
rendering (HTML/Markdown/CSV-escaping), domeinnormalisatie en de CLI-exitcodes.
"""
import base64
import importlib.util
import io
import pathlib
import unittest

# --- module onder test laden (naast dit bestand of in de bovenliggende map) -----------
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


# =====================================================================================
# Hulpmiddelen: DNS-antwoorden, een nep-resolver en een RSA-sleutel van gekozen lengte
# =====================================================================================

def ok(rrs, ad=False):
    return mc.DNSResult("ok", rrs, ad=ad)


def nodata(ad=False):
    return mc.DNSResult("nodata", ad=ad)


def nxdomain():
    return mc.DNSResult("nxdomain")


def err(msg="SERVFAIL"):
    return mc.DNSResult("error", error=msg)


class FakeResolver:
    """Bootst een DNS-resolver na. `zone` = {(naam, rtype): DNSResult}.

    Ontbrekende namen geven nxdomain, bestaande namen zonder dat rtype nodata.
    `validates` bepaalt de AD-vlag op het root-DNSKEY-antwoord (voor resolver_validates).
    """

    def __init__(self, zone=None, validates=True):
        self.zone = {}
        for (name, rtype), res in (zone or {}).items():
            self.zone[(name.lower().rstrip("."), rtype)] = res
        self.validates = validates
        self.log = []
        self.queries = []

    def _lookup(self, name, rtype):
        key = (name.lower().rstrip(".") or ".", rtype)
        if key == (".", "DNSKEY") and key not in self.zone:
            return ok([(257, 8)], ad=self.validates)
        if key in self.zone:
            return self.zone[key]
        exists = any(k[0] == key[0] for k in self.zone)
        return nodata(ad=self.validates) if exists else nxdomain()

    def query(self, name, rtype, cd=False):
        r = self._lookup(name, rtype)
        self.queries.append((name.lower().rstrip("."), rtype, cd))
        self.log.append({"naam": name.rstrip("."), "type": rtype, "status": r.status,
                         "antwoord": [mc._fmt_rr(rtype, x) for x in r.rrs], "fout": r.error,
                         "dnssec": r.ad})
        return r

    def nameservers(self):
        return ["9.9.9.9"]


# --- RSA-sleutel (DER / SubjectPublicKeyInfo) van een exacte bitlengte ----------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def rsa_spki_b64(bits):
    """base64 van een geldige RSA-SubjectPublicKeyInfo met een modulus van exact `bits` bit."""
    modulus = (1 << (bits - 1)) | 1
    mb = modulus.to_bytes((bits + 7) // 8, "big")
    if mb[0] & 0x80:
        mb = b"\x00" + mb
    rsapub = _der(0x30, _der(0x02, mb) + _der(0x02, (65537).to_bytes(3, "big")))
    algid = _der(0x30, _der(0x06, mc.RSA_OID) + _der(0x05, b""))
    spki = _der(0x30, algid + _der(0x03, b"\x00" + rsapub))
    return base64.b64encode(spki).decode("ascii")


def make_auditor(resolver, selectors=("selector1",), user_selectors=False, http=False):
    return mc.Auditor(resolver, list(selectors), user_selectors=user_selectors, http=http)


# =====================================================================================
# RSA-sleutellengte en DER-ontleding
# =====================================================================================

class TestRsaKeyBits(unittest.TestCase):
    def test_lengths(self):
        for bits in (512, 1024, 2048, 3072):
            raw = base64.b64decode(rsa_spki_b64(bits))
            self.assertEqual(mc.rsa_key_bits(raw), bits)

    def test_truncated_key_raises(self):
        raw = base64.b64decode(rsa_spki_b64(2048))[:20]
        with self.assertRaises(ValueError):
            mc.rsa_key_bits(raw)

    def test_non_rsa_oid_raises(self):
        bad = _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d0201")) + _der(0x05, b""))
                   + _der(0x03, b"\x00\x00"))
        with self.assertRaises(ValueError):
            mc.rsa_key_bits(bad)


# =====================================================================================
# SPF-evaluator (RFC 7208 check_host)
# =====================================================================================

class TestSPFEvaluator(unittest.TestCase):
    def _eval(self, zone, ip, domain="example.com"):
        r = FakeResolver(zone)
        ev = mc.SPFEvaluator(r, ip, sender=f"postmaster@{domain}", helo=domain)
        return ev.check(domain), ev

    def test_hardfail_for_unauthorized(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 ip4:192.0.2.10 -all"])}
        (res, _), ev = self._eval(zone, "203.0.113.9")
        self.assertEqual(res, "fail")

    def test_pass_for_authorized_ip(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 ip4:203.0.113.0/24 -all"])}
        (res, _), ev = self._eval(zone, "203.0.113.9")
        self.assertEqual(res, "pass")

    def test_plus_all_passes_everyone(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 +all"])}
        (res, _), _ = self._eval(zone, "198.51.100.1")
        self.assertEqual(res, "pass")

    def test_softfail(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 ~all"])}
        (res, _), _ = self._eval(zone, "198.51.100.1")
        self.assertEqual(res, "softfail")

    def test_no_record_is_none(self):
        (res, _), _ = self._eval({("example.com", "TXT"): nodata()}, "198.51.100.1")
        self.assertEqual(res, "none")

    def test_include_pass(self):
        zone = {
            ("example.com", "TXT"): ok(["v=spf1 include:_spf.example.net -all"]),
            ("_spf.example.net", "TXT"): ok(["v=spf1 ip4:198.51.100.0/24 -all"]),
        }
        (res, _), ev = self._eval(zone, "198.51.100.7")
        self.assertEqual(res, "pass")
        self.assertEqual(ev.lookups, 1)

    def test_include_missing_record_is_permerror(self):
        zone = {
            ("example.com", "TXT"): ok(["v=spf1 include:_spf.example.net -all"]),
            ("_spf.example.net", "TXT"): nodata(),
        }
        (res, _), _ = self._eval(zone, "198.51.100.7")
        self.assertEqual(res, "permerror")

    def test_lookup_limit_exceeded(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 " + " ".join(f"include:a{i}.example" for i in range(11)) + " -all"])}
        for i in range(11):
            zone[(f"a{i}.example", "TXT")] = ok(["v=spf1 -all"])
        (res, _), ev = self._eval(zone, "198.51.100.7")
        self.assertEqual(res, "permerror")
        self.assertEqual(ev.error_code, "lookups")

    def test_dns_error_is_temperror(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 include:broken.example -all"]),
                ("broken.example", "TXT"): err("time-out")}
        (res, _), _ = self._eval(zone, "198.51.100.7")
        self.assertEqual(res, "temperror")

    def test_ipv6_mapped_v4(self):
        zone = {("example.com", "TXT"): ok(["v=spf1 ip4:203.0.113.5 -all"])}
        (res, _), _ = self._eval(zone, "::ffff:203.0.113.5")
        self.assertEqual(res, "pass")


class TestParseSPF(unittest.TestCase):
    def test_valid(self):
        terms, mods = mc.parse_spf("v=spf1 ip4:192.0.2.0/24 include:x.example -all")
        self.assertTrue(any(t.name == "include" for t in terms))

    def test_missing_version(self):
        with self.assertRaises(mc.SPFPermError):
            mc.parse_spf("ip4:192.0.2.0/24 -all")

    def test_bad_cidr(self):
        with self.assertRaises(mc.SPFPermError):
            mc.parse_spf("v=spf1 ip4:192.0.2.0/33 -all")

    def test_unknown_mechanism(self):
        with self.assertRaises(mc.SPFPermError):
            mc.parse_spf("v=spf1 bogus:foo -all")


# =====================================================================================
# DKIM
# =====================================================================================

class TestDKIM(unittest.TestCase):
    def _run(self, selectors, keys, domainkey=nodata(), spf_parked=False, user=False):
        zone = {(f"_domainkey.{d}" if False else "_domainkey.example.com", "TXT"): domainkey}
        for sel, rec in keys.items():
            zone[(f"{sel}._domainkey.example.com", "TXT")] = ok([rec])
        aud = make_auditor(FakeResolver(zone), selectors=selectors, user_selectors=user)
        ctx = {"spf_parked": spf_parked}
        return aud.check_dkim("example.com", ctx), ctx

    def _codes(self, res):
        return {f["code"] for f in res.findings}

    def test_2048_is_clean(self):
        res, ctx = self._run(["selector1"], {"selector1": f"v=DKIM1; k=rsa; p={rsa_spki_b64(2048)}"})
        self.assertEqual(self._codes(res), set())
        self.assertTrue(ctx["dkim_found"])

    def test_1024_is_midden(self):
        res, _ = self._run(["k1"], {"k1": f"v=DKIM1; k=rsa; p={rsa_spki_b64(1024)}"})
        self.assertIn("DKIM_KEY_1024", self._codes(res))
        f = next(f for f in res.findings if f["code"] == "DKIM_KEY_1024")
        self.assertEqual(f["ernst"], mc.MIDDEN)

    def test_512_is_weak_hoog(self):
        res, _ = self._run(["s"], {"s": f"v=DKIM1; k=rsa; p={rsa_spki_b64(512)}"})
        self.assertIn("DKIM_KEY_WEAK", self._codes(res))
        f = next(f for f in res.findings if f["code"] == "DKIM_KEY_WEAK")
        self.assertEqual(f["ernst"], mc.HOOG)

    def test_mixed_selectors_rsa_1024_and_2048(self):
        res, ctx = self._run(["selector1", "k1"],
                             {"selector1": f"v=DKIM1; k=rsa; p={rsa_spki_b64(2048)}",
                              "k1": f"k=rsa; p={rsa_spki_b64(1024)}"})
        self.assertEqual(self._codes(res), {"DKIM_KEY_1024"})
        self.assertTrue(ctx["dkim_found"])

    def test_revoked_key(self):
        res, _ = self._run(["selector1"], {"selector1": "v=DKIM1; k=rsa; p="})
        self.assertIn("DKIM_REVOKED", self._codes(res))

    def test_none_published_nxdomain(self):
        res, ctx = self._run(["selector1"], {}, domainkey=nxdomain())
        self.assertIn("DKIM_NONE_PUBLISHED", self._codes(res))
        self.assertFalse(ctx["dkim_found"])
        self.assertTrue(ctx["dkim_absent_zeker"])


# =====================================================================================
# DMARC
# =====================================================================================

class TestDMARC(unittest.TestCase):
    def _run(self, records, extra=None, ctx=None):
        # example.com moet mail kunnen ontvangen, zodat een rua-adres op dat domein geldig is
        zone = {("example.com", "MX"): ok([(10, "mx.example.com")])}
        for name, recs in records.items():
            zone[(name, "TXT")] = ok(recs) if isinstance(recs, list) else recs
        zone.update(extra or {})
        aud = make_auditor(FakeResolver(zone))
        ctx = ctx if ctx is not None else {"spf_state": "ok", "dkim_found": True, "spf_parked": False}
        return aud.check_dmarc("example.com", ctx), ctx

    def _codes(self, res):
        return {f["code"] for f in res.findings}

    def test_reject_no_rua(self):
        res, ctx = self._run({"_dmarc.example.com": ["v=DMARC1; p=reject"]})
        self.assertIn("DMARC_NO_RUA", self._codes(res))
        self.assertEqual(ctx["dmarc_policy"], "reject")

    def test_reject_with_rua_clean(self):
        res, _ = self._run({"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]})
        self.assertEqual(self._codes(res), set())

    def test_p_none_flagged(self):
        res, _ = self._run({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:d@example.com"]})
        self.assertIn("DMARC_P_NONE", self._codes(res))

    def test_missing(self):
        res, _ = self._run({"_dmarc.example.com": nxdomain()})
        self.assertIn("DMARC_MISSING", self._codes(res))

    def test_sp_none_subdomain_hole(self):
        res, _ = self._run({"_dmarc.example.com":
                            ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"]})
        self.assertIn("DMARC_SP_NONE", self._codes(res))

    def test_unknown_tag_typo(self):
        res, _ = self._run({"_dmarc.example.com":
                            ["v=DMARC1; p=reject; rau=mailto:d@example.com; rua=mailto:d@example.com"]})
        self.assertIn("DMARC_UNKNOWN_TAG", self._codes(res))

    def test_invalid_policy_value(self):
        res, _ = self._run({"_dmarc.example.com": ["v=DMARC1; p=blokkeer"]})
        self.assertIn("DMARC_INVALID_P", self._codes(res))

    def test_enforcing_without_auth_basis(self):
        res, _ = self._run({"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]},
                           ctx={"spf_state": "missing", "dkim_found": False, "dkim_absent_zeker": True,
                                "spf_parked": False})
        self.assertIn("DMARC_NO_AUTH_BASIS", self._codes(res))


# =====================================================================================
# MTA-STS en TLS-RPT
# =====================================================================================

class TestMTASTS(unittest.TestCase):
    def _run(self, zone, ctx, fetch=None):
        aud = mc.Auditor(FakeResolver(zone), [], http=fetch is not None,
                         fetch=fetch or mc.http_fetch)
        return aud.check_mtasts("example.com", ctx)

    def _codes(self, res):
        return {f["code"] for f in res.findings}

    def test_missing_record(self):
        res = self._run({("_mta-sts.example.com", "TXT"): nxdomain()}, {"mx_hosts": ["mx.example.com"]})
        self.assertIn("MTASTS_MISSING", self._codes(res))

    def test_not_applicable_without_mx(self):
        res = self._run({}, {"mx_hosts": []})
        self.assertTrue(all(t in res.na for t in ("MTASTS-01", "MTASTS-02")))

    def test_testing_mode_flagged(self):
        policy = b"version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 604800\n"

        def fetch(url, timeout=10.0, limit=65536):
            return 200, "text/plain", policy

        zone = {("_mta-sts.example.com", "TXT"): ok(["v=STSv1; id=20260101T000000"])}
        res = self._run(zone, {"mx_hosts": ["mx.example.com"]}, fetch=fetch)
        self.assertIn("MTASTS_TESTING", self._codes(res))

    def test_enforce_mx_mismatch(self):
        policy = b"version: STSv1\nmode: enforce\nmx: andere.example.net\nmax_age: 604800\n"

        def fetch(url, timeout=10.0, limit=65536):
            return 200, "text/plain", policy

        zone = {("_mta-sts.example.com", "TXT"): ok(["v=STSv1; id=1"])}
        res = self._run(zone, {"mx_hosts": ["mx.example.com"]}, fetch=fetch)
        self.assertIn("MTASTS_MX_MISMATCH", self._codes(res))


class TestTLSRPT(unittest.TestCase):
    def test_missing(self):
        aud = make_auditor(FakeResolver({("_smtp._tls.example.com", "TXT"): nxdomain()}))
        res = aud.check_tlsrpt("example.com", {"mx_hosts": ["mx.example.com"]})
        self.assertIn("TLSRPT_MISSING", {f["code"] for f in res.findings})

    def test_valid(self):
        zone = {("_smtp._tls.example.com", "TXT"): ok(["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"])}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_tlsrpt("example.com", {"mx_hosts": ["mx.example.com"]})
        self.assertEqual([f["code"] for f in res.findings], [])


# =====================================================================================
# DANE — inclusief de Microsoft-365/niet-DNSSEC-regressie
# =====================================================================================

class TestDANE(unittest.TestCase):
    def _codes(self, res):
        return {f["code"] for f in res.findings}

    def test_unsigned_zone_servfail_is_definitive_not_unknown(self):
        """Microsoft-365-achtig geval: TLSA SERVFAIL op een niet-DNSSEC-mailserver -> definitief
        DANE_MISSING, geen 'niet vast te stellen', dus de audit blijft niet onterecht 'onvolledig'."""
        host = "example-nl.mail.protection.outlook.com"
        zone = {
            (f"_25._tcp.{host}", "TLSA"): err("SERVFAIL"),
            (host, "A"): ok(["192.0.2.10"], ad=False),   # zone niet DNSSEC-ondertekend
        }
        aud = make_auditor(FakeResolver(zone, validates=True))
        res = aud.check_dane("example.com", {"mx_hosts": [host], "resolver_validates": True})
        self.assertIn("DANE_MISSING", self._codes(res))
        self.assertFalse(res.dns_unknown)
        self.assertNotIn("DANE-01", res.unknown)

    def test_signed_zone_servfail_stays_unknown(self):
        host = "mx.signed.example"
        zone = {
            (f"_25._tcp.{host}", "TLSA"): err("SERVFAIL"),
            (host, "A"): ok(["203.0.113.5"], ad=True),   # zone WEL ondertekend
        }
        aud = make_auditor(FakeResolver(zone, validates=True))
        res = aud.check_dane("example.com", {"mx_hosts": [host], "resolver_validates": True})
        self.assertTrue(res.dns_unknown)
        self.assertIn("DANE-01", res.unknown)

    def test_no_tlsa_records(self):
        host = "mx.example.com"
        zone = {(f"_25._tcp.{host}", "TLSA"): nodata(), (host, "A"): ok(["203.0.113.5"])}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_dane("example.com", {"mx_hosts": [host], "resolver_validates": True})
        self.assertIn("DANE_MISSING", self._codes(res))

    def test_valid_tlsa(self):
        host = "mx.example.com"
        zone = {(f"_25._tcp.{host}", "TLSA"): ok([(3, 1, 1, "ab" * 32)], ad=True),
                (host, "A"): ok(["203.0.113.5"], ad=True)}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_dane("example.com", {"mx_hosts": [host], "resolver_validates": True})
        self.assertEqual(self._codes(res), set())


# =====================================================================================
# DNSSEC
# =====================================================================================

class TestDNSSEC(unittest.TestCase):
    def test_signed_and_validated(self):
        zone = {("example.com", "SOA"): ok(["ns1.example.com"], ad=True),
                ("example.com", "DS"): ok([(12345, 13, 2)], ad=True),
                ("example.com", "DNSKEY"): ok([(257, 13)], ad=True)}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_dnssec("example.com", {"resolver_validates": True})
        self.assertEqual([f["code"] for f in res.findings], [])

    def test_unsigned(self):
        zone = {("example.com", "SOA"): ok(["ns1.example.com"]),
                ("example.com", "DS"): nodata(), ("example.com", "DNSKEY"): nodata()}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_dnssec("example.com", {"resolver_validates": True})
        self.assertIn("DNSSEC_MISSING", {f["code"] for f in res.findings})

    def test_no_ds(self):
        zone = {("example.com", "SOA"): ok(["ns1.example.com"]),
                ("example.com", "DS"): nodata(), ("example.com", "DNSKEY"): ok([(257, 13)])}
        aud = make_auditor(FakeResolver(zone))
        res = aud.check_dnssec("example.com", {"resolver_validates": True})
        self.assertIn("DNSSEC_NO_DS", {f["code"] for f in res.findings})


# =====================================================================================
# Hulpfuncties: domeinnormalisatie, merge_spf, mx_matches, CSV/Markdown-escaping
# =====================================================================================

class TestHelpers(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(mc.normalize_domain("HTTPS://Mijn.Example.NL/pad?x=1"), "mijn.example.nl")
        self.assertEqual(mc.normalize_domain("info@example.nl"), "example.nl")

    def test_normalize_rejects_ip(self):
        with self.assertRaises(ValueError):
            mc.normalize_domain("203.0.113.1")

    def test_mx_matches_wildcard(self):
        self.assertTrue(mc.mx_matches("*.mail.protection.outlook.com", "example-nl.mail.protection.outlook.com"))
        self.assertFalse(mc.mx_matches("*.example.com", "a.b.example.com"))

    def test_merge_spf(self):
        merged = mc.merge_spf(["v=spf1 ip4:192.0.2.1 -all", "v=spf1 include:x.example ~all"])
        self.assertTrue(merged.endswith("-all"))
        self.assertEqual(merged.count("-all"), 1)

    def test_csv_injection_escaped(self):
        self.assertEqual(mc._csv_cell("=1+2"), "'=1+2")
        self.assertEqual(mc._csv_cell("gewoon"), "gewoon")

    def test_markdown_escape_no_table_break(self):
        # De pijp moet geëscaped zijn met precies één backslash, zodat de tabel niet breekt
        self.assertEqual(mc._md("a|b"), "a\\|b")
        self.assertEqual(mc._md("a\\b"), "a\\\\b")


# =====================================================================================
# Einde-tot-einde: build_report en de CLI (exitcodes), Microsoft-365-achtig scenario
# =====================================================================================

def m365_like_zone():
    """Een domein op een niet-DNSSEC-mailprovider (zoals Microsoft 365), met een 1024-bit
    DKIM-selector naast een 2048-bit selector. Volledig fictief (documentatie-IP's, example.nl)."""
    host = "example-nl.mail.protection.outlook.com"
    return FakeResolver({
        ("example.nl", "SOA"): ok(["ns1.example.net"], ad=True),
        ("example.nl", "MX"): ok([(0, host)], ad=True),
        (host, "A"): ok(["192.0.2.10"], ad=False),
        (host, "CNAME"): err("SERVFAIL"),
        ("example.nl", "TXT"): ok(["v=spf1 ip4:198.51.100.20 -all"]),
        ("selector1._domainkey.example.nl", "TXT"): ok([f"v=DKIM1; k=rsa; p={rsa_spki_b64(2048)}"]),
        ("k1._domainkey.example.nl", "TXT"): ok([f"k=rsa; p={rsa_spki_b64(1024)}"]),
        ("_domainkey.example.nl", "TXT"): nodata(ad=True),
        ("_dmarc.example.nl", "TXT"): ok(["v=DMARC1;p=reject"], ad=True),
        ("_mta-sts.example.nl", "TXT"): nxdomain(),
        ("_smtp._tls.example.nl", "TXT"): nxdomain(),
        (f"_25._tcp.{host}", "TLSA"): err("SERVFAIL"),
        ("example.nl", "DS"): ok([(12345, 13, 2)], ad=True),
        ("example.nl", "DNSKEY"): ok([(257, 13)], ad=True),
        ("default._bimi.example.nl", "TXT"): nxdomain(),
    }, validates=True)


class TestEndToEnd(unittest.TestCase):
    def test_audit_domain_m365_like(self):
        resolver = m365_like_zone()
        results, ctx, fout = mc.audit_domain(
            resolver, "example.nl", list(mc.CHECKS),
            {"selectors": ["selector1", "k1"], "user_selectors": True, "http": False})
        self.assertIsNone(fout)
        codes = {f["code"] for r in results for f in r.findings}
        self.assertIn("DKIM_KEY_1024", codes)
        self.assertIn("DANE_MISSING", codes)
        self.assertIn("DMARC_NO_RUA", codes)
        # De DANE-fix: geen enkele check blijft 'niet vast te stellen' hangen
        self.assertFalse(any(r.dns_unknown for r in results))

    def test_cli_exit_code_and_verdict(self):
        resolver = m365_like_zone()

        def no_fetch(*a, **k):
            raise AssertionError("MTA-STS mag in passieve modus niet worden opgehaald")

        import datetime
        now = datetime.datetime(2026, 10, 17, 12, 56, tzinfo=datetime.timezone.utc)
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(buf):
            code = mc.main(["example.nl", "-s", "selector1", "-s", "k1", "--passief", "--no-color"],
                           resolver=resolver, fetch=no_fetch, now=now)
        # Zwaarste bevinding is MIDDEN (1024-bit DKIM) -> exitcode 1, niet 4 (onvolledig)
        self.assertEqual(code, 1)
        out = buf.getvalue()
        self.assertIn("example.nl", out)
        self.assertNotIn("onvolledig getest", out)

    def test_cli_usage_error(self):
        # argparse-fouten verlaten het programma met exitcode 3 (SystemExit)
        with self.assertRaises(SystemExit) as cm:
            mc.main(["--only", "spf"], resolver=FakeResolver())
        self.assertEqual(cm.exception.code, 3)


# =====================================================================================
# SPF-macro-expansie (RFC 7208 §7.4, canonieke voorbeelden)
# =====================================================================================

class TestSPFMacros(unittest.TestCase):
    def setUp(self):
        # Exact het voorbeeld uit RFC 7208 §7.4
        self.ev = mc.SPFEvaluator(FakeResolver(), "192.0.2.3",
                                  sender="strong-bad@email.example.com", helo="email.example.com")
        self.d = "email.example.com"

    def e(self, spec):
        return self.ev.expand(spec, self.d)

    def test_rfc7208_7_4_examples(self):
        cases = {
            "%{s}": "strong-bad@email.example.com",
            "%{o}": "email.example.com",
            "%{d}": "email.example.com",
            "%{d4}": "email.example.com",
            "%{d3}": "email.example.com",
            "%{d2}": "example.com",
            "%{d1}": "com",
            "%{dr}": "com.example.email",
            "%{d2r}": "example.email",
            "%{l}": "strong-bad",
            "%{l-}": "strong.bad",
            "%{lr}": "strong-bad",
            "%{lr-}": "bad.strong",
            "%{l1r-}": "strong",
        }
        for spec, want in cases.items():
            self.assertEqual(self.e(spec), want, f"{spec} -> {self.e(spec)!r}, verwacht {want!r}")

    def test_ir_v_composed(self):
        # %{ir}.%{v}._spf.%{d2}  ->  3.2.0.192.in-addr._spf.example.com
        self.assertEqual(self.e("%{ir}.%{v}._spf.%{d2}"), "3.2.0.192.in-addr._spf.example.com")

    def test_literal_and_specials(self):
        self.assertEqual(self.e("%%"), "%")
        self.assertEqual(self.e("%_"), " ")
        self.assertEqual(self.e("%-"), "%20")

    def test_uppercase_url_encodes(self):
        # Hoofdletter-macro's URL-escapen; '@' wordt %40
        self.assertEqual(self.e("%{S}"), "strong-bad%40email.example.com")

    def test_exists_macro_match(self):
        # exists met macro: query op de geëxpandeerde naam; bestaat die (A), dan 'pass'
        target = "3.2.0.192.in-addr._spf.example.com"
        zone = {
            ("example.com", "TXT"): ok(["v=spf1 exists:%{ir}._spf.%{d2} -all"]),
            (f"3.2.0.192._spf.example.com", "A"): ok(["127.0.0.1"]),
        }
        ev = mc.SPFEvaluator(FakeResolver(zone), "192.0.2.3", sender="a@example.com", helo="example.com")
        res, _ = ev.check("example.com")
        self.assertEqual(res, "pass")


# =====================================================================================
# --spf-ip-flow via de CLI
# =====================================================================================

class TestSpfIpFlow(unittest.TestCase):
    def _run_json(self, ip):
        import contextlib
        import json
        zone = FakeResolver({
            ("example.com", "SOA"): ok(["ns1.example.com"], ad=True),
            ("example.com", "TXT"): ok(["v=spf1 ip4:203.0.113.0/24 -all"]),
            ("example.com", "MX"): ok([(10, "mx.example.com")]),
            ("mx.example.com", "A"): ok(["203.0.113.10"]),
        })
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = mc.main(["example.com", "--only", "spf", "--spf-ip", ip, "--json"], resolver=zone)
        return code, json.loads(buf.getvalue())

    def test_spf_ip_pass(self):
        _, rep = self._run_json("203.0.113.9")
        tests = rep["spf_ip_tests"]
        self.assertEqual(tests[0]["ip"], "203.0.113.9")
        self.assertEqual(tests[0]["uitkomst"], "pass")

    def test_spf_ip_fail(self):
        _, rep = self._run_json("198.51.100.1")
        self.assertEqual(rep["spf_ip_tests"][0]["uitkomst"], "fail")

    def test_invalid_spf_ip_is_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            mc.main(["example.com", "--spf-ip", "geen-ip"], resolver=FakeResolver())
        self.assertEqual(cm.exception.code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
