#!/usr/bin/env python3
"""
mailcheck - audit van e-mailbeveiliging (SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, DANE, DNSSEC, BIMI)
met klantrapportage in HTML, Markdown, JSON en CSV.

Voorbeelden:
  python3 mailcheck.py klant.nl
  python3 mailcheck.py klant.nl -s selector1 -s google
  python3 mailcheck.py klant.nl klant.be --klant "Klant B.V." --uitvoerder "Jan Jansen, SecureCo" \\
          --referentie "PRJ-XXXX-XXX" --html rapport.html --md rapport.md --csv bevindingen.csv
  python3 mailcheck.py klant.nl --spf-ip 203.0.113.25          # mag dit IP namens klant.nl mailen?
  python3 mailcheck.py -f domeinen.txt -r 9.9.9.9 --json > resultaat.json

Standaarden: RFC 7208 (SPF), RFC 6376/8301/8463 (DKIM), RFC 9989/9990 (DMARC), RFC 5321/7505 (MX),
RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 7672 (DANE voor SMTP), RFC 4033-4035 (DNSSEC), RFC 8020.
De SPF-evaluatie slaagt voor alle 203 scenario's van de officiële RFC 7208-testsuite.

Exitcodes: 0 = geen bevindingen (of alleen Info), 1 = Laag/Midden, 2 = Hoog/Kritiek,
           3 = gebruiksfout, 4 = test (deels) niet uitvoerbaar door DNS-fouten.
Vereist: Python 3.8+ en dnspython (pip install dnspython).
"""
import argparse
import base64
import csv
import datetime
import html
import ipaddress
import json
import re
import ssl
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "3.0.1"

# CHANGELOG
# 3.0.1 - DANE: een TLSA-fout (SERVFAIL) op een mailserver waarvan de zone niet met DNSSEC is
#         ondertekend, wordt nu als definitief 'DANE niet mogelijk' (Laag) gerapporteerd in plaats
#         van 'niet vast te stellen'. Daardoor krijgen domeinen bij een niet-DNSSEC-mailprovider
#         (bijv. Microsoft 365) niet langer onterecht het oordeel 'onvolledig getest' (exitcode 4).
#       - Markdown-rapport: _md() escapet nu eerst de backslash en daarna de overige speciale tekens
#         (incl. '|'); voorheen maakte het backslash-escapen de pijp-escape ongedaan, waardoor DNS-
#         data met een '|' een tabel kon breken.
# 3.0.0 - Eerste release van deze generatie.

# =====================================================================================
# Ernstniveaus, onderdelen en testcatalogus
# =====================================================================================

KRITIEK, HOOG, MIDDEN, LAAG, INFO = "Kritiek", "Hoog", "Midden", "Laag", "Info"
ERNST_ORDE = {INFO: 0, LAAG: 1, MIDDEN: 2, HOOG: 3, KRITIEK: 4}
ERNSTEN = (KRITIEK, HOOG, MIDDEN, LAAG, INFO)
ERNST_UITLEG = {
    KRITIEK: "Het domein is vrijwel onbeschermd tegen misbruik, of e-mail wordt niet meer betrouwbaar afgeleverd. "
             "Direct oplossen.",
    HOOG: "Een belangrijke beschermingsmaatregel ontbreekt of werkt niet. Op korte termijn oplossen.",
    MIDDEN: "Bescherming is aanwezig maar onvolledig of zwak. Inplannen om op te lossen.",
    LAAG: "Verbeterpunt volgens best practice met beperkt risico.",
    INFO: "Ter informatie; geen direct risico.",
}

CHECKS = ("MX", "SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "DANE", "DNSSEC", "BIMI")
CHECK_UITLEG = {
    "MX": "Mailservers die e-mail voor het domein ontvangen (RFC 5321, RFC 7505).",
    "SPF": "Sender Policy Framework (RFC 7208): legt vast welke servers namens het domein e-mail mogen versturen.",
    "DKIM": "DomainKeys Identified Mail (RFC 6376): digitale handtekening die aantoont dat een bericht van het "
            "domein afkomstig is en onderweg niet is gewijzigd.",
    "DMARC": "Domain-based Message Authentication, Reporting and Conformance (RFC 9989): bepaalt wat ontvangers "
             "doen met mail die SPF en DKIM niet doorstaat, en regelt rapportage aan de domeineigenaar.",
    "MTA-STS": "SMTP MTA Strict Transport Security (RFC 8461): dwingt versleutelde aflevering van inkomende mail "
               "af en voorkomt dat aanvallers de versleuteling kunnen uitschakelen.",
    "TLS-RPT": "SMTP TLS Reporting (RFC 8460): rapportage over problemen met versleutelde mailaflevering.",
    "DANE": "DNS-based Authentication of Named Entities voor SMTP (RFC 7672): legt via DNSSEC vast welk "
            "certificaat de mailserver gebruikt, zodat versleuteling niet kan worden onderschept.",
    "DNSSEC": "DNS Security Extensions (RFC 4033-4035): beschermt DNS-antwoorden tegen vervalsing. Voorwaarde "
              "voor DANE en een betrouwbare basis voor SPF, DKIM en DMARC.",
    "BIMI": "Brand Indicators for Message Identification: toont het logo van de organisatie in mailprogramma's. "
            "Optioneel; vereist een handhavend DMARC-beleid.",
}

# id: (onderdeel, korte naam, wat er gecontroleerd wordt)
TESTS = {
    "MX-01": ("MX", "Mailontvangst ingericht", "De MX-records worden opgevraagd; vastgesteld wordt of het domein mail "
                                               "ontvangt, of expliciet geen mail ontvangt via een null-MX (RFC 7505)."),
    "MX-02": ("MX", "Geldige mailservers", "Elke mailserver heeft een IPv4- of IPv6-adres, is geen IP-adres en geen "
                                          "CNAME (RFC 5321, RFC 2181)."),
    "SPF-01": ("SPF", "SPF-record aanwezig", "Er is een TXT-record met v=spf1 gepubliceerd op het domein."),
    "SPF-02": ("SPF", "Eén SPF-record", "Er is precies één SPF-record (meerdere records maken SPF ongeldig)."),
    "SPF-03": ("SPF", "Geldige syntax", "Het record en alle records waarnaar het verwijst zijn syntactisch geldig "
                                        "volgens RFC 7208."),
    "SPF-04": ("SPF", "Uitkomst voor onbevoegden", "Het SPF-record wordt geëvalueerd zoals een ontvangende mailserver dat "
                                                   "doet, voor willekeurige niet-geautoriseerde IPv4- en IPv6-adressen. "
                                                   "De uitkomst moet fail (-all) of softfail (~all) zijn."),
    "SPF-05": ("SPF", "DNS-lookuplimieten", "Bij evaluatie blijven het aantal DNS-lookups (max. 10), het aantal "
                                           "lege lookups (max. 2) en het aantal MX-records per mx-mechanisme "
                                           "(max. 10) binnen de limieten."),
    "SPF-06": ("SPF", "Geldige verwijzingen", "Alle includes en redirects verwijzen naar bestaande, enkelvoudige "
                                              "SPF-records en zijn bereikbaar via DNS."),
    "SPF-07": ("SPF", "Veilige mechanismen", "Geen gebruik van het verouderde ptr-mechanisme en geen zeer brede "
                                             "IP-bereiken in de eigen SPF-records."),
    "DKIM-01": ("DKIM", "DKIM-sleutel aanwezig", "Er wordt gezocht naar publieke DKIM-sleutels op de opgegeven of "
                                                 "veelgebruikte selectors; daarnaast wordt via RFC 8020 vastgesteld of "
                                                 "er überhaupt sleutels onder _domainkey bestaan."),
    "DKIM-02": ("DKIM", "Sleutelsterkte", "RSA-sleutels zijn minimaal 2048 bit (of Ed25519) en staan SHA-256 toe."),
    "DKIM-03": ("DKIM", "Geldig sleutelrecord", "Het sleutelrecord is syntactisch geldig, de sleutel is leesbaar en "
                                                "bruikbaar voor e-mail."),
    "DKIM-04": ("DKIM", "Productiestatus", "Sleutels staan niet in testmodus (t=y); ingetrokken sleutels worden "
                                           "gesignaleerd."),
    "DMARC-01": ("DMARC", "DMARC-record aanwezig", "Er is een DMARC-record op _dmarc.<domein>, of het domein valt onder "
                                                   "het record van zijn organisatiedomein (DNS tree walk, RFC 9989)."),
    "DMARC-02": ("DMARC", "Geldig record", "Er is precies één record; v=DMARC1 staat vooraan en alle tags en "
                                           "waarden zijn geldig."),
    "DMARC-03": ("DMARC", "Handhavend beleid", "Het beleid is quarantine of reject, en niet alleen monitoren (none)."),
    "DMARC-04": ("DMARC", "Subdomeinbeleid", "Bestaande (sp=) en niet-bestaande (np=) subdomeinen zijn niet "
                                             "uitgezonderd van het beleid."),
    "DMARC-05": ("DMARC", "Volledige handhaving", "Het beleid wordt volledig toegepast: geen testmodus (t=y) en geen "
                                                  "pct onder 100."),
    "DMARC-06": ("DMARC", "Rapportage", "Er is een geldig rapportadres (rua=); externe ontvangers zijn geautoriseerd "
                                        "en het rapportdomein kan mail ontvangen."),
    "DMARC-07": ("DMARC", "Alignment", "De alignment-instellingen voor SPF (aspf) en DKIM (adkim) worden vastgelegd."),
    "DMARC-08": ("DMARC", "Basis voor DMARC", "Er is ten minste SPF of DKIM ingericht, zodat legitieme mail DMARC "
                                              "kan doorstaan."),
    "MTASTS-01": ("MTA-STS", "MTA-STS-record", "Er is een geldig TXT-record op _mta-sts.<domein> (v=STSv1; id=...)."),
    "MTASTS-02": ("MTA-STS", "Beleid bereikbaar", "Het beleid is bereikbaar via https://mta-sts.<domein>/.well-known/"
                                                  "mta-sts.txt met een geldig certificaat, zonder doorverwijzing."),
    "MTASTS-03": ("MTA-STS", "Geldig beleid", "Het beleid bevat geldige waarden voor version, mode, mx en max_age."),
    "MTASTS-04": ("MTA-STS", "Handhavende modus", "Het beleid staat op mode: enforce."),
    "MTASTS-05": ("MTA-STS", "MX-dekking", "Alle mailservers (MX) van het domein vallen onder de mx-regels van het "
                                          "beleid."),
    "TLSRPT-01": ("TLS-RPT", "TLS-RPT-record", "Er is precies één geldig TLS-RPT-record op _smtp._tls.<domein> met "
                                               "een geldig rapportadres."),
    "DANE-01": ("DANE", "TLSA-records", "Voor elke mailserver is een TLSA-record gepubliceerd op _25._tcp.<mailserver>."),
    "DANE-02": ("DANE", "DNSSEC-validatie TLSA", "De TLSA-records zijn met DNSSEC beveiligd en gevalideerd."),
    "DANE-03": ("DANE", "Geschikte TLSA-parameters", "De TLSA-records gebruiken voor SMTP geschikte parameters "
                                                     "(usage 2 of 3) en hebben een geldige hashlengte."),
    "DNSSEC-01": ("DNSSEC", "Domein ondertekend", "Het domein heeft een DS-record bij de bovenliggende zone en "
                                                  "DNSKEY-records."),
    "DNSSEC-02": ("DNSSEC", "Geldige validatie", "Een validerende resolver kan de DNSSEC-keten van het domein "
                                                 "valideren."),
    "BIMI-01": ("BIMI", "BIMI-record", "Indien aanwezig: het BIMI-record op default._bimi.<domein> is geldig en "
                                       "het DMARC-beleid voldoet aan de BIMI-vereisten."),
}

# =====================================================================================
# Bevindingencatalogus. Teksten mogen {domain} en de keyword-argumenten van Result.find() bevatten.
# =====================================================================================

FINDINGS = {
    # ------------------------------------------------------------------ MX
    "MX_NONE": dict(
        test="MX-01", ernst=INFO, titel="Domein ontvangt geen e-mail (geen MX-records)",
        risico="Zonder MX-records en zonder IP-adres op het domein ontvangt {domain} geen e-mail. Domeinen die geen "
               "mail gebruiken zijn een geliefd doelwit voor spoofing, omdat misbruik niet opvalt.",
        oplossing="Maak expliciet dat het domein geen mail gebruikt: publiceer een null-MX, een SPF-record dat alles "
                  "weigert en een DMARC-record met p=reject.",
        voorbeeld='{domain}. MX 0 .\n{domain}. TXT "v=spf1 -all"\n_dmarc.{domain}. TXT "v=DMARC1; p=reject"',
        ref="RFC 7505, RFC 7208, RFC 9989"),
    "MX_IMPLICIT": dict(
        test="MX-01", ernst=LAAG, titel="Geen MX-records; mail wordt afgeleverd op het IP-adres van het domein",
        risico="Zonder MX-records leveren verzendende servers mail af op het IP-adres van {domain} zelf (impliciete "
               "MX, RFC 5321). Meestal is dat een webserver, waardoor mail vertraagd raakt of verloren gaat, en "
               "kan de webserver onbedoeld als mailserver worden benaderd.",
        oplossing="Publiceer de juiste MX-records als het domein mail moet ontvangen, of een null-MX als dat niet zo is.",
        voorbeeld="{domain}. MX 0 .", ref="RFC 5321 §5.1, RFC 7505"),
    "MX_NULL_MIXED": dict(
        test="MX-01", ernst=MIDDEN, titel="Null-MX gecombineerd met andere MX-records",
        risico="Een null-MX ('.') geeft aan dat het domein geen mail ontvangt en moet het enige MX-record zijn. In "
               "combinatie met andere MX-records is de configuratie tegenstrijdig en gedragen verzenders zich "
               "onvoorspelbaar.",
        oplossing="Verwijder óf de null-MX (als het domein mail ontvangt), óf alle andere MX-records.",
        ref="RFC 7505 §3"),
    "MX_NO_ADDRESS": dict(
        test="MX-02", ernst=HOOG, titel="Mailserver zonder IP-adres",
        risico="De mailserver {host} heeft geen IPv4- of IPv6-adres. Verzenders kunnen daar geen mail afleveren; "
               "als dit de enige of primaire mailserver is, raakt mail vertraagd of gaat ze verloren.",
        oplossing="Corrigeer de hostnaam in het MX-record of publiceer het juiste A/AAAA-record voor {host}.",
        ref="RFC 5321 §5.1"),
    "MX_IP_LITERAL": dict(
        test="MX-02", ernst=MIDDEN, titel="MX-record verwijst naar een IP-adres",
        risico="Het MX-record bevat het IP-adres {host} in plaats van een hostnaam. Dat is niet toegestaan; veel "
               "verzenders kunnen deze mailserver daardoor niet bereiken.",
        oplossing="Vervang het IP-adres door een hostnaam met een A/AAAA-record.",
        ref="RFC 5321 §5.1, RFC 1035"),
    "MX_CNAME": dict(
        test="MX-02", ernst=LAAG, titel="MX-record verwijst naar een CNAME",
        risico="De mailserver {host} is een alias (CNAME). Dat is volgens de standaard niet toegestaan en kan bij "
               "sommige verzenders tot afleverproblemen leiden.",
        oplossing="Laat het MX-record direct naar de uiteindelijke hostnaam (met A/AAAA-record) verwijzen.",
        ref="RFC 2181 §10.3"),
    # ------------------------------------------------------------------ SPF
    "SPF_MISSING": dict(
        test="SPF-01", ernst=HOOG, titel="Geen SPF-record aanwezig",
        risico="Ontvangende mailservers kunnen niet controleren welke servers namens {domain} mogen mailen. Daardoor "
               "is het eenvoudiger om e-mail met een vervalst afzenderadres te versturen (spoofing, phishing), en "
               "wordt legitieme mail vaker als spam gezien.",
        oplossing="Publiceer één TXT-record op {domain} met alle diensten die namens het domein e-mail versturen "
                  "(bijvoorbeeld de mailprovider, de nieuwsbriefdienst en het CRM-systeem), afgesloten met -all. "
                  "Verstuurt het domein geen e-mail, publiceer dan 'v=spf1 -all'.",
        voorbeeld='{domain}. TXT "v=spf1 include:<spf-domein-van-mailprovider> -all"', ref="RFC 7208"),
    "SPF_MULTIPLE": dict(
        test="SPF-02", ernst=HOOG, titel="Meerdere SPF-records gepubliceerd",
        risico="De SPF-standaard staat precies één SPF-record per domein toe. Met meerdere records levert de "
               "controle een permanente fout (permerror) op. Ontvangers behandelen SPF dan als ongeldig, waardoor "
               "zowel de bescherming als de afleverbaarheid achteruitgaat.",
        oplossing="Voeg alle mechanismen samen in één record en verwijder de overige records. Het voorbeeld is een "
                  "samengevoegde versie van de huidige records; controleer of alle verzenders erin staan voordat u "
                  "het publiceert.",
        ref="RFC 7208 §4.5"),
    "SPF_SYNTAX": dict(
        test="SPF-03", ernst=HOOG, titel="SPF-record bevat een syntaxfout",
        risico="Het SPF-record van {target} bevat een fout ({reason}). Ontvangers geven dan een permanente fout "
               "(permerror) en behandelen SPF als ongeldig, waardoor de bescherming wegvalt en legitieme mail kan "
               "worden geweigerd.",
        oplossing="Corrigeer de genoemde term. Let op typefouten, ontbrekende dubbele punten, ongeldige IP-adressen "
                  "of netmaskers, en spaties of regeleinden binnen termen.",
        ref="RFC 7208 §4.6, §12"),
    "SPF_PASS_ALL": dict(
        test="SPF-04", ernst=KRITIEK, titel="SPF keurt mail van iedere server goed",
        risico="Een willekeurig, niet-geautoriseerd IP-adres krijgt de SPF-uitkomst 'pass' ({info}). Iedereen kan "
               "daardoor mail versturen die namens {domain} door SPF wordt goedgekeurd. SPF biedt zo geen enkele "
               "bescherming en maakt vervalste berichten juist geloofwaardiger.",
        oplossing="Verwijder +all (of het te ruime bereik) en sluit het record af met -all, nadat is gecontroleerd dat "
                  "alle legitieme verzenders in het record staan.",
        ref="RFC 7208 §5.1"),
    "SPF_NEUTRAL": dict(
        test="SPF-04", ernst=MIDDEN, titel="SPF geeft geen oordeel over onbevoegde servers",
        risico="Voor een niet-geautoriseerde server is de SPF-uitkomst 'neutral' ({info}). Ontvangers krijgen "
               "daardoor geen signaal om vervalste mail te weigeren.",
        oplossing="Sluit het record af met -all (of ~all als tussenstap) in plaats van ?all, of voeg een "
                  "afsluitend all-mechanisme toe.",
        ref="RFC 7208 §2.6.2, §5.1"),
    "SPF_AFTER_ALL": dict(
        test="SPF-04", ernst=LAAG, titel="Termen na 'all' worden genegeerd",
        risico="Alles wat na het all-mechanisme staat ({info}), wordt door ontvangers genegeerd. Verzenders die "
               "daar staan zijn in de praktijk niet geautoriseerd, waardoor hun legitieme mail kan worden geweigerd.",
        oplossing="Verplaats de betreffende termen naar vóór het all-mechanisme.", ref="RFC 7208 §5.1, §6.1"),
    "SPF_LOOKUPS_EXCEEDED": dict(
        test="SPF-05", ernst=HOOG, titel="SPF overschrijdt de limiet van 10 DNS-lookups",
        risico="Bij evaluatie zijn meer dan 10 DNS-lookups nodig ({info}). Ontvangers geven dan een permerror en "
               "behandelen SPF als mislukt; legitieme mail kan daardoor worden geweigerd of als spam worden "
               "gemarkeerd.",
        oplossing="Verminder het aantal lookups. Verwijder includes van diensten die niet meer worden gebruikt, "
                  "vervang a- en mx-mechanismen door vaste ip4- en ip6-adressen, en zet bulkmail eventueel op een "
                  "apart subdomein met een eigen SPF-record.",
        ref="RFC 7208 §4.6.4"),
    "SPF_LOOKUPS_HIGH": dict(
        test="SPF-05", ernst=LAAG, titel="SPF zit dicht bij de lookup-limiet",
        risico="Het record gebruikt {count} van de maximaal 10 DNS-lookups. Een extra dienst, of een wijziging in "
               "de include van een leverancier, kan de limiet overschrijden en SPF ongeldig maken.",
        oplossing="Ruim ongebruikte includes op en houd ruimte vrij voor toekomstige diensten.",
        ref="RFC 7208 §4.6.4"),
    "SPF_VOID_LIMIT": dict(
        test="SPF-05", ernst=HOOG, titel="SPF overschrijdt de limiet van 2 lege DNS-lookups",
        risico="Meer dan twee mechanismen verwijzen naar namen zonder DNS-gegevens ({info}). Ontvangers geven dan "
               "een permerror en behandelen SPF als mislukt.",
        oplossing="Verwijder of corrigeer a-, mx- en exists-mechanismen die naar niet-bestaande namen verwijzen.",
        ref="RFC 7208 §4.6.4"),
    "SPF_MX_LIMIT": dict(
        test="SPF-05", ernst=HOOG, titel="mx-mechanisme verwijst naar meer dan 10 mailservers",
        risico="Een mx-mechanisme levert meer dan 10 MX-records op ({info}). Dat geeft een permerror, waardoor SPF "
               "als ongeldig wordt behandeld.",
        oplossing="Vervang het mx-mechanisme door expliciete ip4/ip6-bereiken of de include van de mailprovider.",
        ref="RFC 7208 §4.6.4"),
    "SPF_INCLUDE_NONE": dict(
        test="SPF-06", ernst=HOOG, titel="SPF verwijst naar een domein zonder SPF-record",
        risico="Een include of redirect verwijst naar {target}, dat zelf geen SPF-record heeft. Dit levert een "
               "permerror op, waardoor SPF voor {domain} als ongeldig wordt behandeld. Vaak gaat het om een dienst "
               "die niet meer wordt gebruikt, of om een typefout.",
        oplossing="Controleer of de verwijzing nog nodig en correct gespeld is, en verwijder of corrigeer deze.",
        ref="RFC 7208 §5.2, §6.1"),
    "SPF_INCLUDE_MULTIPLE": dict(
        test="SPF-06", ernst=HOOG, titel="Verwezen domein heeft meerdere SPF-records",
        risico="Het domein {target}, waarnaar het SPF-record verwijst, heeft meer dan één SPF-record. Dat levert "
               "een permerror op, waardoor SPF voor {domain} als ongeldig wordt behandeld.",
        oplossing="Laat de beheerder van {target} de records samenvoegen, of verwijs naar een andere include van de "
                  "dienstverlener.",
        ref="RFC 7208 §4.5"),
    "SPF_LOOP": dict(
        test="SPF-06", ernst=HOOG, titel="Kringverwijzing in SPF",
        risico="Includes of redirects verwijzen direct of indirect naar elkaar terug ({info}). Ontvangers lopen dan "
               "tegen de lookup-limiet aan en geven een permerror, waardoor SPF als ongeldig wordt behandeld.",
        oplossing="Pas de include- en redirect-verwijzingen aan, zodat er geen kringverwijzing meer ontstaat.",
        ref="RFC 7208 §4.6.4"),
    "SPF_TEMPERROR": dict(
        test="SPF-06", ernst=MIDDEN, titel="DNS-fout bij het evalueren van SPF",
        risico="Tijdens de evaluatie trad een DNS-fout op ({info}). Ontvangers krijgen dan een tijdelijke fout "
               "(temperror) en kunnen mail uitstellen of afwijzen. Bij een structurele fout werkt SPF in de "
               "praktijk niet.",
        oplossing="Controleer of de genoemde naam correct gespeld is en of de DNS-servers ervan bereikbaar zijn. "
                  "Herhaal de test om een tijdelijke storing uit te sluiten.",
        ref="RFC 7208 §2.6.6"),
    "SPF_PTR": dict(
        test="SPF-07", ernst=LAAG, titel="Gebruik van het verouderde ptr-mechanisme",
        risico="Het ptr-mechanisme is traag en onbetrouwbaar. De standaard raadt het af en sommige ontvangers "
               "negeren het.",
        oplossing="Vervang ptr door expliciete ip4-, ip6- of include-mechanismen.", ref="RFC 7208 §5.5"),
    "SPF_WIDE_RANGE": dict(
        test="SPF-07", ernst=MIDDEN, titel="SPF autoriseert een zeer groot IP-bereik",
        risico="Het bereik {range} omvat tienduizenden of meer IP-adressen. Iedereen die een adres binnen dit "
               "bereik gebruikt, kan mail versturen die door SPF wordt goedgekeurd.",
        oplossing="Beperk het bereik tot de mailservers die daadwerkelijk worden gebruikt.", ref="RFC 7208 §5.6"),
    # ------------------------------------------------------------------ DKIM
    "DKIM_NONE_PUBLISHED": dict(
        test="DKIM-01", ernst=HOOG, titel="Er zijn geen DKIM-sleutels gepubliceerd",
        risico="Onder _domainkey.{domain} bestaat geen enkele DNS-naam (NXDOMAIN), dus er is op geen enkele "
               "selector een DKIM-sleutel gepubliceerd. Berichten van {domain} kunnen niet met DKIM worden "
               "geverifieerd; DMARC moet dan volledig op SPF steunen, wat faalt bij doorgestuurde mail.",
        oplossing="Schakel DKIM-ondertekening in bij elke dienst die namens {domain} mailt en publiceer de "
                  "bijbehorende publieke sleutel(s) in DNS.",
        voorbeeld='<selector>._domainkey.{domain}. TXT "v=DKIM1; k=rsa; p=<publieke sleutel>"',
        ref="RFC 6376, RFC 8020"),
    "DKIM_NOT_FOUND_GIVEN": dict(
        test="DKIM-01", ernst=HOOG, titel="Geen DKIM-sleutel gevonden op de opgegeven selector(s)",
        risico="Voor de opgegeven selector(s) ({selectors}) is geen DKIM-sleutel gepubliceerd. Berichten die met "
               "deze selector worden ondertekend, falen daardoor de DKIM-controle.",
        oplossing="Publiceer de publieke sleutel voor deze selector, of controleer in de header 'DKIM-Signature' "
                  "van een verzonden bericht welke selector (s=) werkelijk wordt gebruikt.",
        voorbeeld='<selector>._domainkey.{domain}. TXT "v=DKIM1; k=rsa; p=<publieke sleutel>"', ref="RFC 6376"),
    "DKIM_NOT_FOUND": dict(
        test="DKIM-01", ernst=MIDDEN, titel="DKIM niet aangetroffen op gangbare selectors",
        risico="Er bestaan DNS-namen onder _domainkey.{domain}, maar op {count} veelgebruikte selectors is geen "
               "sleutel gevonden. Waarschijnlijk gebruikt het domein een afwijkende selector; het is echter niet "
               "aangetoond dat DKIM werkt.",
        oplossing="Bekijk de header 'DKIM-Signature' van een recent verzonden bericht; de selector staat achter "
                  "s=. Voer de test opnieuw uit met die selector (-s).",
        ref="RFC 6376"),
    "DKIM_NO_USABLE": dict(
        test="DKIM-01", ernst=MIDDEN, titel="Geen bruikbare DKIM-sleutel gevonden",
        risico="Op de gevonden selector(s) staan alleen ingetrokken of onbruikbare sleutels. Mogelijk ondertekent "
               "het domein met een andere selector, maar het is niet aangetoond dat DKIM werkt.",
        oplossing="Bekijk de header 'DKIM-Signature' van een recent verzonden bericht; de selector staat achter s=. "
                  "Voer de test opnieuw uit met die selector (-s), of richt DKIM in bij de mailprovider.",
        ref="RFC 6376"),
    "DKIM_KEY_WEAK": dict(
        test="DKIM-02", ernst=HOOG, titel="DKIM-sleutel is te zwak",
        risico="De sleutel van selector '{selector}' is {bits} bit. Sleutels korter dan 1024 bit worden door "
               "ontvangers geweigerd en zijn te kraken, waardoor handtekeningen vervalst kunnen worden.",
        oplossing="Genereer een nieuw sleutelpaar van minimaal 2048 bit, publiceer dit onder een nieuwe selector, en "
                  "trek daarna de oude sleutel in (lege p=).",
        ref="RFC 8301 §3.2"),
    "DKIM_KEY_1024": dict(
        test="DKIM-02", ernst=MIDDEN, titel="DKIM-sleutel van 1024 bit is verouderd",
        risico="Selector '{selector}' gebruikt een RSA-sleutel van {bits} bit. Dat is het minimum dat de standaard "
               "toestaat, maar het geldt niet meer als voldoende sterk voor de lange termijn.",
        oplossing="Roteer naar een sleutel van 2048 bit. Publiceer de nieuwe sleutel onder een nieuwe selector, "
                  "schakel de mailservers om en trek daarna de oude sleutel in.",
        ref="RFC 8301 §3.2"),
    "DKIM_SHA1": dict(
        test="DKIM-02", ernst=MIDDEN, titel="DKIM-sleutel staat alleen SHA-1 toe",
        risico="Selector '{selector}' staat alleen SHA-1 toe (h={h}). SHA-1 mag niet meer worden gebruikt voor "
               "ondertekening; ontvangers mogen zulke handtekeningen als ongeldig behandelen.",
        oplossing="Verwijder de h=-tag of zet deze op sha256, en onderteken met rsa-sha256.", ref="RFC 8301 §3.1"),
    "DKIM_RECORD_INVALID": dict(
        test="DKIM-03", ernst=HOOG, titel="DKIM-sleutelrecord is ongeldig",
        risico="Het sleutelrecord van selector '{selector}' is ongeldig ({reason}). Ontvangers kunnen handtekeningen "
               "met deze selector niet verifiëren, waardoor DKIM faalt.",
        oplossing="Publiceer het record opnieuw zoals de mailprovider het aanlevert. Let op afgekapte records en op "
                  "ongewenste spaties of aanhalingstekens bij het splitsen van lange TXT-records.",
        ref="RFC 6376 §3.6.1, RFC 8463"),
    "DKIM_SERVICE": dict(
        test="DKIM-03", ernst=MIDDEN, titel="DKIM-sleutel is niet bruikbaar voor e-mail",
        risico="Selector '{selector}' beperkt de sleutel tot service type s={s}. Voor e-mail moet dit 'email' of "
               "'*' zijn; anders worden handtekeningen niet geaccepteerd.",
        oplossing="Verwijder de s=-tag of zet deze op email.", ref="RFC 6376 §3.6.1"),
    "DKIM_UNKNOWN_KEYTYPE": dict(
        test="DKIM-03", ernst=LAAG, titel="Onbekend DKIM-sleuteltype",
        risico="Selector '{selector}' gebruikt sleuteltype '{ktype}'. Ontvangers ondersteunen dit niet.",
        oplossing="Gebruik k=rsa (minimaal 2048 bit) of k=ed25519, eventueel naast elkaar.", ref="RFC 8463"),
    "DKIM_TESTMODE": dict(
        test="DKIM-04", ernst=LAAG, titel="DKIM-sleutel staat in testmodus (t=y)",
        risico="Met t=y geeft het domein aan dat DKIM nog getest wordt. Ontvangers mogen mislukte verificaties dan "
               "negeren.",
        oplossing="Verwijder t=y uit het record van selector '{selector}' zodra DKIM correct werkt.",
        ref="RFC 6376 §3.6.1"),
    "DKIM_REVOKED": dict(
        test="DKIM-04", ernst=INFO, titel="Ingetrokken DKIM-sleutel gepubliceerd",
        risico="Selector '{selector}' heeft een lege sleutel (p=). Dit is de juiste manier om een oude sleutel in te "
               "trekken en vormt geen risico.",
        oplossing="Geen actie nodig, zolang deze selector niet meer wordt gebruikt om te ondertekenen.",
        ref="RFC 6376 §3.6.1"),
    # ------------------------------------------------------------------ DMARC
    "DMARC_MISSING": dict(
        test="DMARC-01", ernst=HOOG, titel="Geen DMARC-record aanwezig",
        risico="Zonder DMARC krijgen ontvangers geen instructie over wat ze moeten doen met mail die SPF of DKIM niet "
               "doorstaat, en ontvangt de organisatie geen rapportages over misbruik. Spoofing van {domain} wordt "
               "daardoor nauwelijks tegengehouden. Grote mailproviders zoals Google, Yahoo en Microsoft eisen "
               "bovendien DMARC van bulkverzenders.",
        oplossing="Publiceer een DMARC-record. Begin met p=none om rapporten te verzamelen, analyseer welke diensten "
                  "namens het domein mailen, en voer het beleid daarna binnen enkele weken op naar quarantine en "
                  "vervolgens reject. Vervang het voorbeeld-rapportadres door een eigen mailbox of DMARC-dienst.",
        voorbeeld='_dmarc.{domain}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"', ref="RFC 9989"),
    "DMARC_MULTIPLE": dict(
        test="DMARC-02", ernst=HOOG, titel="Meerdere DMARC-records gepubliceerd",
        risico="Op _dmarc.{policy_domain} staan {count} DMARC-records. Ontvangers negeren dan alle records. {gevolg}",
        oplossing="Voeg de records samen tot één record en verwijder de overige.", ref="RFC 9989 §4.10"),
    "DMARC_V_NOT_FIRST": dict(
        test="DMARC-02", ernst=HOOG, titel="DMARC-record begint niet met v=DMARC1",
        risico="Het record op _dmarc.{policy_domain} begint niet met 'v=DMARC1' ({info}). Ontvangers negeren het "
               "volledige record. {gevolg}",
        oplossing="Zorg dat het record exact begint met 'v=DMARC1;', gevolgd door de overige tags.",
        ref="RFC 9989 §4.7"),
    "DMARC_INVALID_P": dict(
        test="DMARC-02", ernst=HOOG, titel="DMARC-beleid bevat een ongeldige waarde",
        risico="Het record bevat een ongeldige beleidswaarde ({info}). Ontvangers passen DMARC dan hoogstens toe "
               "alsof p=none is ingesteld, of slaan DMARC helemaal over. Er wordt dus geen actie ondernomen tegen "
               "vervalste mail.",
        oplossing="Corrigeer de waarde: voor p, sp en np zijn alleen none, quarantine en reject toegestaan.",
        ref="RFC 9989 §4.7, §4.10.1"),
    "DMARC_SYNTAX": dict(
        test="DMARC-02", ernst=MIDDEN, titel="DMARC-record bevat ongeldige waarden",
        risico="Het record bevat een ongeldige of dubbele tag ({info}). Ontvangers negeren zulke tags en vallen "
               "terug op de standaardwaarde, waardoor het beleid anders uitpakt dan bedoeld.",
        oplossing="Corrigeer de genoemde tag. Toegestane waarden staan in RFC 9989 §4.7.", ref="RFC 9989 §4.7"),
    "DMARC_UNKNOWN_TAG": dict(
        test="DMARC-02", ernst=LAAG, titel="DMARC-record bevat een onbekende tag",
        risico="De tag '{tag}' is geen DMARC-tag en wordt door ontvangers genegeerd. Vaak is het een typefout (zoals "
               "'rau' in plaats van 'rua'), waardoor een bedoelde instelling niet werkt.",
        oplossing="Verwijder de tag of corrigeer de spelling.", ref="RFC 9989 §4.7"),
    "DMARC_P_NONE": dict(
        test="DMARC-03", ernst=MIDDEN, titel="DMARC-beleid staat op alleen monitoren (p=none)",
        risico="Met p=none worden alleen rapporten verzameld. Ontvangers ondernemen geen actie tegen vervalste mail "
               "namens {domain}, waardoor het domein nog steeds kan worden misbruikt voor phishing.",
        oplossing="Controleer met de DMARC-rapporten dat alle legitieme mail SPF of DKIM doorstaat. Voer het beleid "
                  "daarna op naar p=quarantine, en uiteindelijk naar p=reject.",
        ref="RFC 9989 §4.7"),
    "DMARC_PARKED_NOT_REJECT": dict(
        test="DMARC-03", ernst=LAAG, titel="Domein zonder mailverkeer heeft geen reject-beleid",
        risico="Het domein verstuurt volgens SPF geen e-mail, maar het DMARC-beleid staat op {policy}. Voor zo'n "
               "domein is p=reject veilig en biedt het de sterkste bescherming.",
        oplossing="Zet het beleid op p=reject.", ref="RFC 9989, M3AAWG"),
    "DMARC_SP_NONE": dict(
        test="DMARC-04", ernst=MIDDEN, titel="Subdomeinen zijn uitgezonderd van DMARC (sp=none)",
        risico="Het hoofddomein is beschermd, maar sp=none schakelt de bescherming voor alle bestaande subdomeinen "
               "uit. Aanvallers kunnen dan bijvoorbeeld afzenders als factuur.{domain} vervalsen.",
        oplossing="Verwijder sp=none zodat subdomeinen het beleid van het hoofddomein volgen, of zet sp op "
                  "quarantine of reject.",
        ref="RFC 9989 §4.7"),
    "DMARC_NP_NONE": dict(
        test="DMARC-04", ernst=LAAG, titel="Niet-bestaande subdomeinen zijn uitgezonderd (np=none)",
        risico="Met np=none is er geen bescherming voor mail vanaf subdomeinen die niet eens bestaan, zoals "
               "willekeurig-verzonnen.{domain}. Juist zulke afzenders worden misbruikt voor phishing.",
        oplossing="Verwijder np=none of zet np=reject.", ref="RFC 9989 §4.7"),
    "DMARC_TESTMODE": dict(
        test="DMARC-05", ernst=MIDDEN, titel="DMARC-beleid staat in testmodus (t=y)",
        risico="Met t=y vraagt het domein ontvangers om het beleid een niveau lager toe te passen (reject wordt "
               "quarantine, quarantine wordt none). Het gepubliceerde beleid wordt dus niet volledig gehandhaafd.",
        oplossing="Verwijder t=y (of zet t=n) zodra de DMARC-rapporten laten zien dat alle legitieme mail slaagt.",
        ref="RFC 9989 §4.7"),
    "DMARC_PCT": dict(
        test="DMARC-05", ernst=LAAG, titel="DMARC-beleid geldt voor een deel van de mail (pct={pct})",
        risico="Ontvangers die nog de oude standaard volgen, passen het beleid slechts op {pct}% van de niet-conforme "
               "berichten toe. In de nieuwe standaard (RFC 9989) bestaat pct niet meer en wordt de tag genegeerd, "
               "waardoor het beleid onvoorspelbaar uitpakt.",
        oplossing="Verwijder de pct-tag. Gebruik t=y als u het beleid tijdelijk gefaseerd wilt invoeren.",
        ref="RFC 9989 Appendix A.6"),
    "DMARC_NO_RUA": dict(
        test="DMARC-06", ernst=LAAG, titel="Geen DMARC-rapportage ingesteld",
        risico="Zonder rua-adres ontvangt de organisatie geen rapporten. Misbruik van het domein en fouten in de "
               "inrichting van SPF en DKIM blijven daardoor onopgemerkt, en het beleid kan niet veilig worden "
               "aangescherpt.",
        oplossing="Voeg een rua-adres toe dat naar een eigen mailbox of een DMARC-analysedienst verwijst. Vervang het "
                  "voorbeeldadres door het gewenste adres.",
        ref="RFC 9990"),
    "DMARC_BAD_URI": dict(
        test="DMARC-06", ernst=LAAG, titel="Ongeldig DMARC-rapportadres",
        risico="Het rapportadres '{uri}' in {tag}= is geen geldig mailto:-adres, waardoor daar geen rapporten "
               "worden afgeleverd.",
        oplossing="Gebruik het formaat mailto:adres@domein.", ref="RFC 9990"),
    "DMARC_EXT_NOT_AUTH": dict(
        test="DMARC-06", ernst=LAAG, titel="Extern rapportadres is niet geautoriseerd",
        risico="Rapporten ({tag}) gaan naar {target}, een extern domein dat niet heeft bevestigd rapporten voor "
               "{policy_domain} te willen ontvangen. Ontvangers sturen de rapporten dan niet.",
        oplossing="Laat de beheerder van {target} het autorisatierecord publiceren. Bij een DMARC-dienst gebeurt "
                  "dit doorgaans automatisch; controleer anders de configuratie bij die dienst.",
        voorbeeld='{policy_domain}._report._dmarc.{target}. TXT "v=DMARC1"', ref="RFC 9990 §4"),
    "DMARC_RUA_NO_MX": dict(
        test="DMARC-06", ernst=LAAG, titel="Rapportdomein kan geen e-mail ontvangen",
        risico="Het rapportadres in {tag}= gebruikt domein {target}, maar dat domein heeft geen mailserver (geen MX "
               "en geen IP-adres, of een null-MX). Rapporten kunnen niet worden afgeleverd.",
        oplossing="Gebruik een rapportadres op een domein dat e-mail kan ontvangen.", ref="RFC 9990, RFC 5321"),
    "DMARC_NO_AUTH_BASIS": dict(
        test="DMARC-08", ernst=HOOG, titel="Handhavend DMARC-beleid zonder SPF of DKIM",
        risico="Het DMARC-beleid staat op {policy}, maar SPF {spf} en er is geen bruikbare DKIM-sleutel gevonden. "
               "Legitieme mail van {domain} kan DMARC daardoor niet doorstaan en wordt geweigerd of als spam "
               "afgeleverd.",
        oplossing="Richt SPF en DKIM in voor alle diensten die namens het domein mailen. Gebruikt het domein een "
                  "DKIM-selector die niet is gecontroleerd, test dan opnieuw met -s.",
        ref="RFC 9989 §4.4"),
    # ------------------------------------------------------------------ MTA-STS
    "MTASTS_MISSING": dict(
        test="MTASTS-01", ernst=LAAG, titel="MTA-STS is niet ingericht",
        risico="Zonder MTA-STS kan een aanvaller op het netwerkpad de versleuteling van inkomende mail voor {domain} "
               "uitschakelen (STARTTLS-downgrade) of mail omleiden naar een eigen server, waarna berichten "
               "onversleuteld kunnen worden meegelezen.",
        oplossing="Publiceer een MTA-STS-beleid op https://mta-sts.{domain}/.well-known/mta-sts.txt en een TXT-record "
                  "op _mta-sts.{domain}. Begin met mode: testing in combinatie met TLS-RPT en ga daarna naar "
                  "enforce.",
        voorbeeld='_mta-sts.{domain}. TXT "v=STSv1; id=20260101T000000"\n\n'
                  '# https://mta-sts.{domain}/.well-known/mta-sts.txt\nversion: STSv1\nmode: testing\n'
                  'mx: <mailserver-van-de-provider>\nmax_age: 604800',
        ref="RFC 8461"),
    "MTASTS_RECORD_INVALID": dict(
        test="MTASTS-01", ernst=MIDDEN, titel="MTA-STS-record is ongeldig",
        risico="Het TXT-record op _mta-sts.{domain} is ongeldig ({info}). Verzenders negeren het beleid dan.",
        oplossing="Publiceer precies één record in de vorm 'v=STSv1; id=<1-32 letters/cijfers>'.",
        ref="RFC 8461 §3.1"),
    "MTASTS_FETCH_FAILED": dict(
        test="MTASTS-02", ernst=MIDDEN, titel="MTA-STS-beleid is niet bereikbaar",
        risico="Het TXT-record kondigt een MTA-STS-beleid aan, maar het beleid kan niet worden opgehaald ({info}). "
               "Verzenders passen MTA-STS dan niet toe, waardoor de bescherming ontbreekt.",
        oplossing="Zorg dat https://mta-sts.{domain}/.well-known/mta-sts.txt bereikbaar is met een geldig certificaat "
                  "voor mta-sts.{domain}, status 200, Content-Type text/plain en zonder doorverwijzing.",
        ref="RFC 8461 §3.3"),
    "MTASTS_POLICY_INVALID": dict(
        test="MTASTS-03", ernst=MIDDEN, titel="MTA-STS-beleid is ongeldig",
        risico="Het opgehaalde beleid is ongeldig ({info}). Verzenders negeren het beleid dan.",
        oplossing="Corrigeer het beleid. Het moet de velden version: STSv1, mode, max_age en (behalve bij mode: none) "
                  "minstens één mx-regel bevatten.",
        ref="RFC 8461 §3.2"),
    "MTASTS_SHORT_MAXAGE": dict(
        test="MTASTS-03", ernst=LAAG, titel="MTA-STS max_age is erg kort",
        risico="Met max_age={max_age} seconden onthouden verzenders het beleid maar kort, waardoor een aanvaller na "
               "afloop de bescherming kan omzeilen.",
        oplossing="Gebruik een max_age van minimaal één week (604800) en bij voorkeur enkele maanden.",
        ref="RFC 8461 §3.2"),
    "MTASTS_TESTING": dict(
        test="MTASTS-04", ernst=LAAG, titel="MTA-STS staat in testmodus",
        risico="Met mode: {mode} wordt MTA-STS niet afgedwongen; verzenders rapporteren problemen alleen (via "
               "TLS-RPT), maar leveren bij een aanval toch onversleuteld af.",
        oplossing="Zet mode op enforce zodra de TLS-RPT-rapporten geen problemen meer laten zien.",
        ref="RFC 8461 §5"),
    "MTASTS_MX_MISMATCH": dict(
        test="MTASTS-05", ernst=HOOG, titel="Mailserver valt niet onder het MTA-STS-beleid",
        risico="De mailserver {host} staat niet in de mx-regels van het MTA-STS-beleid ({patterns}). In enforce-modus "
               "weigeren verzenders mail aan deze server af te leveren, waardoor mail vertraagd raakt of verloren gaat.",
        oplossing="Voeg de mailserver toe aan de mx-regels van het beleid en verhoog daarna de id in het TXT-record.",
        ref="RFC 8461 §4.1"),
    # ------------------------------------------------------------------ TLS-RPT
    "TLSRPT_MISSING": dict(
        test="TLSRPT-01", ernst=LAAG, titel="TLS-RPT is niet ingericht",
        risico="Zonder TLS-RPT ontvangt de organisatie geen meldingen als verzenders geen versleutelde verbinding "
               "met de mailservers van {domain} kunnen opzetten. Problemen met MTA-STS, DANE of certificaten "
               "blijven dan onopgemerkt.",
        oplossing="Publiceer een TLS-RPT-record met een rapportadres.",
        voorbeeld='_smtp._tls.{domain}. TXT "v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"', ref="RFC 8460"),
    "TLSRPT_INVALID": dict(
        test="TLSRPT-01", ernst=LAAG, titel="TLS-RPT-record is ongeldig",
        risico="Het record op _smtp._tls.{domain} is ongeldig ({info}). Verzenders sturen dan geen rapporten.",
        oplossing="Publiceer precies één record in de vorm 'v=TLSRPTv1; rua=mailto:adres@domein'.",
        ref="RFC 8460 §3"),
    # ------------------------------------------------------------------ DANE
    "DANE_MISSING": dict(
        test="DANE-01", ernst=LAAG, titel="DANE is niet ingericht voor de mailservers",
        risico="Voor de mailservers van {domain} zijn geen TLSA-records gepubliceerd. Verzenders kunnen daardoor niet "
               "via DNSSEC controleren of ze met de echte mailserver verbinden, waardoor versleuteling kan worden "
               "onderschept. DANE staat op de pas-toe-of-leg-uitlijst van het Forum Standaardisatie.",
        oplossing="Vraag de mailprovider om DANE (TLSA-records met usage 3 1 1 of 2 1 1) te ondersteunen. Dit vereist "
                  "dat de zone van de mailservers met DNSSEC is ondertekend.",
        ref="RFC 7672, Forum Standaardisatie"),
    "DANE_PARTIAL": dict(
        test="DANE-01", ernst=MIDDEN, titel="DANE is niet voor alle mailservers ingericht",
        risico="Voor {hosts} ontbreken TLSA-records, terwijl andere mailservers die wel hebben. Een aanvaller kan "
               "verzenders naar de onbeschermde server sturen.",
        oplossing="Publiceer TLSA-records voor alle mailservers.", ref="RFC 7672 §2.2"),
    "DANE_NOT_VALIDATED": dict(
        test="DANE-02", ernst=HOOG, titel="TLSA-records zijn niet met DNSSEC beveiligd",
        risico="Er zijn TLSA-records voor {host}, maar het antwoord is niet DNSSEC-gevalideerd. Verzenders negeren "
               "TLSA-records zonder DNSSEC, dus DANE werkt niet.",
        oplossing="Onderteken de zone van {host} met DNSSEC en zorg voor een DS-record bij de bovenliggende zone.",
        ref="RFC 7672 §2.2"),
    "DANE_BAD_PARAMS": dict(
        test="DANE-03", ernst=MIDDEN, titel="TLSA-record met ongeschikte parameters",
        risico="Het TLSA-record '{record}' voor {host} is ongeschikt voor SMTP ({reason}). Verzenders negeren zulke "
               "records, of kunnen de verbinding afbreken.",
        oplossing="Gebruik usage 3 (DANE-EE) of 2 (DANE-TA), selector 1 en matching type 1 (SHA-256), bijvoorbeeld "
                  "'3 1 1 <sha256-hash van de publieke sleutel>'.",
        ref="RFC 7672 §3.1, RFC 7671"),
    # ------------------------------------------------------------------ DNSSEC
    "DNSSEC_MISSING": dict(
        test="DNSSEC-01", ernst=MIDDEN, titel="Domein is niet met DNSSEC ondertekend",
        risico="Zonder DNSSEC kunnen DNS-antwoorden voor {domain} worden vervalst. Een aanvaller kan dan onder meer "
               "SPF-, DKIM-, DMARC- en MX-gegevens manipuleren. DANE is zonder DNSSEC niet mogelijk. DNSSEC staat op "
               "de pas-toe-of-leg-uitlijst van het Forum Standaardisatie.",
        oplossing="Activeer DNSSEC bij de DNS-provider en laat de registrar het DS-record bij de bovenliggende zone "
                  "publiceren.",
        ref="RFC 4033-4035, Forum Standaardisatie"),
    "DNSSEC_INCOMPLETE": dict(
        test="DNSSEC-01", ernst=HOOG, titel="DNSSEC is onvolledig geconfigureerd",
        risico="{info}. Hierdoor is de DNSSEC-keten verbroken: het domein is niet beveiligd, of validerende "
               "resolvers kunnen het domein niet meer opvragen.",
        oplossing="Controleer bij de DNS-provider en de registrar of DNSKEY- en DS-records overeenkomen.",
        ref="RFC 4035"),
    "DNSSEC_NO_DS": dict(
        test="DNSSEC-01", ernst=MIDDEN, titel="DNSSEC-ondertekening wordt niet gebruikt (DS ontbreekt)",
        risico="De zone {zone} is ondertekend, maar er staat geen DS-record bij de bovenliggende zone. Resolvers "
               "controleren de handtekeningen daardoor niet, zodat het domein in de praktijk niet door DNSSEC wordt "
               "beschermd.",
        oplossing="Laat de registrar het DS-record publiceren dat bij de huidige sleutel (KSK) van de zone hoort.",
        ref="RFC 4035, Forum Standaardisatie"),
    "DNSSEC_BOGUS": dict(
        test="DNSSEC-02", ernst=KRITIEK, titel="DNSSEC-validatie van het domein faalt",
        risico="Validerende resolvers kunnen de DNSSEC-handtekeningen van {domain} niet valideren (SERVFAIL). Voor "
               "gebruikers van zulke resolvers (waaronder veel grote mailproviders) is het domein onbereikbaar: "
               "e-mail en websites werken niet.",
        oplossing="Herstel de DNSSEC-configuratie direct: vervang verlopen handtekeningen of corrigeer het DS-record "
                  "bij de registrar (of trek het DS-record in als de zone niet meer wordt ondertekend).",
        ref="RFC 4035 §5.5"),
    # ------------------------------------------------------------------ BIMI
    "BIMI_INVALID": dict(
        test="BIMI-01", ernst=LAAG, titel="BIMI-record is ongeldig",
        risico="Het record op default._bimi.{domain} is ongeldig ({info}). Mailprogramma's tonen het logo dan niet.",
        oplossing="Publiceer het record in de vorm 'v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem'.",
        ref="BIMI (draft-brand-indicators-for-message-identification)"),
    "BIMI_DMARC_WEAK": dict(
        test="BIMI-01", ernst=LAAG, titel="DMARC-beleid voldoet niet aan de BIMI-vereisten",
        risico="Er is een BIMI-record, maar het DMARC-beleid ({info}) is niet streng genoeg. Mailprogramma's tonen "
               "het logo alleen bij p=quarantine of p=reject, volledig toegepast en zonder sp=none.",
        oplossing="Scherp het DMARC-beleid aan tot ten minste p=quarantine zonder pct, t=y of sp=none.",
        ref="BIMI"),
}

DEFAULT_SELECTORS = [
    "default", "dkim", "mail", "email", "smtp", "selector1", "selector2", "google", "s1", "s2", "s1024", "s2048",
    "k1", "k2", "k3", "key1", "key2", "sig1", "dkim1", "dkim2", "mx", "mxvault", "mandrill", "mailjet", "mailgun",
    "mg", "pic", "krs", "sendgrid", "smtpapi", "em", "hs1", "hs2", "sf1", "sf2", "zoho", "zmail", "zendesk1",
    "zendesk2", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "everlytickey1",
    "everlytickey2", "ctct1", "ctct2", "pm", "spop1024", "mailchimp", "mcdkim", "cm", "turbo-smtp", "scph0920",
    "intercom", "ms", "neolane", "mailo", "dk", "domk", "dkim-shared", "mimecast20190104", "brevo", "mail2",
]

# =====================================================================================
# DNS-laag
# =====================================================================================


class DNSResult:
    __slots__ = ("status", "rrs", "ad", "error")

    def __init__(self, status, rrs=None, ad=False, error=None):
        self.status = status      # ok | nxdomain | nodata | error
        self.rrs = list(rrs or [])
        self.ad = ad
        self.error = error


def _rr_value(rtype, rd):
    if rtype == "TXT":
        return b"".join(rd.strings).decode("utf-8", "replace")
    if rtype in ("A", "AAAA"):
        return rd.address
    if rtype == "MX":
        return (rd.preference, rd.exchange.to_text(omit_final_dot=True))
    if rtype in ("PTR", "CNAME"):
        return rd.target.to_text(omit_final_dot=True)
    if rtype == "TLSA":
        return (rd.usage, rd.selector, rd.mtype, rd.cert.hex())
    if rtype == "DS":
        return (rd.key_tag, rd.algorithm, rd.digest_type)
    if rtype == "DNSKEY":
        return (rd.flags, rd.algorithm)
    if rtype == "SOA":
        return rd.mname.to_text(omit_final_dot=True)
    return rd.to_text()


class RealResolver:
    """DNS via dnspython, met cache, logboek, DNSSEC-flags (DO/AD) en één herhaling bij een time-out."""

    def __init__(self, nameservers=None, timeout=5.0):
        try:
            import dns.exception
            import dns.flags
            import dns.name
            import dns.resolver
        except ImportError:
            sys.stderr.write("dnspython ontbreekt. Installeer met: pip install dnspython\n")
            sys.exit(3)
        self.dns = dns
        port = 53
        servers = []
        for ns in nameservers or []:
            m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::(\d+))?|([0-9.]+)(?::(\d+))?|([0-9a-fA-F:.]+)", ns.strip())
            if not m:
                raise ValueError(f"ongeldige resolver: {ns}")
            host = m.group(1) or m.group(3) or m.group(5)
            prt = m.group(2) or m.group(4)
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise ValueError(f"ongeldige resolver: {ns} (gebruik een IP-adres)")
            prt = int(prt) if prt else 53
            if servers and prt != port:
                raise ValueError("alle resolvers moeten dezelfde poort gebruiken")
            port = prt
            servers.append(host)
        self.resolvers = {}
        for cd in (False, True):
            r = dns.resolver.Resolver(configure=not servers)
            if servers:
                r.nameservers = servers
            r.port = port
            r.timeout = min(2.5, timeout)
            r.lifetime = timeout
            r.use_edns(0, dns.flags.DO, 1232)
            r.flags = dns.flags.RD | dns.flags.AD | (dns.flags.CD if cd else 0)
            r.cache = None
            self.resolvers[cd] = r
        self._cache = {}
        self._lock = threading.Lock()
        self.log = []

    def nameservers(self):
        r = self.resolvers[False]
        if r.port == 53:
            return [str(ns) for ns in r.nameservers]
        return [f"[{ns}]:{r.port}" if ":" in str(ns) else f"{ns}:{r.port}" for ns in r.nameservers]

    def query(self, name, rtype, cd=False):
        name = name.rstrip(".") or "."
        key = (name.lower(), rtype, cd)
        with self._lock:
            cached = self._cache.get(key)
        if cached is None:
            cached = self._do(name, rtype, cd)
            if cached.status == "error" and cached.error == "time-out":
                cached = self._do(name, rtype, cd)
            with self._lock:
                self._cache[key] = cached
        with self._lock:
            self.log.append({"naam": name, "type": rtype, "status": cached.status,
                             "antwoord": [_fmt_rr(rtype, x) for x in cached.rrs], "fout": cached.error,
                             "dnssec": cached.ad})
        return cached

    def _do(self, name, rtype, cd):
        dns = self.dns
        try:
            ans = self.resolvers[cd].resolve(name, rtype, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN:
            return DNSResult("nxdomain")
        except dns.resolver.NoNameservers:
            return DNSResult("error", error="SERVFAIL")
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return DNSResult("error", error="time-out")
        except (dns.name.LabelTooLong, dns.name.NameTooLong, dns.name.EmptyLabel):
            return DNSResult("error", error="ongeldige DNS-naam")
        except dns.exception.DNSException as e:
            return DNSResult("error", error=e.__class__.__name__)
        ad = bool(ans.response.flags & dns.flags.AD)
        if ans.rrset is None:
            return DNSResult("nodata", ad=ad)
        return DNSResult("ok", [_rr_value(rtype, rd) for rd in ans.rrset], ad=ad)


class CDResolver:
    """Wrapper die alle queries met 'checking disabled' uitvoert (voor domeinen met een kapotte DNSSEC-keten)."""

    def __init__(self, inner):
        self.inner = inner
        self.log = inner.log

    def query(self, name, rtype, cd=True):
        return self.inner.query(name, rtype, cd=True)

    def nameservers(self):
        return self.inner.nameservers()


def _fmt_rr(rtype, v):
    if rtype == "MX":
        return f"{v[0]} {v[1] or '.'}"
    if rtype in ("TLSA", "DS", "DNSKEY"):
        return " ".join(str(x) for x in v)
    return str(v)


# =====================================================================================
# HTTPS (voor het MTA-STS-beleid)
# =====================================================================================

class FetchError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError(f"doorverwijzing (HTTP {code}) naar {newurl}; doorverwijzingen zijn niet toegestaan")


def http_fetch(url, timeout=10.0, limit=65536):
    """Haalt een URL op zonder redirects te volgen. Geeft (status, content_type, body) of FetchError."""
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": f"mailcheck/{__version__}"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(limit + 1)
            return resp.status, resp.headers.get("Content-Type", ""), body
    except FetchError:
        raise
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP-status {e.code}")
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise FetchError(f"ongeldig certificaat ({reason.verify_message})")
        raise FetchError(f"niet bereikbaar ({reason})")
    except (OSError, ValueError) as e:
        raise FetchError(f"niet bereikbaar ({e.__class__.__name__})")


# =====================================================================================
# SPF-evaluator (RFC 7208 check_host); slaagt voor de volledige RFC 7208-testsuite
# =====================================================================================

class SPFPermError(Exception):
    def __init__(self, msg, code="syntax", domain=None):
        super().__init__(msg)
        self.code = code
        self.domain = domain


class SPFTempError(Exception):
    def __init__(self, msg, domain=None):
        super().__init__(msg)
        self.domain = domain


SPF_MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
_MACRO_RE = re.compile(r"%(?:\{([a-zA-Z])(\d*)(r?)([.\-+,/_=]*)\}|%|_|-)")
_MACRO_END_RE = re.compile(r"(%\{[a-zA-Z]\d*r?[.\-+,/_=]*\}|%%|%_|%-)\Z")
_TOPLABEL = re.compile(r"(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])", re.I)
_MODIFIER_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9\-_.]*)=(.*)", re.S)
_CIDR4 = r"(0|[1-9]\d?)"
_CIDR6 = r"(0|[1-9]\d{0,2})"
_DUAL_CIDR = re.compile(r"(?:/" + _CIDR4 + r")?(?://" + _CIDR6 + r")?")
QUALIFIER_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def is_spf_record(txt):
    t = txt.lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def valid_macro_string(s, exp=False):
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "%":
            m = _MACRO_RE.match(s, i)
            if not m:
                return False
            if m.group(1):
                if m.group(1).lower() not in "slodiphv" + ("crt" if exp else ""):
                    return False
                if m.group(2) and int(m.group(2)) == 0:
                    return False
            i = m.end()
            continue
        if not (0x21 <= ord(ch) <= 0x7E) and not (exp and ch == " "):
            return False
        i += 1
    return True


def valid_domain_spec(s):
    if not s or not valid_macro_string(s):
        return False
    if _MACRO_END_RE.search(s):
        return True
    t = s[:-1] if s.endswith(".") else s
    if "." not in t:
        return False
    top = t.rsplit(".", 1)[1]
    return bool(top) and "%" not in top and bool(_TOPLABEL.fullmatch(top))


class SPFTerm:
    __slots__ = ("kind", "qualifier", "name", "arg", "cidr4", "cidr6", "raw")

    def __init__(self, kind, name, raw, qualifier="+", arg=None, cidr4=None, cidr6=None):
        self.kind, self.name, self.raw = kind, name, raw
        self.qualifier, self.arg, self.cidr4, self.cidr6 = qualifier, arg, cidr4, cidr6


def parse_spf(record):
    """Ontleedt een SPF-record. Geeft (termen, modifiers); SPFPermError bij syntaxfouten."""
    parts = [p for p in record.split(" ") if p]
    if not parts or parts[0].lower() != "v=spf1":
        raise SPFPermError("record begint niet met v=spf1")
    terms, mods = [], {}
    for raw in parts[1:]:
        q, body = "+", raw
        if body[0] in "+-~?":
            q, body = body[0], body[1:]
        m = re.match(r"[a-zA-Z][a-zA-Z0-9\-_.]*", body)
        name = m.group(0).lower() if m else ""
        rest = body[len(name):] if m else body
        if name in SPF_MECHANISMS and not rest.startswith("="):
            terms.append(_parse_mechanism(q, name, rest, raw))
            continue
        mm = _MODIFIER_RE.fullmatch(body)
        if mm and raw[0] not in "+-~?":
            mname, value = mm.group(1).lower(), mm.group(2)
            if mname in ("redirect", "exp"):
                if mname in mods:
                    raise SPFPermError(f"dubbele {mname}=-modifier")
                if not valid_domain_spec(value):
                    raise SPFPermError(f"ongeldige domeinnaam in '{raw}'")
                mods[mname] = value
            elif not valid_macro_string(value):
                raise SPFPermError(f"ongeldige waarde in modifier '{raw}'")
            terms.append(SPFTerm("modifier", mname, raw, arg=value))
            continue
        raise SPFPermError(f"onbekend mechanisme of ongeldige term '{raw}'")
    return terms, mods


def _parse_mechanism(q, name, rest, raw):
    if name == "all":
        if rest:
            raise SPFPermError(f"ongeldig all-mechanisme '{raw}'")
        return SPFTerm("mech", name, raw, q)
    if name in ("include", "exists"):
        if not rest.startswith(":") or not valid_domain_spec(rest[1:]):
            raise SPFPermError(f"'{raw}' vereist een geldige domeinnaam")
        return SPFTerm("mech", name, raw, q, arg=rest[1:])
    if name == "ptr":
        if rest == "":
            return SPFTerm("mech", name, raw, q)
        if not rest.startswith(":") or not valid_domain_spec(rest[1:]):
            raise SPFPermError(f"ongeldig ptr-mechanisme '{raw}'")
        return SPFTerm("mech", name, raw, q, arg=rest[1:])
    if name in ("a", "mx"):
        dom, cidr = None, rest
        if rest.startswith(":"):
            m = re.fullmatch(r":(.*?)((?:/" + _CIDR4 + r")?(?://" + _CIDR6 + r")?)", rest, re.S)
            if not m:
                raise SPFPermError(f"ongeldig {name}-mechanisme '{raw}'")
            dom, cidr = m.group(1), m.group(2)
            if not valid_domain_spec(dom):
                raise SPFPermError(f"ongeldige domeinnaam in '{raw}'")
        m = _DUAL_CIDR.fullmatch(cidr)
        if not m:
            raise SPFPermError(f"ongeldig netmasker in '{raw}'")
        c4 = int(m.group(1)) if m.group(1) is not None else 32
        c6 = int(m.group(2)) if m.group(2) is not None else 128
        if c4 > 32 or c6 > 128:
            raise SPFPermError(f"netmasker buiten bereik in '{raw}'")
        return SPFTerm("mech", name, raw, q, arg=dom, cidr4=c4, cidr6=c6)
    if name == "ip4":
        m = re.fullmatch(r":(\d{1,3}(?:\.\d{1,3}){3})(?:/" + _CIDR4 + r")?", rest)
        if not m or any(int(o) > 255 for o in m.group(1).split(".")):
            raise SPFPermError(f"ongeldig ip4-mechanisme '{raw}'")
        c = int(m.group(2)) if m.group(2) is not None else 32
        if c > 32:
            raise SPFPermError(f"netmasker buiten bereik in '{raw}'")
        return SPFTerm("mech", name, raw, q, arg=ipaddress.IPv4Network(f"{m.group(1)}/{c}", strict=False), cidr4=c)
    if name == "ip6":
        m = re.fullmatch(r":([0-9a-fA-F:.]+?)(?:/" + _CIDR6 + r")?", rest)
        if not m:
            raise SPFPermError(f"ongeldig ip6-mechanisme '{raw}'")
        try:
            addr = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            raise SPFPermError(f"ongeldig IPv6-adres in '{raw}'")
        c = int(m.group(2)) if m.group(2) is not None else 128
        if c > 128:
            raise SPFPermError(f"netmasker buiten bereik in '{raw}'")
        return SPFTerm("mech", name, raw, q, arg=ipaddress.IPv6Network(f"{addr}/{c}", strict=False), cidr6=c)
    raise SPFPermError(f"onbekend mechanisme '{raw}'")


def valid_check_domain(domain):
    if not domain or domain.startswith("["):
        return False
    d = domain[:-1] if domain.endswith(".") else domain
    labels = d.split(".")
    return len(labels) >= 2 and all(0 < len(lbl) <= 63 for lbl in labels)


class SPFEvaluator:
    """check_host() volgens RFC 7208. resolver.query(name, rtype) -> DNSResult."""

    def __init__(self, resolver, ip, sender="", helo="", receiver="unknown",
                 lookup_limit=10, void_limit=2, default_exp=None):
        ip = ipaddress.ip_address(ip)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        self.ip = ip
        self.helo = helo or ""
        sender = sender or ("postmaster@" + self.helo)
        local, dom = sender.rsplit("@", 1) if "@" in sender else ("postmaster", sender)
        self.local, self.sender_domain = (local or "postmaster"), dom
        self.sender = f"{self.local}@{dom}"
        self.receiver = receiver
        self.resolver = resolver
        self.lookup_limit, self.void_limit = lookup_limit, void_limit
        self.default_exp = default_exp
        self.lookups = 0
        self.voids = 0
        self.void_names = []
        self.records = []
        self.mechanism = None
        self.mechanism_domain = None
        self.error = None
        self.error_code = None
        self.error_domain = None
        self._ptr_cache = None
        self._current = None

    def check(self, domain=None):
        domain = domain if domain is not None else self.sender_domain
        if not valid_check_domain(domain):
            return "none", None
        try:
            return self._check_host(domain.rstrip("."), in_include=False)
        except SPFTempError as e:
            self.error, self.error_domain = str(e), e.domain
            return "temperror", None
        except SPFPermError as e:
            self.error, self.error_code = str(e), e.code
            self.error_domain = e.domain or self._current
            return "permerror", None

    def _q(self, name, rtype):
        r = self.resolver.query(name, rtype)
        if r.status == "error":
            raise SPFTempError(f"DNS-fout voor {name} ({rtype}): {r.error}", domain=name.lower().rstrip("."))
        return r

    def _count(self):
        self.lookups += 1
        if self.lookups > self.lookup_limit:
            raise SPFPermError(f"meer dan {self.lookup_limit} DNS-lookups", code="lookups")

    def _void(self, r, name):
        if not r.rrs:
            self.voids += 1
            self.void_names.append(name)
            if self.voids > self.void_limit:
                raise SPFPermError(f"meer dan {self.void_limit} lege DNS-lookups", code="voids")

    def _addresses(self, name):
        return self._q(name, "A" if self.ip.version == 4 else "AAAA")

    def _get_record(self, domain):
        r = self._q(domain, "TXT")
        recs = [t for t in r.rrs if is_spf_record(t)]
        if len(recs) > 1:
            raise SPFPermError(f"meerdere SPF-records op {domain}", code="multiple", domain=domain)
        return recs[0] if recs else None

    def _check_host(self, domain, in_include):
        record = self._get_record(domain)
        if record is None:
            return "none", None
        self.records.append((domain, record))
        prev, self._current = self._current, domain
        try:
            terms, mods = parse_spf(record)
        except SPFPermError as e:
            e.domain = domain
            raise
        for t in terms:
            if t.kind == "mech" and self._match(t, domain):
                res = QUALIFIER_RESULT[t.qualifier]
                self.mechanism, self.mechanism_domain = t.raw, domain
                exp = self._explanation(mods.get("exp"), domain) if res == "fail" and not in_include else None
                self._current = prev
                return res, exp
        if "redirect" in mods:
            self._count()
            target = self._expand_domain(mods["redirect"], domain)
            if target is None:
                raise SPFPermError(f"redirect naar ongeldige naam '{mods['redirect']}'", code="redirect_none",
                                   domain=mods["redirect"])
            res, exp = self._check_host(target, in_include)
            if res == "none":
                raise SPFPermError(f"redirect-doel {target} heeft geen SPF-record", code="redirect_none",
                                   domain=target)
            self._current = prev
            return res, exp
        self.mechanism, self.mechanism_domain = "(geen match)", domain
        self._current = prev
        return "neutral", None

    def _match(self, t, domain):
        n = t.name
        if n == "all":
            return True
        if n == "ip4":
            return self.ip.version == 4 and self.ip in t.arg
        if n == "ip6":
            return self.ip.version == 6 and self.ip in t.arg
        if n == "include":
            self._count()
            target = self._expand_domain(t.arg, domain)
            if target is None:
                return False
            res, _ = self._check_host(target, in_include=True)
            if res == "none":
                raise SPFPermError(f"include-doel {target} heeft geen SPF-record", code="include_none", domain=target)
            return res == "pass"
        if n in ("a", "mx", "ptr", "exists"):
            self._count()
            target = self._expand_domain(t.arg, domain) if t.arg else domain
            if target is None:
                return False
            if n == "a":
                r = self._addresses(target)
                self._void(r, target)
                return self._in_cidr(r.rrs, t)
            if n == "mx":
                r = self._q(target, "MX")
                self._void(r, target)
                hosts = [h for _, h in r.rrs]
                if len(hosts) > 10:
                    raise SPFPermError(f"meer dan 10 MX-records voor {target}", code="mx_limit")
                for h in hosts:
                    if h and h != "." and self._in_cidr(self._addresses(h).rrs, t):
                        return True
                return False
            if n == "ptr":
                target = target.lower().rstrip(".")
                return any(nm.lower().rstrip(".") == target or nm.lower().rstrip(".").endswith("." + target)
                           for nm in self._validated_names())
            r = self._q(target, "A")
            self._void(r, target)
            return bool(r.rrs)
        raise SPFPermError(f"onbekend mechanisme {n}")

    def _in_cidr(self, addrs, t):
        bits = t.cidr4 if self.ip.version == 4 else t.cidr6
        for a in addrs:
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                continue
            if ip.version == self.ip.version and self.ip in ipaddress.ip_network(f"{ip}/{bits}", strict=False):
                return True
        return False

    def _validated_names(self):
        if self._ptr_cache is not None:
            return self._ptr_cache
        out = []
        r = self.resolver.query(self.ip.reverse_pointer, "PTR")
        if r.status == "ok":
            for name in r.rrs[:10]:
                try:
                    ar = self._addresses(name)
                except SPFTempError:
                    continue
                for a in ar.rrs:
                    try:
                        if ipaddress.ip_address(a) == self.ip:
                            out.append(name)
                            break
                    except ValueError:
                        pass
        self._ptr_cache = out
        return out

    def _macro_value(self, letter, domain):
        lt = letter.lower()
        if lt == "s":
            return self.sender
        if lt == "l":
            return self.local
        if lt == "o":
            return self.sender_domain
        if lt == "d":
            return domain
        if lt == "i":
            if self.ip.version == 4:
                return str(self.ip)
            return ".".join(self.ip.exploded.replace(":", "").upper())
        if lt == "p":
            names = self._validated_names()
            if not names:
                return "unknown"
            for cand in names:
                if cand.lower().rstrip(".") == domain.lower():
                    return cand
            for cand in names:
                if cand.lower().rstrip(".").endswith("." + domain.lower()):
                    return cand
            return names[0]
        if lt == "v":
            return "in-addr" if self.ip.version == 4 else "ip6"
        if lt == "h":
            return self.helo
        if lt == "c":
            return str(self.ip)
        if lt == "r":
            return self.receiver or "unknown"
        if lt == "t":
            return str(int(time.time()))
        raise SPFPermError(f"onbekende macro {letter}")

    def expand(self, s, domain, exp=False):
        if not valid_macro_string(s, exp=exp):
            raise SPFPermError(f"ongeldige macro in '{s}'")
        out, i = [], 0
        while i < len(s):
            if s[i] != "%":
                out.append(s[i])
                i += 1
                continue
            m = _MACRO_RE.match(s, i)
            tok = m.group(0)
            if tok == "%%":
                out.append("%")
            elif tok == "%_":
                out.append(" ")
            elif tok == "%-":
                out.append("%20")
            else:
                letter, digits, rev, delims = m.groups()
                parts = re.split("[" + re.escape(delims or ".") + "]", self._macro_value(letter, domain))
                if rev:
                    parts.reverse()
                if digits:
                    parts = parts[-int(digits):]
                val = ".".join(parts)
                if letter.isupper():
                    val = urllib.parse.quote(val, safe="-._~")
                out.append(val)
            i = m.end()
        return "".join(out)

    def _expand_domain(self, spec, domain):
        """Lege of te lange labels gelden als niet-bestaande naam (RFC 7208 laat dit open; zoals de
        voorkeursuitkomst van de officiële testsuite)."""
        d = self.expand(spec, domain).rstrip(".")
        while len(d) > 253 and "." in d:
            d = d.split(".", 1)[1]
        if not d or any(not 0 < len(lbl) <= 63 for lbl in d.split(".")):
            return None
        return d

    def _explanation(self, spec, domain):
        if not spec:
            return self.default_exp
        try:
            target = self._expand_domain(spec, domain)
            if target is None:
                return self.default_exp
            r = self.resolver.query(target, "TXT")
            if r.status != "ok" or len(r.rrs) != 1:
                return self.default_exp
            return self.expand(r.rrs[0], domain, exp=True)
        except (SPFPermError, SPFTempError):
            return self.default_exp


# =====================================================================================
# Resultaat per onderdeel
# =====================================================================================

class Result:
    def __init__(self, check, domain):
        self.check = check
        self.domain = domain
        self.records = []
        self.obs = {}
        self.findings = []
        self.details = {}
        self.fout = None
        self.na = {}       # test-id -> reden niet van toepassing
        self.info = set()  # tests met alleen informatieve uitkomst
        self.unknown = {}  # test-id -> reden niet vast te stellen
        self.dns_unknown = False  # True als iets niet vast te stellen was door een DNS-fout

    def observe(self, test, text):
        self.obs.setdefault(test, []).append(text)

    def not_applicable(self, test, reason):
        self.na[test] = reason

    def set_unknown(self, test, reason, dns_error=True):
        self.unknown[test] = reason
        if dns_error:
            self.dns_unknown = True

    def find(self, code, detail="", voorbeeld=None, also=(), **kw):
        """Registreert een bevinding; 'also' = andere tests die door deze bevinding ook niet slagen."""
        cat = FINDINGS[code]
        self.obs.setdefault(cat["test"], [])
        f = {"code": code, "test": cat["test"], "ernst": cat["ernst"], "detail": detail, "voorbeeld": voorbeeld,
             "kw": kw, "also": tuple(also)}
        self.findings.append(f)
        return f


def parse_tags(record):
    """Tag-lijst (DKIM/DMARC/MTA-STS/TLS-RPT/BIMI). Geeft (tags, volgorde, fouten, dubbel)."""
    tags, order, errors, dups = {}, [], [], []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"'{part}' is geen tag=waarde")
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", k):
            errors.append(f"ongeldige tagnaam '{k}'")
            continue
        if k in tags:
            dups.append(k)
        tags[k] = v.strip()
        order.append(k)
    return tags, order, errors, dups


def _is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


# =====================================================================================
# Audit
# =====================================================================================

# Twee ver uiteenliggende, nooit gebruikte adressen per IP-versie (documentatie- en gereserveerde reeksen).
# 'Keurt alles goed' wordt pas gemeld als beide adressen van één versie 'pass' krijgen.
SPF_TEST_IPS = ("192.0.2.1", "240.0.0.1", "2001:db8::1", "100::1")


class Auditor:
    def __init__(self, resolver, selectors, user_selectors=False, fetch=http_fetch, http=True):
        self.q = resolver
        self.selectors = selectors
        self.user_selectors = user_selectors
        self.fetch = fetch
        self.http = http
        self._org_cache = {}
        self._org_errors = set()

    # ---------------------------------------------------------------- hulpfuncties
    def txt(self, name):
        r = self.q.query(name, "TXT")
        if r.status == "error":
            raise AuditDNSError(f"{name} (TXT): {r.error}")
        return r

    def _receives_mail(self, domain):
        """Kan dit domein mail ontvangen (MX niet-null, of impliciet via A/AAAA)?"""
        r = self.q.query(domain, "MX")
        if r.status == "error":
            return None
        if r.rrs:
            return not (len(r.rrs) == 1 and r.rrs[0][1] in ("", "."))
        if r.status == "nxdomain":
            return False
        answers = [self.q.query(domain, t) for t in ("A", "AAAA")]
        if any(a.rrs for a in answers):
            return True
        return None if any(a.status == "error" for a in answers) else False

    # ---------------------------------------------------------------- MX
    def check_mx(self, domain, ctx):
        res = Result("MX", domain)
        r = self.q.query(domain, "MX")
        if r.status == "error":
            raise AuditDNSError(f"{domain} (MX): {r.error}")
        mx = sorted(r.rrs)
        res.records = [f"{p} {h or '.'}" for p, h in mx]
        nulls = [h for _, h in mx if h in ("", ".")]
        hosts = [h for _, h in mx if h not in ("", ".")]
        ctx["mx_hosts"] = hosts
        ctx["null_mx"] = bool(nulls) and not hosts
        if not mx:
            answers = [self.q.query(domain, t) for t in ("A", "AAAA")]
            if any(a.status == "error" for a in answers) and not any(a.rrs for a in answers):
                raise AuditDNSError(f"{domain} (A/AAAA): {next(a.error for a in answers if a.error)}")
            addr = [a for ans in answers for a in ans.rrs]
            ctx["receives"] = bool(addr)
            if addr:
                res.observe("MX-01", "Geen MX-records; het domein heeft wel een IP-adres (impliciete MX)")
                res.find("MX_IMPLICIT", f"Geen MX-records; IP-adres(sen): {', '.join(addr[:4])}")
            else:
                res.observe("MX-01", "Geen MX-records en geen IP-adres")
                res.find("MX_NONE", "Geen MX-records gevonden")
            res.not_applicable("MX-02", "Geen mailservers")
            return res
        if nulls and hosts:
            ctx["receives"] = True
            res.find("MX_NULL_MIXED", "Null-MX naast: " + ", ".join(hosts))
        elif nulls:
            ctx["receives"] = False
            res.observe("MX-01", "Null-MX: het domein ontvangt bewust geen e-mail")
            if nulls and mx[0][0] != 0:
                res.observe("MX-01", "Let op: null-MX hoort voorkeur 0 te hebben")
            res.not_applicable("MX-02", "Null-MX")
            return res
        else:
            ctx["receives"] = True
            res.observe("MX-01", f"{len(hosts)} mailserver(s): " + ", ".join(hosts))

        def inspect(h):
            if _is_ip(h):
                return h, "ip", []
            cn = self.q.query(h, "CNAME")
            answers = [self.q.query(h, t) for t in ("A", "AAAA")]
            addrs = [a for ans in answers for a in ans.rrs]
            if not addrs and any(ans.status == "error" for ans in answers):
                return h, "error", []
            return h, ("cname" if cn.rrs else "ok"), addrs

        with ThreadPoolExecutor(max_workers=8) as pool:
            infos = list(pool.map(inspect, hosts[:20]))
        dead, unknown = [], []
        for h, kind, addrs in infos:
            if kind == "error":
                unknown.append(h)
                continue
            if kind == "ip":
                res.find("MX_IP_LITERAL", f"MX-record bevat {h}", host=h)
                continue
            if kind == "cname":
                res.find("MX_CNAME", f"{h} is een CNAME", host=h)
            if not addrs:
                dead.append(h)
        for h in dead:
            f = res.find("MX_NO_ADDRESS", f"{h} heeft geen A- of AAAA-record", host=h)
            if len(dead) < len(hosts):
                f["ernst"] = MIDDEN
        if unknown:
            res.set_unknown("MX-02", "DNS-fout bij het opvragen van het IP-adres van " + ", ".join(unknown))
        elif all(f["test"] != "MX-02" for f in res.findings):
            res.observe("MX-02", "Alle mailservers hebben een IP-adres en zijn geldige hostnamen")
        ctx["mx_details"] = [{"host": h, "adressen": a} for h, _, a in infos]
        return res

    # ---------------------------------------------------------------- SPF
    def check_spf(self, domain, ctx):
        res = Result("SPF", domain)
        r = self.txt(domain)
        recs = [t for t in r.rrs if is_spf_record(t)]
        near = [t for t in r.rrs if not is_spf_record(t) and re.match(r"\s*v\s*=\s*spf1", t, re.I)]
        res.records = recs + near
        ctx["spf_parked"] = False
        if not recs:
            ctx["spf_state"] = "missing"
            res.observe("SPF-01", "Geen SPF-record gevonden" + (" (wel een misvormd record)" if near else ""))
            res.find("SPF_MISSING", "Geen geldig TXT-record met v=spf1" +
                     (f"; misvormd record: {near[0]}" if near else ""))
            for t in ("SPF-02", "SPF-03", "SPF-04", "SPF-05", "SPF-06", "SPF-07"):
                res.not_applicable(t, "Geen SPF-record")
            return res
        res.observe("SPF-01", "SPF-record gevonden")
        if len(recs) > 1:
            ctx["spf_state"] = "invalid"
            res.observe("SPF-02", f"{len(recs)} SPF-records gevonden")
            res.find("SPF_MULTIPLE", f"{len(recs)} SPF-records gepubliceerd",
                     voorbeeld=f'{domain}. TXT "{merge_spf(recs)}"')
            for t in ("SPF-03", "SPF-04", "SPF-05", "SPF-06", "SPF-07"):
                res.not_applicable(t, "SPF is ongeldig door meerdere records")
            return res
        res.observe("SPF-02", "Precies één SPF-record")
        try:
            terms, _ = parse_spf(recs[0])
        except SPFPermError as e:
            ctx["spf_state"] = "invalid"
            res.find("SPF_SYNTAX", f"{domain}: {e}", target=domain, reason=str(e))
            for t in ("SPF-04", "SPF-05", "SPF-06", "SPF-07"):
                res.not_applicable(t, "SPF-record is syntactisch ongeldig")
            return res
        mech = [t for t in terms if t.kind == "mech"]
        ctx["spf_parked"] = len(mech) == 1 and mech[0].name == "all" and mech[0].qualifier == "-"

        # 1. Evaluatie zoals een ontvangende mailserver, voor niet-geautoriseerde IPv4- en IPv6-adressen
        evals = []
        for ip in SPF_TEST_IPS:
            ev = SPFEvaluator(self.q, ip, sender=f"postmaster@{domain}", helo=domain)
            result, _ = ev.check(domain)
            evals.append((ip, result, ev))
        res.details["evaluatie"] = [{"ip": ip, "uitkomst": rr, "lookups": ev.lookups, "lege_lookups": ev.voids,
                                     "beslissende_term": ev.mechanism, "fout": ev.error} for ip, rr, ev in evals]
        ip0, result0, ev0 = max(evals, key=lambda x: (x[1] == "permerror", x[1] == "temperror", x[2].lookups))
        # 2. Volledige analyse van de hele SPF-boom (gaat, anders dan een ontvanger, door na een fout)
        walk = spf_walk(self.q, domain)
        res.details["volledige_analyse"] = {"lookups": walk["lookups"], "problemen": [p[2] for p in walk["problems"]]}

        lookups = max([ev.lookups for _, _, ev in evals] + [walk["lookups"]])
        voids = max(ev.voids for _, _, ev in evals)
        res.details.update(dns_lookups=lookups, lege_lookups=voids)
        reported = set()

        def report_problem(kind, target, text, note=""):
            key = (kind, target.lower() if target else "")
            if key in reported:
                return
            reported.add(key)
            if kind in ("none", "include_none", "redirect_none"):
                res.find("SPF_INCLUDE_NONE", text + note, target=target)
            elif kind == "multiple":
                res.find("SPF_INCLUDE_MULTIPLE", text + note, target=target)
            elif kind == "loop":
                res.find("SPF_LOOP", text + note, info=text)
            elif kind == "dns":
                res.find("SPF_TEMPERROR", text + note, info=text)
            else:
                res.find("SPF_SYNTAX", f"{target}: {text}{note}", target=target, reason=text)

        if result0 == "permerror":
            ctx["spf_state"] = "invalid"
            code, edomain = ev0.error_code, ev0.error_domain or domain
            v6 = " (bij evaluatie voor IPv6-afzenders)" if ":" in ip0 else ""
            loops = [p for p in walk["problems"] if p[0] == "loop"]
            if code == "lookups" and loops:
                reported.add(("lookups", ""))
                report_problem("loop", loops[0][1], loops[0][2])
            elif code == "lookups":
                reported.add(("lookups", ""))
                res.find("SPF_LOOKUPS_EXCEEDED", f"Evaluatie afgebroken: {ev0.error}{v6}", info=ev0.error + v6)
            elif code == "voids":
                names = ", ".join(dict.fromkeys(ev0.void_names))
                res.find("SPF_VOID_LIMIT", f"Lege lookups{v6}: {names}", info=names + v6)
            elif code == "mx_limit":
                res.find("SPF_MX_LIMIT", ev0.error, info=ev0.error)
            else:
                report_problem({"include_none": "none", "redirect_none": "none"}.get(code, code), edomain, ev0.error)
            res.not_applicable("SPF-04", "De uitkomst is permerror: SPF wordt door ontvangers als ongeldig behandeld")
        elif result0 == "temperror":
            ctx["spf_state"] = "temp"
            report_problem("dns", ev0.error_domain or "", ev0.error)
            res.set_unknown("SPF-04", "Evaluatie onderbroken door een DNS-fout")
        else:
            ctx["spf_state"] = "ok"
            for ip, rr, ev in evals:
                res.observe("SPF-04", f"{ip}: {rr} (via {ev.mechanism})")
            v4p = [(ip, ev) for ip, rr, ev in evals[:2] if rr == "pass"]
            v6p = [(ip, ev) for ip, rr, ev in evals[2:] if rr == "pass"]
            passing = v4p if len(v4p) == 2 else v6p if len(v6p) == 2 else []
            neutral = [(ip, ev, rr) for ip, rr, ev in evals if rr in ("neutral", "none")]
            if passing:
                ip, ev = passing[0]
                res.find("SPF_PASS_ALL", f"{ip} krijgt 'pass' via '{ev.mechanism}' in {ev.mechanism_domain}",
                         info=f"via '{ev.mechanism}'")
            elif neutral:
                ip, ev, rr = neutral[0]
                res.find("SPF_NEUTRAL", f"{ip} krijgt '{rr}' via '{ev.mechanism}'", info=f"via '{ev.mechanism}'")

        # Aanvullende problemen uit de volledige analyse (pas zichtbaar na herstel van de eerste fout)
        note = " (gevonden in de volledige analyse; wordt zichtbaar zodra eerdere fouten zijn hersteld)" \
            if result0 in ("permerror", "temperror") else ""
        for kind, target, text in walk["problems"]:
            report_problem(kind, target, text, note)
        if walk["lookups"] > 10 and ("lookups", "") not in reported:
            res.find("SPF_LOOKUPS_EXCEEDED", f"Volledige analyse: {walk['lookups']} DNS-lookups{note}",
                     info=f"{walk['lookups']} lookups")
        elif 8 <= lookups <= 10:
            res.find("SPF_LOOKUPS_HIGH", f"{lookups} DNS-lookups nodig{note}", count=lookups)

        if not any(f["test"] == "SPF-03" for f in res.findings):
            res.observe("SPF-03", "Alle records in de SPF-boom zijn syntactisch geldig")
        if any(p[0] == "dns" for p in walk["problems"]) or result0 == "temperror":
            res.set_unknown("SPF-05", f"Ten minste {lookups} DNS-lookups; de volledige telling is door een DNS-fout "
                                      f"niet vast te stellen")
        elif not any(f["test"] == "SPF-05" and f["ernst"] != LAAG for f in res.findings):
            res.observe("SPF-05", f"{lookups} van max. 10 DNS-lookups, {voids} van max. 2 lege lookups")
        if not any(f["test"] == "SPF-06" for f in res.findings):
            res.observe("SPF-06", "Alle verwijzingen zijn geldig en bereikbaar")

        all_idx = next((i for i, t in enumerate(terms) if t.kind == "mech" and t.name == "all"), None)
        if all_idx is not None:
            after = [t.raw for t in terms[all_idx + 1:] if t.kind == "mech" or t.name == "redirect"]
            if after:
                res.find("SPF_AFTER_ALL", " ".join(after), info=" ".join(after))

        visited = list(dict.fromkeys([rd for _, _, ev in evals for rd in ev.records] + walk["records"]))
        res.details["geëvalueerde_records"] = [{"domein": d, "record": rr} for d, rr in visited]
        org = self.org_domain(domain)
        issue7 = False
        for d, rr in visited:
            dl = d.lower()
            own = dl in (domain.lower(), org) or dl.endswith("." + org)
            try:
                tms, _ = parse_spf(rr)
            except SPFPermError:
                continue
            for t in tms:
                if t.kind != "mech" or t.qualifier != "+":
                    continue
                if t.name == "ptr" and own:
                    res.find("SPF_PTR", f"'{t.raw}' in record van {d}")
                    issue7 = True
                if t.name in ("ip4", "ip6", "a", "mx"):
                    c4 = t.cidr4 if t.name != "ip6" else None
                    c6 = t.cidr6 if t.name != "ip4" else None
                    limit4, limit6 = (16, 32) if own else (9, 17)
                    if (c4 is not None and c4 < limit4) or (c6 is not None and c6 < limit6):
                        rng = t.raw.lstrip("+")
                        where = f"in record van {d}" + ("" if own else " (externe dienst)")
                        res.find("SPF_WIDE_RANGE", f"{rng} {where}", range=rng)
                        issue7 = True
        if not issue7:
            res.observe("SPF-07", "Geen ptr-mechanisme en geen zeer brede IP-bereiken")
        res.details["geautoriseerd"] = [t.raw for t in terms if t.kind == "mech" and t.name != "all"]
        return res

    # ---------------------------------------------------------------- DKIM
    def check_dkim(self, domain, ctx):
        res = Result("DKIM", domain)
        sels = self.selectors

        def lookup(sel):
            name = f"{sel}._domainkey.{domain}"
            r = self.q.query(name, "TXT")
            if r.status == "error":
                return sel, None, r.error
            recs = [t for t in r.rrs if re.search(r"(^|;)\s*p\s*=", t) or re.match(r"\s*v\s*=\s*DKIM1", t, re.I)]
            return sel, recs, None

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lookup, sels))
        errors = [(s, e) for s, recs, e in results if e]
        found = [(s, recs) for s, recs, e in results if recs]
        res.details["selectors_gecontroleerd"] = list(sels)
        dk = self.q.query(f"_domainkey.{domain}", "TXT")
        res.details["_domainkey"] = dk.status
        keys = []
        for sel, recs in found:
            for rec in recs:
                res.records.append(f"{sel}._domainkey.{domain}: {rec}")
                keys.append(self._analyze_dkim(sel, rec, res))
        res.details["sleutels"] = keys
        usable = [k for k in keys if k.get("bruikbaar")]
        ctx["dkim_found"] = bool(usable)
        ctx["dkim_absent_zeker"] = dk.status == "nxdomain" and not found

        if not found:
            for t in ("DKIM-02", "DKIM-03", "DKIM-04"):
                res.not_applicable(t, "Geen DKIM-sleutel gevonden")
            if errors and len(errors) == len(sels):
                raise AuditDNSError(f"DKIM-selectors: {errors[0][1]}")
            if errors:
                res.set_unknown("DKIM-01", f"DNS-fout bij {len(errors)} selector(s): "
                                           + ", ".join(s for s, _ in errors[:5]))
            if ctx.get("spf_parked"):
                res.observe("DKIM-01", "Geen sleutels; het domein verstuurt volgens SPF geen e-mail, DKIM is dan niet "
                                       "nodig")
                return res
            if self.user_selectors:
                res.observe("DKIM-01", f"Geen sleutel op de opgegeven selector(s): {', '.join(sels)}")
                res.find("DKIM_NOT_FOUND_GIVEN", "Gecontroleerde selector(s): " + ", ".join(sels),
                         selectors=", ".join(sels))
            elif dk.status == "nxdomain":
                res.observe("DKIM-01", f"_domainkey.{domain} bestaat niet (NXDOMAIN); {len(sels)} selectors "
                                       f"gecontroleerd")
                res.find("DKIM_NONE_PUBLISHED", f"NXDOMAIN op _domainkey.{domain}")
            else:
                dk_text = {"nodata": "zonder eigen records", "ok": "met eigen records"}.get(
                    dk.status, "status onbekend door een DNS-fout")
                res.observe("DKIM-01", f"Geen sleutel op {len(sels)} gangbare selectors; _domainkey.{domain} bestaat "
                                       f"wel ({dk_text})")
                res.find("DKIM_NOT_FOUND", f"{len(sels)} gangbare selectors gecontroleerd", count=len(sels))
            return res
        res.observe("DKIM-01", f"Sleutel(s) gevonden op selector(s): {', '.join(s for s, _ in found)} "
                               f"({len(sels)} gecontroleerd)")
        if not usable and not ctx.get("spf_parked") and \
                not any(ERNST_ORDE[f["ernst"]] >= ERNST_ORDE[HOOG] for f in res.findings):
            res.find("DKIM_NO_USABLE", "Alleen ingetrokken of onbruikbare sleutels op: "
                     + ", ".join(s for s, _ in found))
        for test in ("DKIM-02", "DKIM-03"):
            if test not in res.obs:
                res.not_applicable(test, "Geen leesbare sleutel")
        if "DKIM-04" not in res.obs:
            res.observe("DKIM-04", "Geen sleutels in testmodus")
        return res

    def _analyze_dkim(self, sel, rec, res):
        tags, order, errs, dups = parse_tags(rec)
        k = tags.get("k", "rsa").lower()
        info = {"selector": sel, "type": k, "bruikbaar": False}
        reasons = list(errs) + [f"dubbele tag '{d}'" for d in dups]
        if "v" in tags and (order[0] != "v" or tags["v"] != "DKIM1"):
            reasons.append("v=DKIM1 moet de eerste tag zijn")
        if "p" not in tags:
            reasons.append("p= ontbreekt")
        if reasons:
            res.find("DKIM_RECORD_INVALID", f"Selector '{sel}': {'; '.join(reasons)}", selector=sel,
                     reason="; ".join(reasons))
            return info
        p = re.sub(r"\s+", "", tags["p"])
        if not p:
            res.find("DKIM_REVOKED", f"Selector '{sel}': lege p=", selector=sel)
            res.observe("DKIM-02", f"'{sel}': ingetrokken")
            return info
        try:
            raw = base64.b64decode(p, validate=True)
        except Exception:
            res.find("DKIM_RECORD_INVALID", f"Selector '{sel}': p= is geen geldige base64", selector=sel,
                     reason="p= is geen geldige base64")
            return info
        if k == "ed25519":
            if len(raw) != 32:
                res.find("DKIM_RECORD_INVALID", f"Selector '{sel}': Ed25519-sleutel is {len(raw)} bytes (32 vereist)",
                         selector=sel, reason=f"Ed25519-sleutel van {len(raw)} bytes")
                return info
            info.update(bits=256, bruikbaar=True)
            res.observe("DKIM-02", f"'{sel}': Ed25519")
        elif k == "rsa":
            try:
                bits = rsa_key_bits(raw)
            except ValueError as e:
                res.find("DKIM_RECORD_INVALID", f"Selector '{sel}': {e}", selector=sel, reason=str(e))
                return info
            info.update(bits=bits, bruikbaar=bits >= 1024)
            res.observe("DKIM-02", f"'{sel}': RSA {bits} bit")
            if bits < 1024:
                res.find("DKIM_KEY_WEAK", f"Selector '{sel}': RSA {bits} bit", selector=sel, bits=bits)
            elif bits < 2048:
                res.find("DKIM_KEY_1024", f"Selector '{sel}': RSA {bits} bit", selector=sel, bits=bits)
        else:
            res.find("DKIM_UNKNOWN_KEYTYPE", f"Selector '{sel}': k={k}", selector=sel, ktype=k)
            return info
        if "h" in tags:
            algs = [a.strip().lower() for a in tags["h"].split(":") if a.strip()]
            if "sha256" not in algs:
                res.find("DKIM_SHA1", f"Selector '{sel}': h={tags['h']}", selector=sel, h=tags["h"])
        if "s" in tags:
            svc = [a.strip().lower() for a in tags["s"].split(":")]
            if "*" not in svc and "email" not in svc:
                res.find("DKIM_SERVICE", f"Selector '{sel}': s={tags['s']}", selector=sel, s=tags["s"])
                info["bruikbaar"] = False
        flags = [a.strip().lower() for a in tags.get("t", "").split(":")]
        if "y" in flags:
            res.find("DKIM_TESTMODE", f"Selector '{sel}': t={tags['t']}", selector=sel)
        res.observe("DKIM-03", f"'{sel}': geldig")
        return info

    # ---------------------------------------------------------------- DMARC
    def dmarc_records(self, domain):
        r = self.txt(f"_dmarc.{domain}")
        valid = [t for t in r.rrs if re.match(r"v\s*=\s*DMARC1\s*(;|$)", t.strip())]
        near = [t for t in r.rrs if t not in valid and re.search(r"v\s*=\s*dmarc1", t, re.I)]
        return valid, near

    def org_domain(self, domain):
        """Organisatiedomein via de DNS tree walk van RFC 9989 §4.10.2."""
        domain = domain.lower().rstrip(".")
        if domain in self._org_cache:
            return self._org_cache[domain]
        labels = domain.split(".")
        found = []   # (domain, tags) van lang naar kort
        cands = [domain]
        x = len(labels)
        cur = labels
        if x >= 8:
            cur = labels[-7:]
            cands.append(".".join(cur))
        while len(cur) > 1:
            cur = cur[1:]
            cands.append(".".join(cur))
        for d in dict.fromkeys(cands):
            try:
                recs, _ = self.dmarc_records(d)
            except AuditDNSError:
                self._org_errors.add(domain)
                continue
            if len(recs) == 1:
                tags = parse_tags(recs[0])[0]
                found.append((d, tags))
                if tags.get("psd", "").lower() in ("y", "n"):
                    break
        org = None
        for d, tags in found:
            psd = tags.get("psd", "").lower()
            if psd == "n":
                org = d
                break
            if psd == "y" and d != domain:
                org = domain.split(".")[-(len(d.split(".")) + 1):]
                org = ".".join(org)
                break
        if org is None:
            org = found[-1][0] if found else domain
        self._org_cache[domain] = org
        return org

    def check_dmarc(self, domain, ctx):
        res = Result("DMARC", domain)
        ctx["dmarc_policy"] = None
        recs, near = self.dmarc_records(domain)
        res.records = recs + near
        problem = None   # (code, beleidsdomein, detail, aantal) voor een ongeldige recordset
        if len(recs) > 1:
            problem = ("DMARC_MULTIPLE", domain, f"{len(recs)} DMARC-records op _dmarc.{domain}", len(recs))
        elif not recs and near:
            problem = ("DMARC_V_NOT_FIRST", domain, near[0], 1)
        use, policy_domain, inherited = (recs[0] if len(recs) == 1 else None), domain, False
        if use is None:
            # RFC 9989 §4.10: ongeldige of ontbrekende records worden genegeerd; de zoektocht gaat verder omhoog.
            org = self.org_domain(domain)
            if org != domain:
                r2, n2 = self.dmarc_records(org)
                if len(r2) == 1:
                    use, policy_domain, inherited = r2[0], org, True
                    res.records.append(f"_dmarc.{org}: {r2[0]}")
                elif (r2 or n2) and not problem:
                    res.records += r2 + n2
                    problem = (("DMARC_MULTIPLE", org, f"{len(r2)} DMARC-records op _dmarc.{org}", len(r2)) if r2
                               else ("DMARC_V_NOT_FIRST", org, n2[0], 1))
        if problem:
            code, pdom, detail, count = problem
            gevolg = (f"Daardoor geldt het beleid van het organisatiedomein {policy_domain}, niet het hier bedoelde "
                      f"beleid." if use else "Het domein heeft daardoor in de praktijk geen DMARC.")
            f = res.find(code, detail, policy_domain=pdom, count=count, info=detail[:80], gevolg=gevolg)
            if use:
                f["ernst"] = MIDDEN
        if use is None:
            rest = ("DMARC-03", "DMARC-04", "DMARC-05", "DMARC-06", "DMARC-07", "DMARC-08")
            if problem:
                res.observe("DMARC-01", "Record aanwezig, maar ongeldig")
                for t in rest:
                    res.not_applicable(t, "Het DMARC-record wordt door ontvangers genegeerd")
                return res
            if domain.lower() in self._org_errors:
                res.set_unknown("DMARC-01", f"Geen record op _dmarc.{domain}; de bovenliggende domeinen konden door "
                                            f"een DNS-fout niet worden gecontroleerd")
                for t in ("DMARC-02",) + rest:
                    res.set_unknown(t, "DMARC-beleid niet vast te stellen")
                return res
            res.observe("DMARC-01", f"Geen record op _dmarc.{domain}" +
                        ("" if self.org_domain(domain) == domain else " of op het organisatiedomein"))
            res.find("DMARC_MISSING", f"Geen DMARC-record op _dmarc.{domain}")
            res.not_applicable("DMARC-02", "Geen DMARC-record")
            for t in rest:
                res.not_applicable(t, "Geen DMARC-record")
            return res
        res.observe("DMARC-01", f"Overgenomen van organisatiedomein {policy_domain}" if inherited
                    else f"Record gevonden op _dmarc.{domain}")
        res.details["beleidsdomein"] = policy_domain

        tags, order, errs, dups = parse_tags(use)
        res.details["tags"] = tags
        problems = list(errs) + [f"dubbele tag '{d}'" for d in dups]
        known = {"v", "p", "sp", "np", "adkim", "aspf", "fo", "rua", "ruf", "t", "psd", "pct", "rf", "ri"}
        policies = ("none", "quarantine", "reject")
        enum = {"adkim": ("r", "s"), "aspf": ("r", "s"), "t": ("y", "n"), "psd": ("y", "n", "u")}
        for k, v in tags.items():
            if k not in known:
                res.find("DMARC_UNKNOWN_TAG", f"{k}={v}", tag=k)
            elif k in enum and v.lower() not in enum[k]:
                problems.append(f"{k}={v}")
            elif k == "fo" and not all(x.strip() in ("0", "1", "d", "s") for x in v.split(":")):
                problems.append(f"fo={v}")
            elif k == "pct" and not (v.isdigit() and 0 <= int(v) <= 100):
                problems.append(f"pct={v}")
            elif k == "ri" and not v.isdigit():
                problems.append(f"ri={v}")
        bad_policy = [f"{k}={tags[k]}" for k in ("p", "sp", "np") if k in tags and tags[k].lower() not in policies]
        if bad_policy:
            res.find("DMARC_INVALID_P", "; ".join(bad_policy), info="; ".join(bad_policy), also=("DMARC-03",))
        if problems:
            res.find("DMARC_SYNTAX", "; ".join(problems), info="; ".join(problems))
        if not bad_policy and not problems:
            res.observe("DMARC-02", "Eén geldig record" + ("; p ontbreekt en geldt als p=none" if "p" not in tags
                                                          else ""))
        p = tags.get("p", "none").lower()
        sp = tags.get("sp", "").lower()
        np_ = tags.get("np", "").lower()
        label = "sp" if inherited and sp else "p"
        if bad_policy:
            # RFC 9989 §4.10.1: ongeldige p/sp/np -> hoogstens behandelen als p=none
            effective = "none"
            res.observe("DMARC-03", "Beleid ongeldig; ontvangers passen hoogstens p=none toe")
        else:
            effective = (sp or p) if inherited else p
            res.observe("DMARC-03", f"Beleid: {label}={effective}" + (f" (van {policy_domain})" if inherited else ""))
        ctx["dmarc_policy"] = effective
        ctx["dmarc_tags"] = tags
        rua_default = tags.get("rua") or f"mailto:dmarc@{policy_domain}"
        if effective == "none" and not bad_policy:
            res.find("DMARC_P_NONE", f"{label}=none" if "p" in tags or inherited else "p ontbreekt (geldt als p=none)",
                     voorbeeld=dmarc_suggest(policy_domain, tags, p="quarantine", pct=None, t=None, rua=rua_default))
        elif ctx.get("spf_parked") and effective == "quarantine":
            res.find("DMARC_PARKED_NOT_REJECT", f"{label}=quarantine bij SPF 'v=spf1 -all'",
                     policy=f"{label}=quarantine", voorbeeld=dmarc_suggest(policy_domain, tags, p="reject"))

        if inherited:
            res.observe("DMARC-04", f"Subdomein; beleid van {policy_domain} is van toepassing")
        elif not bad_policy:
            res.observe("DMARC-04", f"sp={sp or '(niet gezet, volgt p)'}, np={np_ or '(niet gezet, volgt sp/p)'}")
            if sp == "none" and p in ("quarantine", "reject"):
                res.find("DMARC_SP_NONE", f"sp=none terwijl p={p}", voorbeeld=dmarc_suggest(domain, tags, sp=None))
            if np_ == "none" and (sp or p) in ("quarantine", "reject"):
                res.find("DMARC_NP_NONE", "np=none", voorbeeld=dmarc_suggest(domain, tags, np=None))

        t_flag = tags.get("t", "n").lower()
        pct = tags.get("pct", "")
        res.observe("DMARC-05", f"t={t_flag}" + (f", pct={pct}" if pct else ""))
        if t_flag == "y" and effective in ("quarantine", "reject"):
            res.find("DMARC_TESTMODE", "t=y", voorbeeld=dmarc_suggest(policy_domain, tags, t=None))
        if pct.isdigit() and int(pct) < 100:
            res.find("DMARC_PCT", f"pct={pct}", pct=pct, voorbeeld=dmarc_suggest(policy_domain, tags, pct=None))

        if not tags.get("rua"):
            res.find("DMARC_NO_RUA", "Geen rua-tag",
                     voorbeeld=dmarc_suggest(policy_domain, tags, rua=f"mailto:dmarc@{policy_domain}"))
        else:
            res.observe("DMARC-06", f"rua={tags['rua']}")
            self._check_report_uris(policy_domain, tags["rua"], "rua", res)
        if tags.get("ruf"):
            res.observe("DMARC-06", f"ruf={tags['ruf']}")
            self._check_report_uris(policy_domain, tags["ruf"], "ruf", res)

        am = {"s": "strict", "r": "relaxed"}
        res.observe("DMARC-07", f"SPF: {am.get(tags.get('aspf', 'r').lower(), 'ongeldig')}, "
                                f"DKIM: {am.get(tags.get('adkim', 'r').lower(), 'ongeldig')}")
        res.info.add("DMARC-07")

        if effective not in ("quarantine", "reject"):
            res.not_applicable("DMARC-08", "Het beleid handhaaft niet (none)")
        elif ctx.get("spf_parked"):
            res.not_applicable("DMARC-08", "Het domein verstuurt volgens SPF geen e-mail")
        else:
            spf_state, dkim = ctx.get("spf_state"), ctx.get("dkim_found")
            if spf_state == "ok" or dkim:
                res.observe("DMARC-08", " en ".join(x for x, ok in (("Geldig SPF-record", spf_state == "ok"),
                                                                    ("bruikbare DKIM-sleutel", dkim)) if ok))
            elif spf_state in (None, "temp") or dkim is None:
                res.set_unknown("DMARC-08", "SPF of DKIM kon door een DNS-fout niet worden vastgesteld")
            else:
                spf_txt = "ontbreekt" if spf_state == "missing" else "is ongeldig"
                f = res.find("DMARC_NO_AUTH_BASIS", f"SPF {spf_txt}; geen bruikbare DKIM-sleutel gevonden",
                             policy=f"{label}={effective}", spf=spf_txt)
                if not ctx.get("dkim_absent_zeker"):
                    f["ernst"] = MIDDEN
        return res

    def _check_report_uris(self, policy_domain, uris, tag, res):
        org = self.org_domain(policy_domain)
        for uri in [u.strip() for u in uris.split(",") if u.strip()]:
            m = re.fullmatch(r"mailto:([^@\s]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]{2,63})\.?(?:![0-9]+[kmgt]?)?",
                             uri, re.I)
            if not m or m.group(2).split(".")[-1].isdigit():
                res.find("DMARC_BAD_URI", f"{tag}={uri}", uri=uri, tag=tag)
                continue
            target = m.group(2).lower()
            rx = self._receives_mail(target)
            if rx is False:
                res.find("DMARC_RUA_NO_MX", f"{target} kan geen mail ontvangen", target=target, tag=tag)
            elif rx is None:
                res.set_unknown("DMARC-06", f"Of {target} mail kan ontvangen is door een DNS-fout niet vast te stellen")
            if target == org or target.endswith("." + org) or self.org_domain(target) == org:
                continue
            ar = self.q.query(f"{policy_domain}._report._dmarc.{target}", "TXT")
            if ar.status == "error":
                res.set_unknown("DMARC-06", f"Autorisatie van {target} is door een DNS-fout niet vast te stellen")
                continue
            if any(re.match(r"v\s*=\s*DMARC1", t.strip()) for t in ar.rrs):
                res.observe("DMARC-06", f"Extern rapportdomein {target} is geautoriseerd")
            else:
                res.find("DMARC_EXT_NOT_AUTH", f"Geen record op {policy_domain}._report._dmarc.{target}",
                         target=target, tag=tag, policy_domain=policy_domain)

    # ---------------------------------------------------------------- MTA-STS
    def check_mtasts(self, domain, ctx):
        res = Result("MTA-STS", domain)
        tests = ("MTASTS-01", "MTASTS-02", "MTASTS-03", "MTASTS-04", "MTASTS-05")
        if ctx.get("mx_hosts") is None:
            for t in tests:
                res.set_unknown(t, "De MX-records konden door een DNS-fout niet worden opgevraagd")
            return res
        if not ctx.get("mx_hosts"):
            for t in tests:
                res.not_applicable(t, "Domein ontvangt geen mail via MX")
            return res
        r = self.txt(f"_mta-sts.{domain}")
        recs = [t for t in r.rrs if re.match(r"v\s*=\s*STSv1", t.strip())]
        res.records = [f"_mta-sts.{domain}: {t}" for t in recs]
        if not recs:
            res.observe("MTASTS-01", "Geen MTA-STS-record")
            res.find("MTASTS_MISSING", f"Geen record op _mta-sts.{domain}")
            for t in tests[1:]:
                res.not_applicable(t, "MTA-STS niet ingericht")
            return res
        tags, order, errs, dups = parse_tags(recs[0])
        bad = []
        if len(recs) > 1:
            bad.append(f"{len(recs)} records")
        if order[0] != "v" or tags.get("v") != "STSv1":
            bad.append("v=STSv1 moet de eerste tag zijn")
        if not re.fullmatch(r"[A-Za-z0-9]{1,32}", tags.get("id", "")):
            bad.append(f"ongeldige id '{tags.get('id', '')}'")
        bad += errs
        if bad:
            res.find("MTASTS_RECORD_INVALID", "; ".join(bad), info="; ".join(bad))
        else:
            res.observe("MTASTS-01", f"Geldig record (id={tags['id']})")
        if not self.http:
            for t in tests[1:]:
                res.not_applicable(t, "Niet opgehaald (passieve modus)")
            return res
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            status, ctype, body = self.fetch(url)
        except FetchError as e:
            res.find("MTASTS_FETCH_FAILED", f"{url}: {e}", info=str(e))
            for t in tests[2:]:
                res.not_applicable(t, "Beleid niet opgehaald")
            return res
        problems = []
        if status != 200:
            problems.append(f"HTTP-status {status}")
        if not ctype.lower().startswith("text/plain"):
            problems.append(f"Content-Type is '{ctype or 'leeg'}' in plaats van text/plain")
        if len(body) > 65536:
            problems.append("beleid groter dan 64 KB")
        if problems:
            res.find("MTASTS_FETCH_FAILED", f"{url}: {'; '.join(problems)}", info="; ".join(problems))
            for t in tests[2:]:
                res.not_applicable(t, "Beleid niet bruikbaar")
            return res
        res.observe("MTASTS-02", f"Opgehaald via {url}")
        text = body.decode("utf-8", "replace")
        res.records.append("Beleid:\n" + text.strip())
        policy, mx_patterns, perr = {}, [], []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                perr.append(f"ongeldige regel '{line[:40]}'")
                continue
            k, v = (x.strip() for x in line.split(":", 1))
            k = k.lower()
            if k == "mx":
                mx_patterns.append(v.lower().rstrip("."))
            elif k in policy:
                perr.append(f"dubbel veld '{k}'")
            else:
                policy[k] = v
        mode = policy.get("mode", "").lower()
        if policy.get("version") != "STSv1":
            perr.append("version: STSv1 ontbreekt")
        if mode not in ("enforce", "testing", "none"):
            perr.append(f"ongeldige mode '{policy.get('mode', '')}'")
        ma = policy.get("max_age", "")
        if not (ma.isdigit() and int(ma) <= 31557600):
            perr.append(f"ongeldige max_age '{ma}'")
        if mode in ("enforce", "testing") and not mx_patterns:
            perr.append("geen mx-regels")
        for pat in mx_patterns:
            if not re.fullmatch(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", pat):
                perr.append(f"ongeldige mx-regel '{pat}'")
        if perr:
            res.find("MTASTS_POLICY_INVALID", "; ".join(perr), info="; ".join(perr))
            for t in tests[3:]:
                res.not_applicable(t, "Beleid ongeldig")
            return res
        res.observe("MTASTS-03", f"mode={mode}, max_age={ma}, mx={', '.join(mx_patterns)}")
        if int(ma) < 86400 and mode != "none":
            res.find("MTASTS_SHORT_MAXAGE", f"max_age={ma}", max_age=ma)
        res.observe("MTASTS-04", f"mode: {mode}")
        if mode != "enforce":
            res.find("MTASTS_TESTING", f"mode: {mode}", mode=mode)
        if mode == "none":
            res.not_applicable("MTASTS-05", "Beleid staat op mode: none")
            return res
        missing = [h for h in ctx["mx_hosts"] if not any(mx_matches(p, h) for p in mx_patterns)]
        for h in missing:
            f = res.find("MTASTS_MX_MISMATCH", f"{h} valt niet onder {', '.join(mx_patterns)}", host=h,
                         patterns=", ".join(mx_patterns))
            if mode != "enforce":
                f["ernst"] = MIDDEN
        if not missing:
            res.observe("MTASTS-05", "Alle mailservers vallen onder het beleid")
        return res

    # ---------------------------------------------------------------- TLS-RPT
    def check_tlsrpt(self, domain, ctx):
        res = Result("TLS-RPT", domain)
        if ctx.get("mx_hosts") is None:
            for t in ("TLSRPT-01",):
                res.set_unknown(t, "De MX-records konden door een DNS-fout niet worden opgevraagd")
            return res
        if not ctx.get("mx_hosts"):
            res.not_applicable("TLSRPT-01", "Domein ontvangt geen mail via MX")
            return res
        r = self.txt(f"_smtp._tls.{domain}")
        recs = [t for t in r.rrs if re.match(r"v\s*=\s*TLSRPTv1", t.strip())]
        res.records = recs
        if not recs:
            res.observe("TLSRPT-01", "Geen TLS-RPT-record")
            res.find("TLSRPT_MISSING", f"Geen record op _smtp._tls.{domain}")
            return res
        tags, order, errs, dups = parse_tags(recs[0])
        bad = list(errs)
        if len(recs) > 1:
            bad.append(f"{len(recs)} records")
        if order[0] != "v" or tags.get("v") != "TLSRPTv1":
            bad.append("v=TLSRPTv1 moet de eerste tag zijn")
        uris = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
        if not uris:
            bad.append("rua ontbreekt")
        for u in uris:
            if not re.fullmatch(r"(mailto:[^@\s]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*|https://[^\s,]+)",
                                u, re.I):
                bad.append(f"ongeldig rapportadres '{u}'")
        if bad:
            res.find("TLSRPT_INVALID", "; ".join(bad), info="; ".join(bad))
        else:
            res.observe("TLSRPT-01", f"rua={tags['rua']}")
        return res

    # ---------------------------------------------------------------- DANE
    def check_dane(self, domain, ctx):
        res = Result("DANE", domain)
        if ctx.get("mx_hosts") is None:
            for t in ("DANE-01", "DANE-02", "DANE-03"):
                res.set_unknown(t, "De MX-records konden door een DNS-fout niet worden opgevraagd")
            return res
        hosts = [h for h in ctx["mx_hosts"] if not _is_ip(h)]
        if not hosts:
            for t in ("DANE-01", "DANE-02", "DANE-03"):
                res.not_applicable(t, "Domein ontvangt geen mail via MX")
            return res

        def get(h):
            return h, self.q.query(f"_25._tcp.{h}", "TLSA")

        with ThreadPoolExecutor(max_workers=8) as pool:
            answers = list(pool.map(get, hosts[:20]))
        failed = [h for h, r in answers if r.status == "error"]
        with_tlsa = [(h, r) for h, r in answers if r.rrs]
        without = [h for h, r in answers if not r.rrs and r.status != "error"]
        validates = ctx.get("resolver_validates")
        unsigned = []
        if failed:
            # DANE vereist dat de zone van de mailserver met DNSSEC is ondertekend. Faalt de
            # TLSA-opvraag, dan stellen we eerst vast of die zone überhaupt ondertekend is: zo niet,
            # dan is DANE sowieso onmogelijk — een definitief resultaat, geen 'niet vast te stellen'.
            # Dit voorkomt dat een domein bij een niet-DNSSEC-mailprovider (bijv. Microsoft 365)
            # onterecht als 'onvolledig getest' wordt beoordeeld. Alleen bij een aantoonbaar
            # ondertekende zone duidt een TLSA-fout op een mogelijk kapotte DNSSEC-keten.
            still_unknown = []
            for h in failed:
                a = self.q.query(h, "A")
                if not a.rrs and a.status != "error":
                    a = self.q.query(h, "AAAA")
                if validates and a.status in ("ok", "nodata", "nxdomain") and not a.ad:
                    unsigned.append(h)
                else:
                    still_unknown.append(h)
            without += unsigned
            if still_unknown:
                res.set_unknown("DANE-01", "DNS-fout bij het opvragen van TLSA voor " + ", ".join(still_unknown) +
                                " (bij een DNSSEC-fout stellen DANE-verzenders de aflevering uit)")
                if not with_tlsa and not without:
                    res.set_unknown("DANE-02", "TLSA-records niet op te vragen")
                    res.set_unknown("DANE-03", "TLSA-records niet op te vragen")
                    return res
        for h, r in with_tlsa:
            for v in r.rrs:
                res.records.append(f"_25._tcp.{h}: {_fmt_rr('TLSA', v)}")
        if not with_tlsa:
            if unsigned and all(h in unsigned for h in without):
                res.observe("DANE-01", f"Geen DANE voor {len(unsigned)} mailserver(s); de zone is niet met "
                                       f"DNSSEC ondertekend, dus DANE is niet mogelijk")
                res.find("DANE_MISSING", "Mailserverzone niet met DNSSEC ondertekend (DANE niet mogelijk): "
                         + ", ".join(unsigned))
            else:
                res.observe("DANE-01", f"Geen TLSA-records voor {len(without)} mailserver(s)")
                res.find("DANE_MISSING", "Geen TLSA-records voor: " + ", ".join(without))
            res.not_applicable("DANE-02", "Geen TLSA-records")
            res.not_applicable("DANE-03", "Geen TLSA-records")
            return res
        if without:
            res.find("DANE_PARTIAL", "Zonder TLSA: " + ", ".join(without), hosts=", ".join(without))
        else:
            res.observe("DANE-01", f"TLSA-records voor alle {len(hosts)} mailserver(s)")
        validates = ctx.get("resolver_validates")
        for h, r in with_tlsa:
            if r.ad:
                res.observe("DANE-02", f"{h}: gevalideerd")
            elif validates:
                res.find("DANE_NOT_VALIDATED", f"{h}: TLSA-antwoord zonder DNSSEC-validatie", host=h)
            else:
                res.unknown["DANE-02"] = "De gebruikte resolver valideert geen DNSSEC (gebruik bijv. -r 9.9.9.9)"
        bad = False
        for h, r in with_tlsa:
            for usage, sel, mtype, data in r.rrs:
                reason = None
                if usage in (0, 1):
                    reason = f"usage {usage} (PKIX) is niet geschikt voor SMTP"
                elif usage not in (2, 3):
                    reason = f"onbekende usage {usage}"
                elif sel not in (0, 1):
                    reason = f"onbekende selector {sel}"
                elif mtype not in (0, 1, 2):
                    reason = f"onbekend matching type {mtype}"
                elif mtype == 1 and len(data) != 64:
                    reason = "SHA-256-hash heeft niet de juiste lengte"
                elif mtype == 2 and len(data) != 128:
                    reason = "SHA-512-hash heeft niet de juiste lengte"
                if reason:
                    rec = f"{usage} {sel} {mtype} {data[:16]}…"
                    res.find("DANE_BAD_PARAMS", f"{h}: {rec} — {reason}", host=h, record=rec, reason=reason)
                    bad = True
        if not bad:
            res.observe("DANE-03", "Alle TLSA-records hebben geschikte parameters")
        return res

    # ---------------------------------------------------------------- DNSSEC
    def check_dnssec(self, domain, ctx):
        res = Result("DNSSEC", domain)
        if ctx.get("dnssec_bogus"):
            res.observe("DNSSEC-01", "Ondertekend, maar de keten is ongeldig")
            res.find("DNSSEC_BOGUS", "SERVFAIL bij validatie; antwoord wel beschikbaar zonder validatie (CD)")
            return res
        zone = self._zone_apex(domain)
        ds = self.q.query(zone, "DS")
        key = self.q.query(zone, "DNSKEY")
        if ds.status == "error" or key.status == "error":
            raise AuditDNSError(f"DNSSEC-gegevens van {zone}: {ds.error or key.error}")
        res.records = [f"{zone} DS {_fmt_rr('DS', v)}" for v in ds.rrs] + \
                      [f"{zone} DNSKEY {_fmt_rr('DNSKEY', v)}" for v in key.rrs]
        if zone != domain:
            res.observe("DNSSEC-01", f"{domain} valt onder zone {zone}")
        if not ds.rrs and not key.rrs:
            res.observe("DNSSEC-01", "Geen DS- en geen DNSKEY-records")
            res.find("DNSSEC_MISSING", f"Geen DS bij de bovenliggende zone en geen DNSKEY voor {zone}")
            res.not_applicable("DNSSEC-02", "Domein is niet ondertekend")
            return res
        if ds.rrs and not key.rrs:
            res.find("DNSSEC_INCOMPLETE", "DS aanwezig maar geen DNSKEY",
                     info=f"Er staat een DS-record voor {zone} bij de bovenliggende zone, maar de zone publiceert "
                            f"geen DNSKEY-records")
        elif key.rrs and not ds.rrs:
            res.find("DNSSEC_NO_DS", f"{len(key.rrs)} DNSKEY-record(s), geen DS bij de bovenliggende zone", zone=zone)
        else:
            res.observe("DNSSEC-01", f"{len(ds.rrs)} DS- en {len(key.rrs)} DNSKEY-record(s)")
        if not ds.rrs:
            res.not_applicable("DNSSEC-02", "Geen DS-record")
            return res
        if key.ad:
            res.observe("DNSSEC-02", "Gevalideerd door de resolver (AD-vlag)")
        elif ctx.get("resolver_validates"):
            res.find("DNSSEC_INCOMPLETE", "Niet gevalideerd ondanks validerende resolver",
                     info="De resolver valideert DNSSEC, maar de antwoorden voor dit domein zijn niet als veilig "
                            "gemarkeerd")
        else:
            res.unknown["DNSSEC-02"] = "De gebruikte resolver valideert geen DNSSEC (gebruik bijv. -r 9.9.9.9)"
        return res

    def _zone_apex(self, domain):
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            r = self.q.query(cand, "SOA")
            if r.status == "ok" and r.rrs:
                return cand
        return domain

    # ---------------------------------------------------------------- BIMI
    def check_bimi(self, domain, ctx):
        res = Result("BIMI", domain)
        r = self.txt(f"default._bimi.{domain}")
        recs = [t for t in r.rrs if re.match(r"v\s*=\s*BIMI1", t.strip(), re.I)]
        res.records = recs
        if not recs:
            res.observe("BIMI-01", "Geen BIMI-record (optioneel)")
            res.info.add("BIMI-01")
            return res
        tags, order, errs, dups = parse_tags(recs[0])
        bad = list(errs)
        if len(recs) > 1:
            bad.append(f"{len(recs)} records")
        if order[0] != "v" or tags.get("v") != "BIMI1":
            bad.append("v=BIMI1 moet de eerste tag zijn")
        loc = tags.get("l", "")
        if loc and not re.fullmatch(r"https://\S+\.svg", loc, re.I):
            bad.append("l= moet een https-URL naar een SVG-bestand zijn")
        if tags.get("a") and not re.fullmatch(r"https://\S+", tags["a"], re.I):
            bad.append("a= moet een https-URL zijn")
        if bad:
            res.find("BIMI_INVALID", "; ".join(bad), info="; ".join(bad))
        else:
            res.observe("BIMI-01", f"Geldig record; logo: {loc or '(geen)'}" + (", met VMC/CMC" if tags.get("a") else ""))
        dt = ctx.get("dmarc_tags") or {}
        pol = ctx.get("dmarc_policy")
        weak = (pol not in ("quarantine", "reject") or dt.get("sp", "").lower() == "none"
                or dt.get("t", "n").lower() == "y" or (dt.get("pct", "100").isdigit() and int(dt.get("pct", "100")) < 100))
        if weak:
            res.find("BIMI_DMARC_WEAK", f"DMARC-beleid: {pol or 'geen'}", info=f"p={pol or 'geen'}")
        return res


def spf_walk(q, domain, path=(), out=None):
    """Volledige analyse van de SPF-boom die, anders dan check_host(), na een fout doorgaat.

    Telt DNS-lookups zoals bij evaluatie voor een niet-geautoriseerd adres (alle termen tot 'all', redirect
    alleen zonder 'all'), en verzamelt alle problemen: (soort, domein, tekst). Macro-doelen worden geteld maar
    niet gevolgd."""
    if out is None:
        out = {"lookups": 0, "problems": [], "records": []}
    d = domain.lower().rstrip(".")
    if d in path:
        out["problems"].append(("loop", d, " -> ".join(path + (d,))))
        return out
    if len(path) > 12:
        return out
    r = q.query(d, "TXT")
    if r.status == "error":
        out["problems"].append(("dns", d, f"DNS-fout voor {d}: {r.error}"))
        return out
    recs = [t for t in r.rrs if is_spf_record(t)]
    if not recs:
        out["problems"].append(("none", d, f"{d} heeft geen SPF-record"))
        return out
    if len(recs) > 1:
        out["problems"].append(("multiple", d, f"meerdere SPF-records op {d}"))
        return out
    out["records"].append((d, recs[0]))
    try:
        terms, mods = parse_spf(recs[0])
    except SPFPermError as e:
        out["problems"].append(("syntax", d, str(e)))
        return out
    has_all = False
    for t in terms:
        if t.kind != "mech":
            continue
        if t.name == "all":
            has_all = True
            break
        if t.name in ("include", "a", "mx", "ptr", "exists"):
            out["lookups"] += 1
        if t.name == "include" and "%" not in t.arg:
            spf_walk(q, t.arg, path + (d,), out)
    if not has_all and "redirect" in mods:
        out["lookups"] += 1
        if "%" not in mods["redirect"]:
            spf_walk(q, mods["redirect"], path + (d,), out)
    return out


class AuditDNSError(Exception):
    pass


def mx_matches(pattern, host):
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and host.count(".") == base.count(".") + 1
    return host == pattern


def merge_spf(recs):
    terms = []
    for r in recs:
        for t in r.split()[1:]:
            lt = t.lower()
            if re.fullmatch(r"[+\-~?]?all", lt) or lt.startswith("redirect="):
                continue
            if lt not in (x.lower() for x in terms):
                terms.append(t)
    return "v=spf1 " + " ".join(terms + ["-all"])


DMARC_TAG_ORDER = ["v", "p", "sp", "np", "t", "pct", "rua", "ruf", "adkim", "aspf", "fo", "psd"]


def dmarc_suggest(domain, tags, **overrides):
    new = {"v": "DMARC1"}
    new.update({k: v for k, v in tags.items() if k != "v"})
    for k, v in overrides.items():
        if v is None:
            new.pop(k, None)
        else:
            new[k] = v
    keys = [k for k in DMARC_TAG_ORDER if k in new] + [k for k in new if k not in DMARC_TAG_ORDER]
    return f'_dmarc.{domain}. TXT "' + "; ".join(f"{k}={new[k]}" for k in keys) + '"'


# ------------------------------------------------------------------ RSA-sleutellengte (DER)

def _der(data, i, expect=None):
    if i + 2 > len(data):
        raise ValueError("RSA-sleutel is afgekapt")
    tag, length = data[i], data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or i + n > len(data):
            raise ValueError("ongeldige DER-lengte in RSA-sleutel")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    if i + length > len(data):
        raise ValueError("RSA-sleutel is afgekapt")
    if expect is not None and tag != expect:
        raise ValueError("RSA-sleutel heeft een onverwachte structuur")
    return tag, data[i:i + length], i + length


RSA_OID = bytes.fromhex("2a864886f70d010101")


def rsa_key_bits(der):
    """Sleutellengte uit SubjectPublicKeyInfo (rsaEncryption) of PKCS#1 RSAPublicKey."""
    _, body, end = _der(der, 0, 0x30)
    if end != len(der):
        raise ValueError("onverwachte gegevens na de RSA-sleutel")
    tag, inner, j = _der(body, 0)
    if tag == 0x30:
        _, oid, _ = _der(inner, 0, 0x06)
        if oid != RSA_OID:
            raise ValueError("sleutel is geen RSA-sleutel (verkeerd algoritme voor k=rsa)")
        _, bitstr, _ = _der(body, j, 0x03)
        if not bitstr or bitstr[0] != 0:
            raise ValueError("ongeldige BIT STRING in RSA-sleutel")
        _, seq, _ = _der(bitstr[1:], 0, 0x30)
        _, modulus, k = _der(seq, 0, 0x02)
        _der(seq, k, 0x02)
    elif tag == 0x02:
        modulus = inner
        _der(body, j, 0x02)
    else:
        raise ValueError("onbekend sleutelformaat")
    bits = int.from_bytes(modulus, "big").bit_length()
    if bits < 256:
        raise ValueError("RSA-modulus is ongeldig")
    return bits


# =====================================================================================
# Uitvoeren en rapport opbouwen
# =====================================================================================

def resolver_validates(q):
    """Valideert de resolver DNSSEC? Getest op de altijd-ondertekende rootzone."""
    return bool(q.query(".", "DNSKEY").ad)


def audit_domain(base_resolver, domain, only, auditor_kwargs):
    # None = (nog) onbekend; checks vullen dit in. Afhankelijke checks behandelen None als 'niet vast te stellen'.
    ctx = {"mx_hosts": None, "spf_state": None, "dkim_found": None}
    q = base_resolver
    pre = q.query(domain, "SOA")
    if pre.status == "nxdomain":
        anyrec = any(q.query(domain, t).status != "nxdomain" for t in ("TXT", "MX", "A"))
        if not anyrec:
            return [], ctx, "Het domein bestaat niet (NXDOMAIN)"
    if pre.status == "error" and pre.error == "SERVFAIL":
        alt = q.query(domain, "SOA", cd=True)
        if alt.status != "error":
            ctx["dnssec_bogus"] = True
            q = CDResolver(base_resolver)
    ctx["resolver_validates"] = resolver_validates(base_resolver)
    aud = Auditor(q, **auditor_kwargs)
    funcs = {"MX": aud.check_mx, "SPF": aud.check_spf, "DKIM": aud.check_dkim, "DMARC": aud.check_dmarc,
             "MTA-STS": aud.check_mtasts, "TLS-RPT": aud.check_tlsrpt, "DANE": aud.check_dane,
             "DNSSEC": aud.check_dnssec, "BIMI": aud.check_bimi}
    deps = {"DKIM": {"SPF"}, "DMARC": {"SPF", "DKIM"}, "BIMI": {"DMARC"}, "MTA-STS": {"MX"},
            "TLS-RPT": {"MX"}, "DANE": {"MX"}}
    needed = set(only)
    while True:
        extra = set().union(*(deps.get(c, set()) for c in needed)) - needed
        if not extra:
            break
        needed |= extra
    results = []
    for name in CHECKS:
        if name not in needed:
            continue
        try:
            r = funcs[name](domain, ctx)
        except AuditDNSError as e:
            r = Result(name, domain)
            r.fout = f"DNS-fout tijdens de test: {e}"
        if name in only:
            results.append(r)
    return results, ctx, None


def oordeel(worst, onvolledig):
    if worst in (KRITIEK, HOOG):
        o = "Onvoldoende"
    elif worst == MIDDEN:
        o = "Matig"
    elif worst == LAAG:
        o = "Goed, met verbeterpunten"
    else:
        o = "Goed"
    return o + (" (onvolledig getest)" if onvolledig else "")


class SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def build_report(runs, meta):
    nr = 0
    domeinen = []
    for domain, results, dnslog, fout in runs:
        pairs = [(r, f) for r in results for f in r.findings]
        pairs.sort(key=lambda x: (-ERNST_ORDE[x[1]["ernst"]], CHECKS.index(x[0].check)))
        bevindingen = []
        for r, f in pairs:
            nr += 1
            cat = FINDINGS[f["code"]]
            kw = SafeDict(domain=domain, info=f["detail"])
            kw.update({k: str(v) for k, v in f["kw"].items()})
            voorbeeld = f["voorbeeld"] or (cat.get("voorbeeld") or "").format_map(kw)
            bevindingen.append({
                "id": f"F-{nr:02d}", "code": f["code"], "ernst": f["ernst"], "onderdeel": r.check,
                "test": cat["test"], "ook_tests": list(f.get("also", ())), "titel": cat["titel"].format_map(kw), "aangetroffen": f["detail"],
                "risico": cat["risico"].format_map(kw), "oplossing": cat["oplossing"].format_map(kw),
                "voorbeeld": voorbeeld or None, "referentie": cat["ref"],
            })
        onderdelen = []
        for r in results:
            tests = []
            for tid, (chk, naam, oms) in TESTS.items():
                if chk != r.check:
                    continue
                fs = [b for b in bevindingen if b["test"] == tid or tid in b["ook_tests"]]
                worst = max((b["ernst"] for b in fs), key=ERNST_ORDE.get, default=None)
                waarneming = "; ".join(r.obs.get(tid, [])) or "; ".join(b["aangetroffen"] for b in fs)
                if r.fout:
                    resultaat, waarneming = "Niet uitgevoerd", r.fout
                elif fs:
                    resultaat = "Informatief" if worst == INFO else "Bevinding"
                elif tid in r.unknown:
                    resultaat, waarneming = "Niet vast te stellen", (waarneming + "; " if waarneming else "") + r.unknown[tid]
                elif tid in r.info:
                    resultaat = "Informatief"
                elif tid in r.obs:
                    resultaat = "Geslaagd"
                elif tid in r.na:
                    resultaat, waarneming = "Niet van toepassing", r.na[tid]
                else:
                    resultaat, waarneming = "Niet van toepassing", "Niet getest omdat een voorafgaande test faalde"
                tests.append({"id": tid, "naam": naam, "omschrijving": oms, "resultaat": resultaat, "ernst": worst,
                              "waarneming": waarneming, "bevindingen": [b["id"] for b in fs]})
            sev = [b["ernst"] for b in bevindingen if b["onderdeel"] == r.check]
            if r.fout:
                status = "Fout"
            elif sev:
                status = max(sev, key=ERNST_ORDE.get)
            elif any(t["resultaat"] == "Niet vast te stellen" for t in tests):
                status = "?"
            elif all(t["resultaat"] in ("Niet van toepassing", "Informatief") for t in tests):
                status = "N.v.t."
            else:
                status = "OK"
            onderdelen.append({"onderdeel": r.check, "uitleg": CHECK_UITLEG[r.check], "records": r.records,
                               "status": status, "tests": tests, "fout": r.fout, "details": r.details})
        telling = {e: sum(1 for b in bevindingen if b["ernst"] == e) for e in ERNSTEN}
        worst = max((b["ernst"] for b in bevindingen), key=ERNST_ORDE.get, default=None)
        onvolledig = bool(fout) or any(r.fout or r.dns_unknown for r in results)
        seen, dnsrows = set(), []
        for e in dnslog:
            key = (e["naam"].lower(), e["type"])
            if key in seen:
                continue
            if "._domainkey." in e["naam"] and e["status"] in ("nxdomain", "nodata"):
                continue
            seen.add(key)
            dnsrows.append(e)
        domeinen.append({"domein": domain, "oordeel": "Niet getest" if fout else oordeel(worst, onvolledig),
                         "fout": fout, "hoogste_ernst": worst, "onvolledig": onvolledig, "telling": telling,
                         "onderdelen": onderdelen, "bevindingen": bevindingen, "dns": dnsrows})
    return {
        "meta": meta,
        "ernstniveaus": ERNST_UITLEG,
        "testcatalogus": [{"id": t, "onderdeel": c, "naam": n, "omschrijving": o}
                          for t, (c, n, o) in TESTS.items() if c in meta["onderdelen"]],
        "domeinen": domeinen,
    }


def scope_tekst(meta):
    s = ("De controle is passief uitgevoerd: er zijn uitsluitend openbare DNS-records opgevraagd")
    if "MTA-STS" in meta["onderdelen"] and meta["http"]:
        s += " en is het openbare MTA-STS-beleid via HTTPS opgehaald"
    return s + (". Er is geen e-mail verstuurd en er is geen verbinding gemaakt met de mailservers van de "
                "organisatie. De SPF-evaluatie volgt RFC 7208 en is gevalideerd met de officiële RFC 7208-testsuite.")


BEPERKINGEN = [
    "De resultaten zijn een momentopname van de DNS-configuratie op het moment van testen.",
    "DKIM-selectors zijn niet via DNS op te vragen. Zonder opgegeven selector is gezocht op een lijst met "
    "veelgebruikte selectors; via RFC 8020 is wel vastgesteld of er überhaupt DKIM-sleutels bestaan.",
    "Er is niet getest of daadwerkelijk verstuurde e-mail SPF, DKIM en DMARC doorstaat (alignment in de praktijk); "
    "daarvoor zijn de DMARC-rapporten of een testbericht nodig.",
    "STARTTLS-ondersteuning en de certificaten van de mailservers zelf zijn niet getest, omdat daarvoor een "
    "verbinding met de mailservers nodig is.",
    "De DNSSEC-validatie hangt af van de gebruikte resolver; als die niet valideert, is dat in het rapport vermeld.",
]


# =====================================================================================
# Weergave: terminal
# =====================================================================================

COLORS = {"red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m", "cyan": "\033[36m",
          "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}
ERNST_KLEUR = {KRITIEK: "red", HOOG: "red", MIDDEN: "yellow", LAAG: "yellow", INFO: "cyan"}


def _short_keys(text):
    return re.sub(r"(p=[A-Za-z0-9+/]{24})[A-Za-z0-9+/=]{8,}", r"\1…", str(text))


def print_terminal(report, color, extra=None):
    c = (lambda k: COLORS[k]) if color else (lambda k: "")
    w = 76
    for dom in report["domeinen"]:
        kleur = ERNST_KLEUR.get(dom["hoogste_ernst"], "green")
        print(f"\n{c('bold')}{'═' * w}\n  {dom['domein']}   {c(kleur)}Oordeel: {dom['oordeel']}{c('reset')}"
              f"{c('bold')}\n{'═' * w}{c('reset')}")
        if dom["fout"]:
            print(f"   {c('red')}✘ {dom['fout']}{c('reset')}")
            continue
        for o in dom["onderdelen"]:
            print(f"\n{c('bold')}{o['onderdeel']}{c('reset')}")
            if o["fout"]:
                print(f"   {c('red')}✘ {o['fout']}{c('reset')}")
            for rec in o["records"]:
                for line in str(rec).splitlines():
                    print(f"   {c('dim')}│ {_short_keys(line)}{c('reset')}")
            for t in o["tests"]:
                res = t["resultaat"]
                if res == "Geslaagd":
                    sym, k = "✔", "green"
                elif res == "Bevinding":
                    sym, k = ("✘" if t["ernst"] in (KRITIEK, HOOG) else "!"), ERNST_KLEUR[t["ernst"]]
                elif res == "Informatief":
                    sym, k = "ℹ", "cyan"
                elif res == "Niet vast te stellen":
                    sym, k = "?", "cyan"
                else:
                    sym, k = "–", "dim"
                tag = f" [{t['ernst']}]" if res == "Bevinding" else ""
                print(f"   {c(k)}{sym}{c('reset')} {t['id']:<10}{t['naam']}{c(k)}{tag}{c('reset')}"
                      f"{c('dim')} — {_short_keys(t['waarneming'])}{c('reset')}")
        if dom["bevindingen"]:
            print(f"\n{c('bold')}Bevindingen{c('reset')}")
            for b in dom["bevindingen"]:
                k = ERNST_KLEUR[b["ernst"]]
                print(f"\n  {c(k)}{c('bold')}{b['id']} [{b['ernst']}]{c('reset')}{c('bold')} {b['titel']}{c('reset')}")
                for line in textwrap.wrap("Oplossing: " + b["oplossing"], w - 6, break_on_hyphens=False,
                                          break_long_words=False):
                    print("      " + line)
                if b["voorbeeld"]:
                    for line in b["voorbeeld"].splitlines():
                        print(f"      {c('cyan')}{_short_keys(line)}{c('reset')}")
        else:
            print(f"\n{c('green')}Geen bevindingen.{c('reset')}")
    if extra:
        print(f"\n{c('bold')}SPF-test voor opgegeven IP-adres{c('reset')}")
        for e in extra:
            print(f"   {e['domein']}: {e['ip']} → {c('bold')}{e['uitkomst']}{c('reset')} "
                  f"(term: {e['term']}{', ' + e['fout'] if e['fout'] else ''})")
    print()


# =====================================================================================
# Weergave: Markdown
# =====================================================================================

def _md(s):
    """Escapet tekst (ook uit DNS afkomstig) voor Markdown: geen HTML, geen tabelbreuk, geen opmaak-injectie.

    Backslashes worden eerst geëscaped, daarna de overige speciale tekens (inclusief '|'); anders zou het
    escapen van de backslash de zojuist toegevoegde pijp-escape ongedaan maken en de tabel alsnog breken."""
    s = re.sub(r"[\r\n]+", " ", html.escape(str(s), quote=False))
    s = s.replace("\\", "\\\\")
    return re.sub(r"([`*_\[\]#|])", r"\\\1", s)


def _fence(text):
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    f = "`" * max(3, run + 1)
    return f"{f}\n{text}\n{f}"


def _nl_join(items):
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " en " + items[-1]


def _summary_text(report):
    ds = [d for d in report["domeinen"] if not d["fout"]]
    totaal = sum(len(d["bevindingen"]) for d in ds)
    zwaar = sum(d["telling"][KRITIEK] + d["telling"][HOOG] for d in ds)
    n = len(report["domeinen"])
    s = (f"Op {report['meta']['datum_weergave']} is de e-mailbeveiliging van {n} domein{'en' if n != 1 else ''} "
         f"gecontroleerd op {_nl_join(report['meta']['onderdelen'])}. ")
    if totaal == 0:
        s += "Er zijn geen bevindingen gedaan."
    else:
        s += f"In totaal zijn {totaal} bevinding{'en' if totaal != 1 else ''} vastgesteld"
        s += (f", waarvan {zwaar} met ernst Hoog of Kritiek. Deze verdienen met voorrang aandacht, omdat ze misbruik "
              f"van het domein voor phishing en spoofing mogelijk maken of de aflevering van legitieme e-mail in "
              f"gevaar brengen." if zwaar else ". Er zijn geen bevindingen met ernst Hoog of Kritiek.")
    if any(d["fout"] for d in report["domeinen"]):
        s += " Niet alle domeinen konden worden getest; zie de resultaten per domein."
    return s


def _status_symbol(st):
    return {"OK": "✔", "N.v.t.": "–", "Fout": "⚠", "?": "?"}.get(st, st)


def render_markdown(report):
    m = report["meta"]
    L = [f"# Rapportage e-mailbeveiliging{' – ' + m['klant'] if m['klant'] else ''}\n", "| | |\n|---|---|"]
    for k, v in _meta_rows(report):
        L.append(f"| **{k}** | {_md(v)} |")
    L.append("\n## 1. Samenvatting\n")
    L.append(_summary_text(report) + "\n")
    L.append("| Domein | Oordeel | Kritiek | Hoog | Midden | Laag | Info |\n|---|---|---|---|---|---|---|")
    for d in report["domeinen"]:
        t = d["telling"]
        L.append(f"| {d['domein']} | **{d['oordeel']}** | {t[KRITIEK]} | {t[HOOG]} | {t[MIDDEN]} | {t[LAAG]} | {t[INFO]} |")
    L.append("\n### Status per onderdeel\n")
    L.append("| Domein | " + " | ".join(m["onderdelen"]) + " |\n|---|" + "---|" * len(m["onderdelen"]))
    for d in report["domeinen"]:
        st = {o["onderdeel"]: o["status"] for o in d["onderdelen"]}
        L.append(f"| {d['domein']} | " + " | ".join(_status_symbol(st.get(c, "–")) for c in m["onderdelen"]) + " |")
    acties = [(d["domein"], b) for d in report["domeinen"] for b in d["bevindingen"] if b["ernst"] != INFO]
    acties.sort(key=lambda x: -ERNST_ORDE[x[1]["ernst"]])
    if acties:
        L.append("\n### Actieplan (op prioriteit)\n")
        L.append("| ID | Domein | Ernst | Bevinding |\n|---|---|---|---|")
        for dom, b in acties:
            L.append(f"| {b['id']} | {dom} | {b['ernst']} | {_md(b['titel'])} |")
    L.append("\n## 2. Scope en werkwijze\n")
    L.append(scope_tekst(m) + "\n")
    L.append("### Uitgevoerde tests\n")
    L.append("| ID | Onderdeel | Test | Wat is gecontroleerd |\n|---|---|---|---|")
    for t in report["testcatalogus"]:
        L.append(f"| {t['id']} | {t['onderdeel']} | {_md(t['naam'])} | {_md(t['omschrijving'])} |")
    L.append("\n### Ernstniveaus\n")
    L.append("| Ernst | Betekenis |\n|---|---|")
    for e, u in report["ernstniveaus"].items():
        L.append(f"| {e} | {_md(u)} |")
    L.append("\n### Beperkingen\n")
    L += [f"- {b}" for b in BEPERKINGEN]
    L.append("\n## 3. Resultaten per domein\n")
    for d in report["domeinen"]:
        L.append(f"### {d['domein']} — {d['oordeel']}\n")
        if d["fout"]:
            L.append(f"{_md(d['fout'])}\n")
            continue
        L.append("| ID | Test | Resultaat | Waarneming |\n|---|---|---|---|")
        for o in d["onderdelen"]:
            for t in o["tests"]:
                res = t["resultaat"] + (f" ({t['ernst']}, {', '.join(t['bevindingen'])})" if t["bevindingen"] else "")
                L.append(f"| {t['id']} | {_md(t['naam'])} | {_md(res)} | {_md(_short_keys(t['waarneming']))} |")
        L.append("")
        if not d["bevindingen"]:
            L.append("Er zijn voor dit domein geen bevindingen gedaan.\n")
        for b in d["bevindingen"]:
            L.append(f"#### {b['id']} · {b['ernst']} · {_md(b['titel'])}\n")
            L.append(f"- **Onderdeel / test:** {b['onderdeel']} / {b['test']} ({_md(TESTS[b['test']][1])})")
            L.append(f"- **Aangetroffen:** {_md(_short_keys(b['aangetroffen']))}")
            L.append(f"- **Risico:** {_md(b['risico'])}")
            L.append(f"- **Oplossing:** {_md(b['oplossing'])}")
            if b["voorbeeld"]:
                L.append("- **Voorbeeld:**\n\n" + _fence(b["voorbeeld"]))
            L.append(f"- **Referentie:** {_md(b['referentie'])}\n")
    L.append("## Bijlage A. Opgevraagde DNS-gegevens\n")
    for d in report["domeinen"]:
        L.append(f"### {d['domein']}\n")
        L.append("| Naam | Type | Antwoord | DNSSEC |\n|---|---|---|---|")
        for e in d["dns"]:
            L.append(f"| {_md(e['naam'])} | {e['type']} | {_dns_answer(e, '<br>', _md)} | {'ja' if e['dnssec'] else ''} |")
        L.append("")
    L.append(f"\n_Gegenereerd met mailcheck {m['versie']} op {m['datum_weergave']}._\n")
    return "\n".join(L)


def _dns_answer(e, sep, esc):
    if e["fout"]:
        return esc(f"Fout: {e['fout']}")
    if e["antwoord"]:
        return sep.join(esc(x) for x in e["antwoord"])
    return esc("(bestaat niet)" if e["status"] == "nxdomain" else "(geen record)")


def _meta_rows(report):
    m = report["meta"]
    rows = [("Klant", m["klant"]), ("Domein(en)", ", ".join(d["domein"] for d in report["domeinen"])),
            ("Datum en tijd", m["datum_weergave"]), ("Uitgevoerd door", m["uitvoerder"]),
            ("Referentie", m["referentie"]), ("Gebruikte tool", f"mailcheck {m['versie']}"),
            ("DNS-resolver", ", ".join(m["resolvers"]) + (" (valideert DNSSEC)" if m.get("resolver_valideert") else
                                                           " (valideert geen DNSSEC)"))]
    return [(k, v) for k, v in rows if v]


# =====================================================================================
# Weergave: HTML
# =====================================================================================

CSS = """
:root{--ink:#0f172a;--muted:#5b6474;--line:#e3e7ee;--soft:#f6f8fb;--accent:#0b4f8a;
--kritiek:#8b1538;--hoog:#d62828;--midden:#c96a00;--laag:#2563eb;--info:#64748b;--ok:#15803d}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#eef1f5;color:var(--ink);font:14px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:960px;margin:24px auto;background:#fff;padding:52px 60px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.cover{border-bottom:3px solid var(--accent);padding-bottom:26px;margin-bottom:8px}
.kicker{text-transform:uppercase;letter-spacing:.14em;font-size:11.5px;color:var(--accent);font-weight:700}
h1{font-size:30px;line-height:1.2;margin:8px 0 2px}
.sub{color:var(--muted);font-size:15px;margin:0 0 22px}
h2{font-size:20px;margin:44px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--line);color:var(--accent)}
h3{font-size:17px;margin:30px 0 10px}
h4{font-size:13px;margin:22px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
p{margin:0 0 12px}
table{width:100%;border-collapse:collapse;margin:6px 0 18px;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
table.meta td{border:none;padding:3px 0}
table.meta td:first-child{width:170px;color:var(--muted)}
table.matrix th,table.matrix td{text-align:center;padding:6px 4px}
table.matrix td:first-child,table.matrix th:first-child{text-align:left}
td.id,td.nowrap{white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11.5px;font-weight:600;color:#fff;white-space:nowrap;line-height:1.7}
.b-Kritiek{background:var(--kritiek)}.b-Hoog{background:var(--hoog)}.b-Midden{background:var(--midden)}
.b-Laag{background:var(--laag)}.b-Info{background:var(--info)}.b-OK{background:var(--ok)}
.b-na{background:#e2e8f0;color:#475569}.b-Fout{background:#7c2d12}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin:14px 0 6px}
.card{border:1px solid var(--line);border-top:5px solid var(--c);border-radius:10px;padding:14px 16px}
.card .dom{font-weight:700;font-size:15px}
.card .verdict{font-size:18px;font-weight:700;color:var(--c);margin:2px 0 8px}
.counts{display:flex;gap:6px;flex-wrap:wrap}
.counts .zero{background:#eef1f5;color:#94a3b8}
.finding{border:1px solid var(--line);border-left:5px solid var(--c);border-radius:8px;padding:16px 18px;margin:14px 0;break-inside:avoid}
.finding .head{display:flex;gap:10px;align-items:baseline;margin-bottom:10px}
.finding .fid{font-weight:700;color:var(--muted);white-space:nowrap}
.finding .title{font-weight:700;font-size:15px;flex:1}
.finding dl{display:grid;grid-template-columns:120px 1fr;gap:6px 16px;margin:0}
.finding dt{color:var(--muted);font-weight:600;font-size:13px}
.finding dd{margin:0}
pre{background:#0f1b2d;color:#e6edf7;padding:10px 12px;border-radius:6px;margin:2px 0 0;
font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
pre.records{background:var(--soft);border:1px solid var(--line);color:var(--ink)}
.check-intro{color:var(--muted);margin:10px 0 4px;font-size:13px}
.note{background:#fff8e6;border:1px solid #f3dca0;border-radius:8px;padding:10px 14px;font-size:13px}
.ok-box{background:#ecf8f0;border:1px solid #b6e2c4;border-radius:8px;padding:10px 14px}
.err-box{background:#fdeeee;border:1px solid #f2b8b8;border-radius:8px;padding:10px 14px}
ul.plain{padding-left:18px;margin:0 0 12px}
.muted{color:var(--muted)}
footer{margin-top:48px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@page{size:A4;margin:15mm 14mm}
@media print{body{background:#fff}.page{margin:0;padding:0;max-width:none;box-shadow:none}
h2,h3,h4{break-after:avoid}.domain{break-before:page}tr{break-inside:avoid}}
@media (max-width:640px){.page{padding:24px 16px;margin:0}.finding dl{grid-template-columns:1fr}}
"""

ERNST_CSSVAR = {KRITIEK: "--kritiek", HOOG: "--hoog", MIDDEN: "--midden", LAAG: "--laag", INFO: "--info"}


def _e(s):
    return html.escape(str(s if s is not None else ""), quote=True)


def _result_badge(t):
    r = t["resultaat"]
    if r == "Geslaagd":
        return '<span class="badge b-OK">Geslaagd</span>'
    if r == "Bevinding":
        return f'<span class="badge b-{_e(t["ernst"])}">{_e(t["ernst"])}</span>'
    if r == "Informatief":
        return '<span class="badge b-Info">Informatief</span>'
    return f'<span class="badge b-na">{_e(r)}</span>'


def _status_badge(st):
    if st == "OK":
        return '<span class="badge b-OK">✔</span>'
    if st == "N.v.t.":
        return '<span class="muted">–</span>'
    if st == "Fout":
        return '<span class="badge b-Fout">fout</span>'
    if st == "?":
        return '<span class="badge b-na" title="Niet vast te stellen">?</span>'
    return f'<span class="badge b-{_e(st)}">{_e(st)}</span>'


def render_html(report):
    m = report["meta"]
    H = []
    a = H.append
    title = "Rapportage e-mailbeveiliging" + (f" – {m['klant']}" if m["klant"] else "")
    a(f'<!doctype html><html lang="nl"><head><meta charset="utf-8">'
      f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(title)}</title>'
      f'<style>{CSS}</style></head><body><div class="page">')
    a('<section class="cover"><div class="kicker">Security check e-mail</div>'
      f'<h1>Rapportage e-mailbeveiliging</h1><p class="sub">{_e(" · ".join(m["onderdelen"]))}</p><table class="meta">')
    for k, v in _meta_rows(report):
        a(f"<tr><td>{_e(k)}</td><td><strong>{_e(v)}</strong></td></tr>")
    a("</table></section>")

    a(f"<h2>1. Samenvatting</h2><p>{_e(_summary_text(report))}</p><div class='cards'>")
    for d in report["domeinen"]:
        var = "--ok" if d["hoogste_ernst"] in (None, INFO) else ERNST_CSSVAR[d["hoogste_ernst"]]
        if d["fout"]:
            var = "--info"
        a(f'<div class="card" style="--c:var({var})"><div class="dom">{_e(d["domein"])}</div>'
          f'<div class="verdict">{_e(d["oordeel"])}</div><div class="counts">')
        for e in ERNSTEN:
            n = d["telling"][e]
            a(f'<span class="badge {"b-" + e if n else "zero"}">{n} {e}</span>')
        a("</div>")
        top = [b for b in d["bevindingen"] if b["ernst"] in (KRITIEK, HOOG, MIDDEN)][:4]
        if top:
            a("<ul>" + "".join(f"<li>{_e(b['titel'])} <span class='muted'>({b['id']})</span></li>" for b in top)
              + "</ul>")
        if d["fout"]:
            a(f"<p class='muted'>{_e(d['fout'])}</p>")
        a("</div>")
    a("</div><h4>Status per onderdeel</h4><table class='matrix'><tr><th>Domein</th>"
      + "".join(f"<th>{_e(c)}</th>" for c in m["onderdelen"]) + "</tr>")
    for d in report["domeinen"]:
        st = {o["onderdeel"]: o["status"] for o in d["onderdelen"]}
        a(f"<tr><td><strong>{_e(d['domein'])}</strong></td>"
          + "".join(f"<td>{_status_badge(st.get(c, 'N.v.t.'))}</td>" for c in m["onderdelen"]) + "</tr>")
    a("</table>")
    acties = [(d["domein"], b) for d in report["domeinen"] for b in d["bevindingen"] if b["ernst"] != INFO]
    acties.sort(key=lambda x: -ERNST_ORDE[x[1]["ernst"]])
    if acties:
        a("<h4>Actieplan (op prioriteit)</h4><table><tr><th>ID</th><th>Domein</th><th>Ernst</th><th>Bevinding</th></tr>")
        for dom, b in acties:
            a(f"<tr><td class='id'><a href='#{b['id']}'>{b['id']}</a></td><td>{_e(dom)}</td>"
              f"<td><span class='badge b-{b['ernst']}'>{b['ernst']}</span></td><td>{_e(b['titel'])}</td></tr>")
        a("</table>")

    a(f"<h2>2. Scope en werkwijze</h2><p>{_e(scope_tekst(m))}</p>")
    a("<h4>Onderzochte onderdelen</h4><table><tr><th>Onderdeel</th><th>Doel</th></tr>")
    for chk in m["onderdelen"]:
        a(f"<tr><td class='nowrap'><strong>{_e(chk)}</strong></td><td>{_e(CHECK_UITLEG[chk])}</td></tr>")
    a("</table><h4>Uitgevoerde tests</h4><table><tr><th>ID</th><th>Test</th><th>Wat is gecontroleerd</th></tr>")
    for t in report["testcatalogus"]:
        a(f"<tr><td class='id'>{t['id']}</td><td class='nowrap'>{_e(t['naam'])}</td><td>{_e(t['omschrijving'])}</td></tr>")
    a("</table><h4>Ernstniveaus</h4><table><tr><th>Ernst</th><th>Betekenis</th></tr>")
    for e, u in report["ernstniveaus"].items():
        a(f"<tr><td><span class='badge b-{e}'>{e}</span></td><td>{_e(u)}</td></tr>")
    a("</table><h4>Beperkingen</h4><ul class='plain'>" + "".join(f"<li>{_e(b)}</li>" for b in BEPERKINGEN) + "</ul>")
    if "DKIM" in m["onderdelen"]:
        sel_bron = ("opgegeven door de tester" if m["selectors_opgegeven"]
                    else f"standaardlijst van {len(m['selectors'])} veelgebruikte selectors")
        a(f"<p class='note'><strong>DKIM-selectors:</strong> "
          f"{sel_bron}"
          f" — <span class='mono'>{_e(', '.join(m['selectors']))}</span></p>")

    a("<h2>3. Resultaten per domein</h2>")
    for i, d in enumerate(report["domeinen"]):
        a(f'<section class="{"domain" if i else ""}"><h3>{_e(d["domein"])} — {_e(d["oordeel"])}</h3>')
        if d["fout"]:
            a(f"<p class='err-box'>{_e(d['fout'])}</p></section>")
            continue
        a("<h4>Testresultaten</h4><table><tr><th>ID</th><th>Test</th><th>Resultaat</th><th>Waarneming</th></tr>")
        for o in d["onderdelen"]:
            for t in o["tests"]:
                refs = (" <span class='muted'>→ " + ", ".join(f"<a href='#{x}'>{x}</a>" for x in t["bevindingen"])
                        + "</span>") if t["bevindingen"] else ""
                a(f"<tr><td class='id'>{t['id']}</td><td>{_e(t['naam'])}</td><td class='nowrap'>{_result_badge(t)}{refs}</td>"
                  f"<td>{_e(_short_keys(t['waarneming']))}</td></tr>")
        a("</table>")
        for o in d["onderdelen"]:
            if o["records"]:
                a(f"<p class='check-intro'><strong>{_e(o['onderdeel'])}</strong> — aangetroffen gegevens:</p>"
                  f"<pre class='records'>{_e(chr(10).join(_short_keys(r) for r in o['records']))}</pre>")
        a("<h4>Bevindingen en oplossingen</h4>")
        if not d["bevindingen"]:
            a("<p class='ok-box'>Er zijn voor dit domein geen bevindingen gedaan.</p>")
        for b in d["bevindingen"]:
            a(f'<div class="finding" id="{b["id"]}" style="--c:var({ERNST_CSSVAR[b["ernst"]]})"><div class="head">'
              f'<span class="fid">{b["id"]}</span><span class="title">{_e(b["titel"])}</span>'
              f'<span class="badge b-{b["ernst"]}">{b["ernst"]}</span></div><dl>'
              f'<dt>Onderdeel</dt><dd>{_e(b["onderdeel"])} — test {b["test"]} ({_e(TESTS[b["test"]][1])})</dd>'
              f'<dt>Aangetroffen</dt><dd>{_e(_short_keys(b["aangetroffen"]))}</dd>'
              f'<dt>Risico</dt><dd>{_e(b["risico"])}</dd>'
              f'<dt>Oplossing</dt><dd>{_e(b["oplossing"])}'
              + (f'<pre>{_e(b["voorbeeld"])}</pre>' if b["voorbeeld"] else "") +
              f'</dd><dt>Referentie</dt><dd>{_e(b["referentie"])}</dd></dl></div>')
        a("</section>")

    a("<h2>Bijlage A. Opgevraagde DNS-gegevens</h2><p>Overzicht van de DNS-queries die tijdens de controle zijn "
      "uitgevoerd, als onderbouwing van de bevindingen. Niet-bestaande DKIM-selectors zijn weggelaten. De kolom "
      "DNSSEC geeft aan of het antwoord door de resolver als gevalideerd is gemarkeerd.</p>")
    for d in report["domeinen"]:
        a(f"<h4>{_e(d['domein'])}</h4><table><tr><th>Naam</th><th>Type</th><th>Antwoord</th><th>DNSSEC</th></tr>")
        for e in d["dns"]:
            a(f"<tr><td class='mono'>{_e(e['naam'])}</td><td>{e['type']}</td>"
              f"<td class='mono'>{_dns_answer(e, '<br>', _e)}</td><td>{'✔' if e['dnssec'] else ''}</td></tr>")
        a("</table>")
    a(f"<footer>Gegenereerd met mailcheck {m['versie']} op {_e(m['datum_weergave'])}.</footer></div></body></html>")
    return "".join(H)


def _csv_cell(v):
    """Voorkomt formule-injectie in Excel/LibreOffice (OWASP CSV injection)."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def render_csv(report, fh):
    w = csv.writer(fh, delimiter=";")
    raw_writerow = w.writerow

    class _W:
        @staticmethod
        def writerow(row):
            raw_writerow([_csv_cell(c) for c in row])
    w = _W
    w.writerow(["id", "domein", "ernst", "onderdeel", "test", "titel", "aangetroffen", "risico", "oplossing",
                "voorbeeld", "referentie"])
    for d in report["domeinen"]:
        for b in d["bevindingen"]:
            w.writerow([b["id"], d["domein"], b["ernst"], b["onderdeel"], b["test"], b["titel"],
                        _short_keys(b["aangetroffen"]), b["risico"], b["oplossing"], b["voorbeeld"] or "",
                        b["referentie"]])


# =====================================================================================
# CLI
# =====================================================================================

def normalize_domain(value):
    v = value.strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v).split("/")[0].split("?")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    v = v.split(":")[0].rstrip(".")
    if any(ord(c) > 127 for c in v):
        try:
            import idna  # IDNA2008/UTS-46, indien geïnstalleerd
            v = idna.encode(v, uts46=True, transitional=False).decode("ascii")
        except ImportError:
            # Pythons ingebouwde codec is IDNA2003 en zet o.a. 'ß' om naar 'ss' (een ander domein!).
            if any(c in v for c in "\u00df\u03c2\u200c\u200d"):
                raise ValueError(f"{value}: gebruik de punycode-vorm (xn--...) of installeer het pakket 'idna'")
            try:
                v = v.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError(f"ongeldig domein: {value}")
        except Exception:
            raise ValueError(f"ongeldig domein: {value}")
    if len(v) > 253 or not re.fullmatch(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+", v):
        raise ValueError(f"ongeldig domein: {value}")
    if _is_ip(v):
        raise ValueError(f"een IP-adres is geen domein: {value}")
    return v


MAANDEN = ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober",
           "november", "december"]
CHECK_ARGS = {"mx": "MX", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "mta-sts": "MTA-STS", "mtasts": "MTA-STS",
              "tls-rpt": "TLS-RPT", "tlsrpt": "TLS-RPT", "dane": "DANE", "dnssec": "DNSSEC", "bimi": "BIMI"}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: fout: {message}\n")


def main(argv=None, resolver=None, fetch=None, now=None):
    ap = _Parser(
        prog="mailcheck",
        description="Audit van SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, DANE, DNSSEC en BIMI, met klantrapportage.",
        epilog="Exitcodes: 0 = geen bevindingen, 1 = Laag/Midden, 2 = Hoog/Kritiek, 3 = gebruiksfout, "
               "4 = test onvolledig.")
    ap.add_argument("domains", nargs="*", metavar="domein", help="domein(en), e-mailadres(sen) of URL's")
    ap.add_argument("-f", "--file", metavar="BESTAND", help="bestand met één domein per regel (# = commentaar)")
    ap.add_argument("-s", "--selector", action="append", metavar="SEL",
                    help="DKIM-selector (meerdere keren mogelijk); zonder deze optie worden gangbare selectors geprobeerd")
    ap.add_argument("--only", action="append", choices=sorted(CHECK_ARGS), metavar="ONDERDEEL",
                    help="alleen deze onderdelen: " + ", ".join(sorted(set(CHECK_ARGS) - {"mtasts", "tlsrpt"})))
    ap.add_argument("--skip", action="append", choices=sorted(CHECK_ARGS), metavar="ONDERDEEL",
                    help="deze onderdelen overslaan")
    ap.add_argument("-r", "--resolver", action="append", metavar="IP[:POORT]",
                    help="DNS-resolver, bijv. 9.9.9.9 (valideert DNSSEC); meerdere keren mogelijk")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="DNS-timeout in seconden (standaard 5)")
    ap.add_argument("--passief", action="store_true", help="geen HTTPS-verzoek voor het MTA-STS-beleid")
    ap.add_argument("--spf-ip", action="append", metavar="IP", help="evalueer SPF ook voor dit IP-adres")
    rg = ap.add_argument_group("rapportage")
    rg.add_argument("--html", metavar="BESTAND", help="klantrapport als HTML (afdrukbaar naar PDF)")
    rg.add_argument("--md", metavar="BESTAND", help="klantrapport als Markdown")
    rg.add_argument("--csv", metavar="BESTAND", help="bevindingen als CSV (puntkomma-gescheiden)")
    rg.add_argument("--json", action="store_true", help="volledige resultaten als JSON naar stdout")
    rg.add_argument("--klant", default="", help="naam van de klant in het rapport")
    rg.add_argument("--uitvoerder", default="", help="naam van tester/organisatie in het rapport")
    rg.add_argument("--referentie", default="", help="project- of ordernummer in het rapport")
    ap.add_argument("-q", "--quiet", action="store_true", help="geen terminaluitvoer")
    ap.add_argument("--no-color", action="store_true", help="geen kleuren in de terminaluitvoer")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    raw = list(args.domains)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                raw += [ln.split("#")[0].strip() for ln in fh if ln.split("#")[0].strip()]
        except OSError as e:
            ap.error(f"kan {args.file} niet lezen: {e}")
    if not raw:
        ap.error("geef ten minste één domein op")
    try:
        domains = list(dict.fromkeys(normalize_domain(x) for x in raw))
    except ValueError as e:
        ap.error(str(e))
    for ip in args.spf_ip or []:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ap.error(f"ongeldig IP-adres voor --spf-ip: {ip}")
    selectors = []
    for s in args.selector or []:
        s = s.strip().lower()
        if not re.fullmatch(r"[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?", s):
            ap.error(f"ongeldige DKIM-selector: {s}")
        selectors.append(s)
    selectors = list(dict.fromkeys(selectors)) or list(DEFAULT_SELECTORS)

    only = [CHECK_ARGS[c] for c in (args.only or CHECK_ARGS)]
    skip = {CHECK_ARGS[c] for c in (args.skip or [])}
    only = [c for c in CHECKS if c in only and c not in skip]
    if not only:
        ap.error("er blijven geen onderdelen over om te testen")

    if resolver is None:
        try:
            resolver = RealResolver(args.resolver, args.timeout)
        except ValueError as e:
            ap.error(str(e))
    kwargs = {"selectors": selectors, "user_selectors": bool(args.selector), "http": not args.passief}
    if fetch is not None:
        kwargs["fetch"] = fetch

    nu = now or datetime.datetime.now().astimezone()
    runs, extra = [], []
    validates = False
    for domain in domains:
        start = len(resolver.log)
        results, ctx, fout = audit_domain(resolver, domain, only, kwargs)
        validates = validates or bool(ctx.get("resolver_validates"))
        for ip in args.spf_ip or []:
            ev = SPFEvaluator(resolver, ip, sender=f"postmaster@{domain}", helo=domain)
            uitkomst, _ = ev.check(domain)
            extra.append({"domein": domain, "ip": ip, "uitkomst": uitkomst, "term": ev.mechanism or "-",
                          "fout": ev.error})
        runs.append((domain, results, resolver.log[start:], fout))

    meta = {
        "klant": args.klant, "uitvoerder": args.uitvoerder, "referentie": args.referentie,
        "datum": nu.isoformat(timespec="seconds"),
        "datum_weergave": f"{nu.day} {MAANDEN[nu.month - 1]} {nu.year}, {nu:%H:%M} ({nu.tzname()})",
        "versie": __version__, "resolvers": resolver.nameservers(), "resolver_valideert": validates,
        "onderdelen": only, "http": not args.passief,
        "selectors": selectors, "selectors_opgegeven": bool(args.selector),
    }
    report = build_report(runs, meta)
    if extra:
        report["spf_ip_tests"] = extra

    try:
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html(report))
        if args.md:
            with open(args.md, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(report))
        if args.csv:
            with open(args.csv, "w", encoding="utf-8-sig", newline="") as fh:
                render_csv(report, fh)
    except OSError as e:
        sys.stderr.write(f"Kan rapport niet opslaan: {e}\n")
        return 3
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    elif not args.quiet:
        print_terminal(report, not args.no_color and sys.stdout.isatty(), extra)
        for f in (args.html, args.md, args.csv):
            if f:
                print(f"Rapport opgeslagen: {f}")

    if any(dm["onvolledig"] for dm in report["domeinen"]):
        return 4
    worst = max((ERNST_ORDE[dm["hoogste_ernst"]] for dm in report["domeinen"] if dm["hoogste_ernst"]), default=0)
    return 2 if worst >= ERNST_ORDE[HOOG] else 1 if worst >= ERNST_ORDE[LAAG] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)