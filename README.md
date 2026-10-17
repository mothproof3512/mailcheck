# mailcheck

Passieve audit van e-mailbeveiliging met klantrapportage in HTML, Markdown, JSON en CSV.
Controleert **MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, DNSSEC en BIMI**.

De controle is volledig **passief**: er worden uitsluitend openbare DNS-records opgevraagd en
het openbare MTA-STS-beleid via HTTPS opgehaald. Er wordt geen e-mail verstuurd en geen
verbinding met de mailservers gemaakt. Daardoor geschikt voor een onpartijdige review van een
omgeving, zonder die te belasten of te wijzigen.

## Kenmerken

- Eigen SPF-evaluator volgens RFC 7208 (`check_host`), inclusief include-/redirect-ketens,
  lookup- en void-limieten en macro-expansie.
- DKIM-sleutelsterkte en -ontleding (RSA-bitlengte uit de DER-sleutel, Ed25519, SHA-1, testmodus).
- DMARC-beleid, organisatiedomein (DNS tree walk, RFC 9989), rapportage- en alignment-controles.
- MTA-STS (record + beleid via HTTPS), TLS-RPT, DANE (TLSA + DNSSEC-validatie), DNSSEC en BIMI.
- Rapportage als HTML (afdrukbaar naar PDF), Markdown, JSON en CSV, met een actieplan op prioriteit.

## Installatie

Vereist Python 3.8 of nieuwer.

```bash
pip install -r requirements.txt     # installeert dnspython
# optioneel: pip install idna        (voor internationale/IDN-domeinen)
```

## Gebruik

```bash
python3 mailcheck.py voorbeeld.nl -r 9.9.9.9 \
    --klant "Klant B.V." --uitvoerder "Naam, Organisatie" --referentie "PRJ-XXXX-XXX" \
    --html rapport.html --md rapport.md --csv bevindingen.csv
```

Veelgebruikte opties:

- `-r 9.9.9.9` — gebruik een DNSSEC-validerende resolver (Quad9). Nodig voor een betrouwbaar
  DANE- en DNSSEC-oordeel: de AD-vlag bepaalt of een mislukte TLSA-opvraag "zone niet
  ondertekend" (definitief) of "niet vast te stellen" betekent.
- `-s selector1 -s k1` — geef DKIM-selectors expliciet mee als je ze kent. Zonder `-s` wordt een
  lijst van 66 gangbare selectors geprobeerd.
- `--passief` — sla de HTTPS-fetch van het MTA-STS-beleid over (alleen de DNS-laag).
- `--only` / `--skip` — beperk de onderdelen; `--spf-ip <IP>` — test SPF ook voor een specifiek IP.
- `-f domeinen.txt` — meerdere domeinen uit een bestand; `--json` — volledige resultaten naar stdout.

Exitcodes: `0` geen bevindingen, `1` Laag/Midden, `2` Hoog/Kritiek, `3` gebruiksfout,
`4` test (deels) niet uitvoerbaar door DNS-fouten.

## Beperkingen

Dit zijn inherente grenzen van passief testen, geen fouten:

- DKIM-selectors zijn niet via DNS op te sommen; zonder `-s` wordt een lijst gangbare selectors
  geprobeerd (via RFC 8020 wordt wel vastgesteld óf er sleutels onder `_domainkey` bestaan).
- STARTTLS-ondersteuning en de certificaten van de mailservers zelf worden niet getest; daarvoor
  is een echte SMTP-verbinding nodig.
- Of verstuurde e-mail SPF/DKIM/DMARC in de praktijk doorstaat (alignment), blijkt alleen uit
  DMARC-rapporten of een testbericht.
- De uitkomst is een momentopname van de DNS-configuratie en hangt af van de gebruikte resolver.

## Wijzigingen in 3.0.1

- **DANE bij een niet-DNSSEC-mailprovider.** Een TLSA-fout (SERVFAIL) op een mailserver waarvan de
  zone niet met DNSSEC is ondertekend, wordt nu als definitief "DANE niet mogelijk" (Laag)
  gerapporteerd in plaats van "niet vast te stellen". Domeinen bij bijvoorbeeld Microsoft 365
  krijgen daardoor niet langer onterecht het oordeel "onvolledig getest" (exitcode 4). Vereist een
  validerende resolver (`-r 9.9.9.9`).
- **Markdown-escaping.** `_md()` escapet nu eerst de backslash en daarna de overige speciale tekens
  (inclusief `|`), zodat DNS-data met een `|` geen tabel in het Markdown-rapport meer kan breken.

## Tests

De tests draaien zonder externe afhankelijkheden of netwerk (DNS en HTTPS worden nagebootst):

```bash
python3 -m unittest discover -p 'test_*.py'    # alles (62 tests)
python3 -m pytest                               # idem, als pytest aanwezig is
```

Dekking: de SPF-evaluator (check_host, include-ketens, lookup-limieten, temperror,
macro-expansie volgens RFC 7208 §7.4), DKIM-sleutelsterkte en -ontleding, DMARC-beleid en
organisatiedomein, MTA-STS, TLS-RPT, DANE (met regressietests voor de niet-DNSSEC-casus),
DNSSEC, de rapportopbouw, de HTML/Markdown/CSV-escaping, domeinnormalisatie en de
CLI-exitcodes en `--spf-ip`-flow.

### Officiële RFC 7208-testsuite (optioneel)

`test_rfc7208.py` draait de officiële openspf/pyspf-suite tegen de SPF-evaluator. Die data zit
niet in deze repo. Zet het bestand ernaast of wijs ernaar met een omgevingsvariabele:

```bash
# haal rfc7208-tests.yml op bij openspf/pyspf, dan:
export MAILCHECK_RFC7208=/pad/naar/rfc7208-tests.yml
pip install pyyaml
python3 -m unittest test_rfc7208 -v
```

Zonder het bestand of zonder PyYAML wordt die suite overgeslagen (skip), niet gefaald.

## Licentie

Dit project valt onder de MIT-licentie — zie het LICENSE-bestand in deze repository.

## Verantwoord gebruik

Draai dit alleen tegen domeinen die je mag controleren. De tool is passief en belast de doel-DNS
nauwelijks, maar blijf binnen de scope van je opdracht of toestemming.
