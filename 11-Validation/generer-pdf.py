#!/usr/bin/env python3
"""Markdown -> HTML (pandoc) -> PDF (Chrome headless, local) puis comptage de pages (PyMuPDF). Aucune donnée n'est envoyée à un service tiers.
Usage : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 11-Validation/generer-pdf.py <chemin relatif .md> [<chemin> ...]
Écrit le .pdf à côté du .md et ajoute une ligne à 11-Validation/Pages-PDF.csv (pages, taille, hash)."""
import csv, hashlib, os, subprocess, sys, tempfile, fitz
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CSS = """@page { size: A4; margin: 14mm 14mm 15mm 14mm }
body { font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif; font-size: 10pt; line-height: 1.36; color: #111 }
h1 { font-size: 17pt; margin: 0 0 6px; color: #0b3a66 } h2 { font-size: 12.2pt; margin: 12px 0 4px; color: #0b3a66; border-bottom: 1px solid #c9d6e2; padding-bottom: 2px }
h3 { font-size: 10.6pt; margin: 9px 0 3px } table { border-collapse: collapse; width: 100%; margin: 5px 0 8px; font-size: 8.3pt; page-break-inside: auto }
th, td { border: 1px solid #b8c4d0; padding: 2px 4px; vertical-align: top; word-break: break-word } th { background: #e8eff6 } tr { page-break-inside: avoid }
code { font-size: 8.4pt; background: #f2f4f6; padding: 0 2px } pre { font-size: 8pt; background: #f2f4f6; padding: 5px; white-space: pre-wrap }
blockquote { margin: 4px 0; padding: 2px 8px; border-left: 3px solid #0b3a66; background: #f3f7fb } img { max-width: 100% } p { margin: 3px 0 5px }
.bandeau { background: #fff3cd; border: 1px solid #e0c36a; padding: 3px 6px; font-size: 8.5pt; margin-bottom: 6px }"""
rows = []
FORCE = "--force" in sys.argv
for rel in [x for x in sys.argv[1:] if x != "--force"]:
    md = os.path.join(B, rel); pdf = md[:-3] + ".pdf"
    if os.path.exists(pdf) and os.path.getmtime(pdf) >= os.path.getmtime(md) and not FORCE:      # PDF à jour : non refait (le rendu n'est pas déterministe, le hash resterait stable sinon)
        d = fitz.open(pdf); h = hashlib.sha256(open(pdf, "rb").read()).hexdigest(); rows.append([rel[:-3] + ".pdf", len(d), os.path.getsize(pdf), h]); print(f"{rel[:-3]}.pdf : à jour, non refait ({len(d)} pages)"); continue
    with tempfile.TemporaryDirectory() as t:
        css = os.path.join(t, "s.css"); open(css, "w").write(CSS); html = os.path.join(t, "d.html")
        subprocess.run(["pandoc", md, "-f", "gfm", "-t", "html5", "-s", "--metadata", f"title={os.path.basename(md)[:-3]}", "-c", css, "--resource-path", os.path.dirname(md), "-o", html, "-V", "pagetitle=doc", "--embed-resources"], check=True,
                       capture_output=True)
        s = open(html, encoding="utf-8").read()
        import re
        s = re.sub(r'<header id="title-block-header">.*?</header>', "", s, flags=re.S)
        open(html, "w", encoding="utf-8").write(s)
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf}", "file://" + html], check=True, capture_output=True, timeout=120)
    d = fitz.open(pdf); n = len(d)
    h = hashlib.sha256(open(pdf, "rb").read()).hexdigest()
    rows.append([rel[:-3] + ".pdf", n, os.path.getsize(pdf), h])
    print(f"{rel[:-3]}.pdf : {n} pages, {os.path.getsize(pdf)} octets")
p = os.path.join(B, "11-Validation", "Pages-PDF.csv")
old = {r[0]: r for r in csv.reader(open(p, encoding="utf-8"))} if os.path.exists(p) else {}
for r in rows: old[r[0]] = r
old.pop("fichier", None)
with open(p, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["fichier", "pages", "octets", "sha256"]); w.writerows(old.values())
