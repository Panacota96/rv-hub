#!/usr/bin/env python3
"""Writes the synthetic sample evidence (no real personal data) into DIR. Deterministic for a given Pillow version.

Usage: python3 tests/samples/make_evidence.py examples/sample/evidence
Needs Pillow for the JPEG and PNG. Every name, number and message is invented.
"""

import sys
from pathlib import Path


def tiny_pdf() -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        None,  # content stream, below
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Title (Contrato de prueba) /Author (Demo Rakvor) /Producer (rv-hub sample generator) "
        b"/CreationDate (D:20260101120000Z) >>",
    ]
    text = b"BT /F1 14 Tf 24 90 Td (Contrato de prueba - datos ficticios) Tj ET"
    objs[3] = b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream"
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offsets:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def images(d: Path) -> None:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (96, 64), (40, 70, 110))
    draw = ImageDraw.Draw(img)
    draw.rectangle((10, 10, 50, 40), fill=(200, 160, 60))
    draw.ellipse((55, 20, 85, 50), fill=(180, 40, 40))
    img.save(d / "foto-1.jpg", "JPEG", quality=85)
    png = Image.new("RGB", (64, 48), (240, 240, 240))
    ImageDraw.Draw(png).line((0, 0, 63, 47), fill=(20, 20, 20), width=3)
    png.save(d / "captura.png", "PNG")


WHATSAPP = """\
12/03/2026, 09:14 - Los mensajes y las llamadas están cifrados de extremo a extremo.
12/03/2026, 09:15 - Laura Demo: Hola, ¿recibiste el contrato?
12/03/2026, 09:17 - Pablo Ficticio: Sí, lo reviso hoy y te confirmo.
12/03/2026, 18:02 - Laura Demo: Perfecto, gracias.
13/03/2026, 08:45 - Pablo Ficticio: Firmado. Te lo envío por correo.
"""

NOTES = """Notas del examinador (ficticias)
Caso de muestra SAMPLE-1. Todos los nombres y datos son inventados.
"""


def main() -> int:
    d = Path(sys.argv[1])
    d.mkdir(parents=True, exist_ok=True)
    (d / "contrato.pdf").write_bytes(tiny_pdf())
    images(d)
    (d / "whatsapp-chat.txt").write_bytes(WHATSAPP.encode("utf-8"))
    (d / "notas.txt").write_bytes(NOTES.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
