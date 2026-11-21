#!/usr/bin/env python3
# gen_icon.py — lightningmail app icon master (512 grid, only robust SVG primitives)
S = 512
W = []
def p(x): W.append(x)

# Bolt path (24x36 units, tip at the bottom)
BOLT = "M13.2,0 L0,18.5 L8.2,18.5 L5.1,36 L20,12.4 L11.3,12.4 Z"
def bolt(cx, cy, scale, fill):
    w, h = 20*scale, 36*scale
    return f'<path transform="translate({cx-w/2:.1f} {cy-h/2:.1f}) scale({scale})" d="{BOLT}" fill="{fill}"/>'

p(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}">')
p('<defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">'
  '<stop offset="0" stop-color="#1b3049"/><stop offset="1" stop-color="#0c1a2b"/></linearGradient>'
  '<linearGradient id="paper" x1="0" y1="0" x2="0" y2="1">'
  '<stop offset="0" stop-color="#f8f6ee"/><stop offset="1" stop-color="#ece6d3"/></linearGradient>'
  '<clipPath id="envclip"><rect x="86" y="142" width="340" height="244" rx="18"/></clipPath></defs>')
p(f'<rect width="{S}" height="{S}" rx="118" fill="url(#bg)"/>')

# --- Envelope with priority stripe tape ---
p('<g clip-path="url(#envclip)">')
p('<rect x="86" y="142" width="340" height="244" fill="#ffffff"/>')
x = 60
while x < 470:
    p(f'<path d="M{x},142 L{x+9},142 L{x+9+244},386 L{x+244},386 Z" fill="#f4b71a"/>')
    p(f'<path d="M{x+15},142 L{x+24},142 L{x+24+244},386 L{x+15+244},386 Z" fill="#2456a6"/>')
    x += 30
p('</g>')
p('<rect x="100" y="156" width="312" height="216" rx="9" fill="url(#paper)"/>')

# Flap (closed, V-fold centered)
p('<path d="M100,165 L256,278 L412,165 L412,156 L100,156 Z" fill="#e6dfc9"/>')
p('<path d="M100,165 L256,278 L412,165" fill="none" stroke="#c9c0a6" stroke-width="3.5"/>')
# lower fold lines = envelope look
p('<path d="M100,364 L226,276 M412,364 L286,276" fill="none" stroke="#d8d0b8" stroke-width="3"/>')

# --- Postage stamp: bolt, beaded border, on the flap at the top right ---
cx, cy = 356, 208
p(f'<g transform="rotate(-4 {cx} {cy})"><rect x="{cx-46}" y="{cy-52}" width="92" height="104" rx="4" fill="#ffffff"/>')
for i in range(9):
    ex = cx - 46 + i * 11.5
    p(f'<circle cx="{ex:.1f}" cy="{cy-52}" r="4.5" fill="#ffffff"/><circle cx="{ex:.1f}" cy="{cy+52}" r="4.5" fill="#ffffff"/>')
for j in range(8):
    ey = cy - 52 + (j + 1) * 13
    p(f'<circle cx="{cx-46}" cy="{ey:.1f}" r="4.5" fill="#ffffff"/><circle cx="{cx+46}" cy="{ey:.1f}" r="4.5" fill="#ffffff"/>')
p(f'<rect x="{cx-37}" y="{cy-43}" width="74" height="86" rx="3" fill="#122338"/>')
p(bolt(cx, cy, 1.55, "#f4b71a"))
p('</g>')

# --- Seal lock on the flap closure: encryption is mandatory ---
p('<path d="M240,262 v-10 a16,16 0 0 1 32,0 v10" fill="none" stroke="#d99e0c" stroke-width="9"/>')
p('<rect x="230" y="256" width="52" height="44" rx="10" fill="#f4b71a"/>')
p(bolt(256, 278, 0.62, "#122338"))

p('</svg>')
open("/root/lm-work/icon/appicon.svg", "w").write("\n".join(W))
print("written")
