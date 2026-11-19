# JevIDS brand notes

Read from the Figma file "JEV-IDS" (pages Identidade, Logo, Website) on 2026-09-21, in view-only mode. Hex values marked "read" are
written in the design; values marked "estimated" were judged by eye from the rendered canvas and should be confirmed in Figma.

## Two directions in the file, one adopted

- **Terminal** (page Website, sections D1 · Terminal, T0 · Fundamentos, T1 · Sistema de logo, T2 · Gráficos e figuras,
  T3 · Aplicações): **the adopted identity**, decided on 2026-09-21 for the README, the website and the organization avatar. See
  "Terminal" below.
- **Pine** (page Identidade, sections 00C Brandkit, 04C, 05C, 06C, 99 Exportação): the earlier direction, still the source of the
  organization avatar that was uploaded first. Kept below for reference.

## Terminal (page Website)

### Palette (D1 · Terminal, all read)

| Token    | Hex       | Use in the design    |
| -------- | --------- | -------------------- |
| phosphor | `#3DFF8A` | verdict, cursor      |
| bg       | `#0B0F0E` | background           |
| dim      | `#1E6B3F` | borders, prompt      |
| grey     | `#8E9A93` | comments, muted text |
| paper    | `#E9F2EC` | text                 |

### Semantic tokens (T0 · Fundamentos)

| Token    | Dark mode                     | Light mode                               |
| -------- | ----------------------------- | ---------------------------------------- |
| bg       | `#0B0F0E` (read)              | `#E9F2EC` (estimated, same as paper)     |
| surface  | `#121917` (read, badge label) | `#FFFFFF` (estimated)                    |
| text     | `#E9F2EC` (read)              | `#0B0F0E` (read)                         |
| muted    | `#8E9A93` (read)              | `#5F6B65` (estimated)                    |
| line     | `#1E6B3F` (read)              | `#B7D3C2` (estimated)                    |
| phosphor | `#3DFF8A` (read)              | `#0B6B3A` (read: "fósforo vira #0B6B3A") |

Figure colors (T2): jev `#3DFF8A` (phosphor, the subject), llm `#FFB454` (amber, the expensive baseline), rf `#6EC1FF` (sky, the
classical baseline). On white paper: jev `#0B6B3A`, llm `#B36B00`, rf `#1F6FB2`, text `#0B0F0E`, grid `#D5DED9`. Rules: dark or light
background, one color per detector, thin grid, no shadow, no gradient, title in mono, legend on the right, few axis ticks. Confusion
matrix: one color, opacity as intensity. Tables in mono, digits align by themselves, color marker left of the name, no zebra, thin rules.

### Typography (T0, all read)

| Role    | Font                     |
| ------- | ------------------------ |
| Display | IBM Plex Mono Bold 48    |
| H1      | IBM Plex Mono Bold 32    |
| H2      | IBM Plex Mono Bold 20    |
| Body    | Inter Regular 16         |
| Code    | IBM Plex Mono Regular 14 |
| Caption | IBM Plex Mono Medium 12  |

IBM Plex Mono for display, code and labels; Inter for running text.

### Logo system (T1)

- Square mark: rounded square, `bg` fill with a `dim` 2 px border; two lines of IBM Plex Mono Bold, `jev` in paper over `ids` in
  phosphor, followed by a phosphor cursor block ▮ on the second line.
- Horizontal lockup: `> jev_ids▮` in a rounded box with a `dim` border; `>` in dim, `jev` in paper, `_ids▮` in phosphor.
- Icon: `>▮` on a bg square (prompt and cursor). Only the icon survives at 16 px (favicon); never the square with text.
- Light versions: the same on `#E9F2EC` with text in `#0B0F0E` and phosphor replaced by `#0B6B3A`. Mono black versions exist.
- Reductions: mark 64 · 32 · 16; square 128 · 64 · 32.

### Voice (D1)

"um fluxo. uma resposta." Tone chips: determinístico, sem ruído, uma linha por fluxo, lê como log. Subtitle in the design: "detecção
de intrusão com um System One Model, comparada a um LLM e a uma Random Forest." The product is a terminal: the brand appears in the run
header and the verdict inherits phosphor; categories in lowercase, confidence always beside them.

### Applications (T3)

1. README banner, 1280×320 on GitHub dark: horizontal dark lockup on the left, tagline in Inter ("Intrusion detection with a System One
   Model, benchmarked against an LLM and a Random Forest."), one command line as signature (`$ uv run python -m jev_ids run --detector
jev --k 0,1,2,4`), a `line`-colored border around the lockup that also separates the banner from GitHub's background; on the right a
   `surface` panel with a bar chart in phosphor and dim greens.
2. Badges, shields.io style: label background `#121917`, status in dark phosphor `#0B6B3A`; never light phosphor as a badge background
   (white text fails contrast). Shown: build passing, coverage 94%, python 3.13+, detector jev, license MIT.
3. Slide cover 16:9: title in Plex Mono Bold, large, left-aligned, a phosphor rule on the left edge, minimal mark in the corner, a cursor
   block closes the title.
4. Social card 1200×630 (scale 0.6): square mark left, "JEV IDS" and tagline "um fluxo. uma resposta." right, repository URL below.
5. CLI output: run header (`jev_ids 0.2.0 · detector=jev · split=paper · k=4 · 2 750 flows`), table `row_id truth verdict p ms`, attack
   rows in phosphor, an uncertain row in amber, a summary line (`F1 0.88 · novel 0.61 · 180 ms/flow · $0.04 per 1k`).
6. Browser tab and favicon 16 px: the icon only.
7. Poster header on light paper: the mark inverts to light mode, a dark-phosphor rule separates header and body.

The design's placeholder texts ("Amanda Dias · UNIPAMPA", "github.com/amandadiasdev/somids", version 0.2.0, the figure numbers) are
mock content, not project facts.

## Pine (page Identidade, the earlier direction)

The GitHub organization avatar is the "Dark · fundo pine" version of this mark, so Pine is the identity in use; the Logo page holds
the "Light" version on white (Instagram post).

### Palette (00C Brandkit · Pine, all read)

| Token   | Hex       | Name in the design | Use in the design                     |
| ------- | --------- | ------------------ | ------------------------------------- |
| Celadon | `#B3EFB2` | celadon            | highlight over pine, shapes, verdicts |
| Pine    | `#31493C` | pine teal          | text and deep backgrounds             |
| Ink     | `#001A23` | ink black          | dark mode, maximum contrast           |
| Sage    | `#7A9E7E` | muted teal         | dividers, secondary flow              |
| Paper   | `#E8F1F2` | alice blue         | default background                    |

### Typography (00C, all read)

| Role    | Font               | Sample in the design                                                                      |
| ------- | ------------------ | ----------------------------------------------------------------------------------------- |
| Display | Space Grotesk Bold | "Um fluxo. Uma resposta."                                                                 |
| Text    | Inter Regular      | "Detecção de intrusão com um System One Model, comparada a um LLM e a uma Random Forest." |
| Code    | JetBrains Mono     | `uv run python -m somids run --detector jev --k 0,1,2,4`                                  |

Section 06C shows the same mark set in Geist Black as the alternative display face.

### Voice (00C)

Tone chips: rápido, assertivo, sem conversa, um veredito por fluxo, harness, não chat.

### The mark (04C Tipográfico refinado)

A rounded square holding two stacked words in the display face, "JEV" over "IDS", left-aligned, with a small three-bar glyph (a tiny
bar chart, bars of three heights) sitting at the baseline right of "IDS". Four versions:

| Version                 | Square                  | JEV   | IDS     | Bars          |
| ----------------------- | ----------------------- | ----- | ------- | ------------- |
| Light · borda sage      | Paper fill, Sage border | Ink   | Pine    | Sage and Pine |
| Dark · fundo pine       | Pine fill, no border    | Paper | Celadon | Celadon, Sage |
| Celadon · fundo celadon | Celadon fill            | Ink   | Ink     | Pine, Sage    |
| Mono · uma cor          | Paper fill, Pine border | Pine  | Pine    | Pine          |

Each version also exists at favicon size (about 40 px) with the same layout.

### Variations (05C Variações)

- V1: the "I" of IDS becomes the chosen drawer, in Ink; two colors, no extra glyph.
- V2: light JEV, heavy IDS ("the model is the base, the detection is the shout").
- V3: large IDS, JEV as a letter-spaced label above, the drawer beside the label (Pine square).
- V4: centered circular seal, Django style; good for an organization avatar.
- V5: hexagon, Node.js style, alludes to a network node (Celadon).
- V6: one line only, for the top of the README and slide headers: "JEV IDS" in a rounded pill on Paper with a Sage border, "JEV" in
  Ink, "IDS" in Sage.

### Export (99 Exportação)

"Org / Avatar · 512": the Dark · fundo pine square at 592 × 592, the file behind the GitHub organization avatar.
