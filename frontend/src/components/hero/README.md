# `hero/` — the React Bits look

This folder holds the pieces recreated from the React Bits landing page that you supplied.

| File | What it does |
| --- | --- |
| `InteractiveBackground.tsx` | The full-screen animated background, fixed behind all content (`fixed inset-0 -z-10`, ignores clicks). |
| `colorBends.ts` | Settings type for the ribbon (`color`, `speed`, `frequency`, `noise`, `bandWidth`, `rotation`, `fadeTop`, `iterations`, `intensity`), `DEFAULT_BENDS` (orange `#F97316`) and `hexToRgb`. The prop specs and presets in it are left over from the original ColorBends playground and aren't used by the SATG screens. |
| `icons.tsx` | `LogoIcon` (atom-style logo) and `GitHubIcon` (Lucide v1 removed brand icons, so it's an inline SVG). |

## How `InteractiveBackground` works

It stacks several layers:

1. **Warm glow** — CSS radial gradients (orange patches).
2. **The ribbon** (canvas 1) — drawn at ¼ resolution as 14 thin wavy lines, then blurred with CSS. The low resolution + blur is what makes it look like soft silk and keeps it cheap. The ribbon settings drive its shape; `fadeTop` fades it out toward the top of the screen.
3. **The dot grid** (canvas 2, full resolution) — dots every 28 px. Each dot has a "glow" value:
   - dots within 150 px of the cursor get a target glow (smoothstep falloff),
   - the glow rises fast and fades slowly, so dots "pop" and then ease back,
   - glowing dots turn orange, grow, get a halo, and are pushed ~6 px away from the cursor,
   - a click starts a ring-shaped ripple that travels outward through the grid.
4. **Grain** — an SVG noise texture (`.grain` in `globals.css`).
5. **Vignette** — darkens the edges.

Performance guards: animation pauses when the background is off screen, the pixel ratio is capped at 2, idle dots are drawn in one batch, and with "reduce motion" enabled the ribbon stops moving (the dots still react).

To change the look, edit the constants at the top of the file (`GRID_SPACING`, `HOVER_RADIUS`, `PUSH_DISTANCE`, `BAND_SCALE`, `STRANDS`, `ACCENT`) or pass different settings from `AppShell.tsx`.
