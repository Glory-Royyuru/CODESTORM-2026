"use client";

import { useEffect, useRef } from "react";
import { hexToRgb, type ColorBendsProps, type Theme } from "./colorBends";

interface Props {
  bends: ColorBendsProps;
  theme: Theme;
}

const GRID_SPACING = 28; // wide spacing keeps the field calm
const HOVER_RADIUS = 150;
const PUSH_DISTANCE = 6; // how far hovered dots "pop" away from the cursor
const BAND_SCALE = 4; // band renders at 1/4 res, then CSS-blurred for softness
const STRANDS = 14; // thin strands per band give the silky striations
const ACCENT: [number, number, number] = [251, 146, 60];

interface Ripple {
  x: number;
  y: number;
  start: number;
}

/**
 * Two stacked canvases:
 *  1. a low-res "ColorBends" ribbon, blurred by CSS, driven by the code-window props
 *  2. a full-res dot grid whose dots light up, grow and drift away near the cursor,
 *     then ease back. Clicking sends a ripple through the grid.
 */
export default function InteractiveBackground({ bends, theme }: Props) {
  const rootRef = useRef<HTMLDivElement>(null);
  const bandRef = useRef<HTMLCanvasElement>(null);
  const dotsRef = useRef<HTMLCanvasElement>(null);

  // Props live in refs so the animation loop never restarts on change.
  const bendsRef = useRef(bends);
  const themeRef = useRef(theme);
  useEffect(() => {
    bendsRef.current = bends;
  }, [bends]);
  useEffect(() => {
    themeRef.current = theme;
  }, [theme]);

  useEffect(() => {
    const root = rootRef.current!;
    const bandCanvas = bandRef.current!;
    const dotsCanvas = dotsRef.current!;
    const band = bandCanvas.getContext("2d")!;
    const dots = dotsCanvas.getContext("2d")!;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let width = 0;
    let height = 0;
    let dpr = 1;
    let gx = new Float32Array(0);
    let gy = new Float32Array(0);
    let glow = new Float32Array(0); // eased 0..1 highlight per dot
    const pointer = { x: -9999, y: -9999, active: false };
    const ripples: Ripple[] = [];
    let raf = 0;
    let visible = true;
    let bandTime = 0;
    let last = performance.now();

    const resize = () => {
      const rect = root.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);

      dotsCanvas.width = Math.round(width * dpr);
      dotsCanvas.height = Math.round(height * dpr);
      bandCanvas.width = Math.ceil(width / BAND_SCALE);
      bandCanvas.height = Math.ceil(height / BAND_SCALE);

      const cols = Math.ceil(width / GRID_SPACING) + 1;
      const rows = Math.ceil(height / GRID_SPACING) + 1;
      const ox = (width - (cols - 1) * GRID_SPACING) / 2;
      const oy = (height - (rows - 1) * GRID_SPACING) / 2;
      gx = new Float32Array(cols * rows);
      gy = new Float32Array(cols * rows);
      glow = new Float32Array(cols * rows);
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const i = r * cols + c;
          gx[i] = ox + c * GRID_SPACING;
          gy[i] = oy + r * GRID_SPACING;
        }
      }
    };

    const drawBand = () => {
      const p = bendsRef.current;
      const light = themeRef.current === "light";
      const w = bandCanvas.width;
      const h = bandCanvas.height;
      const [r, g, b] = hexToRgb(p.color);
      const t = bandTime;

      band.setTransform(1, 0, 0, 1, 0, 0);
      band.globalCompositeOperation = "source-over";
      band.clearRect(0, 0, w, h);
      band.globalCompositeOperation = light ? "source-over" : "lighter";

      const reach = Math.hypot(w, h) * 0.65;
      const amp = h * 0.12;
      const thickness = p.bandWidth * h * 2;
      const step = Math.max(2, w / 140);

      band.translate(w * 0.5, h * 0.7);
      band.rotate(((p.rotation - 127) * Math.PI) / 180);
      band.lineCap = "round";

      for (let it = 0; it < p.iterations; it++) {
        const lane = (it - (p.iterations - 1) / 2) * thickness * 0.85;
        const phase = it * 1.7;
        for (let s = 0; s < STRANDS; s++) {
          const u = (s / (STRANDS - 1)) * 2 - 1; // -1..1 across the ribbon
          const weight = Math.exp(-u * u * 2.2);
          const alpha = Math.min(1, weight * 0.12 * p.intensity * (light ? 0.9 : 1));
          const core = weight ** 3 * (light ? 0.1 : 0.3); // lighter, hotter centre
          const cr = Math.round(r + (255 - r) * core);
          const cg = Math.round(g + (225 - g) * core);
          const cb = Math.round(b + (190 - b) * core);

          band.strokeStyle = `rgba(${cr},${cg},${cb},${alpha})`;
          band.lineWidth = Math.max(1, (thickness / STRANDS) * 2.2);
          band.beginPath();
          for (let x = -reach; x <= reach; x += step) {
            const k = x / reach;
            const y =
              lane +
              amp * Math.sin(k * p.frequency * Math.PI + t * 0.6 + phase) +
              p.noise * amp * 1.6 * Math.sin(k * p.frequency * 2.3 * Math.PI - t * 0.9 + phase) +
              u * (thickness / 2) * (0.75 + 0.25 * Math.sin(k * 3 + t * 0.4 + phase)) +
              Math.sin(k * 9 + s * 0.7 + t) * thickness * 0.04;
            if (x === -reach) band.moveTo(x, y);
            else band.lineTo(x, y);
          }
          band.stroke();
        }
      }

      // fadeTop: dissolve the ribbon into the background toward the top edge
      band.setTransform(1, 0, 0, 1, 0, 0);
      band.globalCompositeOperation = "destination-in";
      const fade = band.createLinearGradient(0, 0, 0, h);
      fade.addColorStop(0, "rgba(0,0,0,0)");
      fade.addColorStop(Math.min(0.95, Math.max(0.01, p.fadeTop * 0.62)), "rgba(0,0,0,1)");
      fade.addColorStop(1, "rgba(0,0,0,1)");
      band.fillStyle = fade;
      band.fillRect(0, 0, w, h);
      band.globalCompositeOperation = "source-over";
    };

    const drawDots = (now: number) => {
      const light = themeRef.current === "light";
      const base = light ? [28, 25, 23] : [255, 255, 255];
      const baseAlpha = light ? 0.16 : 0.13;

      dots.setTransform(dpr, 0, 0, dpr, 0, 0);
      dots.clearRect(0, 0, width, height);

      // Drop finished ripples
      for (let i = ripples.length - 1; i >= 0; i--) {
        if (now - ripples[i].start > 1400) ripples.splice(i, 1);
      }

      // Idle dots are batched into a single path/fill.
      dots.fillStyle = `rgba(${base[0]},${base[1]},${base[2]},${baseAlpha})`;
      dots.beginPath();
      const hot: number[] = [];

      for (let i = 0; i < gx.length; i++) {
        const x = gx[i];
        const y = gy[i];
        let target = 0;

        if (pointer.active) {
          const dx = x - pointer.x;
          const dy = y - pointer.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < HOVER_RADIUS * HOVER_RADIUS) {
            const f = 1 - Math.sqrt(d2) / HOVER_RADIUS;
            target = f * f * (3 - 2 * f); // smoothstep falloff
          }
        }

        for (const rp of ripples) {
          const age = (now - rp.start) / 1400;
          const radius = age * 620;
          const d = Math.hypot(x - rp.x, y - rp.y);
          const ring = 1 - Math.abs(d - radius) / 36;
          if (ring > 0) target = Math.max(target, ring * (1 - age) * 0.9);
        }

        // Fast attack, slow release → dots "pop" then gently fade back.
        const cur = glow[i];
        glow[i] = cur + (target - cur) * (target > cur ? 0.28 : 0.055);

        if (glow[i] < 0.01) dots.rect(x - 0.9, y - 0.9, 1.8, 1.8);
        else hot.push(i);
      }
      dots.fill();

      for (const i of hot) {
        const k = glow[i];
        let x = gx[i];
        let y = gy[i];
        if (pointer.active) {
          const dx = x - pointer.x;
          const dy = y - pointer.y;
          const d = Math.hypot(dx, dy) || 1;
          x += (dx / d) * k * PUSH_DISTANCE;
          y += (dy / d) * k * PUSH_DISTANCE;
        }
        const rCol = Math.round(base[0] + (ACCENT[0] - base[0]) * k);
        const gCol = Math.round(base[1] + (ACCENT[1] - base[1]) * k);
        const bCol = Math.round(base[2] + (ACCENT[2] - base[2]) * k);
        const size = 1 + k * 2.1;

        if (k > 0.3) {
          dots.fillStyle = `rgba(${ACCENT[0]},${ACCENT[1]},${ACCENT[2]},${(k - 0.3) * 0.18})`;
          dots.beginPath();
          dots.arc(x, y, size * 3.2, 0, Math.PI * 2);
          dots.fill();
        }
        dots.fillStyle = `rgba(${rCol},${gCol},${bCol},${baseAlpha + k * (0.95 - baseAlpha)})`;
        dots.beginPath();
        dots.arc(x, y, size, 0, Math.PI * 2);
        dots.fill();
      }
    };

    const frame = (now: number) => {
      const dt = Math.min(64, now - last);
      last = now;
      if (!reduceMotion) bandTime += (dt / 1000) * bendsRef.current.speed * 2.2;
      drawBand();
      drawDots(now);
      raf = visible ? requestAnimationFrame(frame) : 0;
    };

    const toLocal = (e: PointerEvent) => {
      const rect = root.getBoundingClientRect();
      return { x: e.clientX - rect.left, y: e.clientY - rect.top };
    };
    const onMove = (e: PointerEvent) => {
      const { x, y } = toLocal(e);
      pointer.x = x;
      pointer.y = y;
      pointer.active = y >= 0 && y <= height;
    };
    const onDown = (e: PointerEvent) => {
      const { x, y } = toLocal(e);
      if (y >= 0 && y <= height && !reduceMotion) ripples.push({ x, y, start: performance.now() });
    };
    const onLeave = () => {
      pointer.active = false;
    };
    const onOut = (e: PointerEvent) => {
      if (!e.relatedTarget) onLeave();
    };

    const ro = new ResizeObserver(resize);
    ro.observe(root);
    resize();

    // Pause the loop entirely while the hero is scrolled out of view.
    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible && !raf) {
        last = performance.now();
        raf = requestAnimationFrame(frame);
      }
    });
    io.observe(root);

    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerdown", onDown, { passive: true });
    window.addEventListener("pointerout", onOut);
    window.addEventListener("blur", onLeave);
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointerout", onOut);
      window.removeEventListener("blur", onLeave);
    };
  }, []);

  return (
    <div ref={rootRef} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      {/* Ambient warm mesh glow */}
      <div
        className="absolute inset-0 transition-opacity duration-500"
        style={{
          background:
            theme === "dark"
              ? "radial-gradient(60% 50% at 20% 85%, rgba(249,115,22,0.16), transparent 70%), radial-gradient(45% 40% at 85% 70%, rgba(234,88,12,0.12), transparent 70%), radial-gradient(70% 45% at 50% 0%, rgba(120,53,15,0.18), transparent 70%)"
              : "radial-gradient(60% 50% at 20% 85%, rgba(249,115,22,0.12), transparent 70%), radial-gradient(45% 40% at 85% 70%, rgba(251,146,60,0.1), transparent 70%)",
        }}
      />
      <canvas
        ref={bandRef}
        className="absolute inset-0 h-full w-full"
        style={{ filter: "blur(10px)", opacity: theme === "dark" ? 0.95 : 0.7 }}
      />
      <canvas ref={dotsRef} className="absolute inset-0 h-full w-full" />
      <div className="grain absolute inset-0" />
      {/* Vignette keeps edges and the nav area deep */}
      <div
        className="absolute inset-0"
        style={{
          background:
            theme === "dark"
              ? "radial-gradient(120% 90% at 50% 55%, transparent 55%, rgba(5,4,3,0.75) 100%), linear-gradient(to bottom, rgba(11,11,14,0.55), transparent 22%)"
              : "radial-gradient(120% 90% at 50% 55%, transparent 60%, rgba(251,247,243,0.8) 100%)",
        }}
      />
    </div>
  );
}
