export type Theme = "dark" | "light";

export interface ColorBendsProps {
  color: string;
  speed: number;
  frequency: number;
  noise: number;
  bandWidth: number;
  rotation: number;
  fadeTop: number;
  iterations: number;
  intensity: number;
}

export type NumericProp = Exclude<keyof ColorBendsProps, "color">;

export const DEFAULT_BENDS: ColorBendsProps = {
  color: "#F97316",
  speed: 0.4,
  frequency: 1.8,
  noise: 0.18,
  bandWidth: 0.22,
  rotation: 115,
  fadeTop: 0.7,
  iterations: 1,
  intensity: 1.4,
};

/** Range + display precision for each scrubbable prop in the code window. */
export const PROP_SPECS: Record<
  NumericProp,
  { min: number; max: number; step: number; decimals: number }
> = {
  speed: { min: 0, max: 2, step: 0.1, decimals: 1 },
  frequency: { min: 0.2, max: 5, step: 0.1, decimals: 1 },
  noise: { min: 0, max: 1, step: 0.01, decimals: 2 },
  bandWidth: { min: 0.05, max: 0.6, step: 0.01, decimals: 2 },
  rotation: { min: 0, max: 360, step: 1, decimals: 0 },
  fadeTop: { min: 0, max: 1, step: 0.01, decimals: 2 },
  iterations: { min: 1, max: 5, step: 1, decimals: 0 },
  intensity: { min: 0, max: 3, step: 0.1, decimals: 1 },
};

export const PROP_ORDER: (keyof ColorBendsProps)[] = [
  "color",
  "speed",
  "frequency",
  "noise",
  "bandWidth",
  "rotation",
  "fadeTop",
  "iterations",
  "intensity",
];

export const PRESETS: { name: string; props: ColorBendsProps }[] = [
  { name: "Ember", props: DEFAULT_BENDS },
  {
    name: "Solar Flare",
    props: { ...DEFAULT_BENDS, color: "#FACC15", speed: 0.6, frequency: 1.2, noise: 0.3, bandWidth: 0.3, rotation: 150, iterations: 2, intensity: 1.1 },
  },
  {
    name: "Crimson Silk",
    props: { ...DEFAULT_BENDS, color: "#EF4444", speed: 0.3, frequency: 2.6, noise: 0.1, bandWidth: 0.16, rotation: 100, iterations: 3, intensity: 1.2 },
  },
  {
    name: "Glacier",
    props: { ...DEFAULT_BENDS, color: "#38BDF8", speed: 0.5, frequency: 1.5, noise: 0.25, bandWidth: 0.26, rotation: 125, iterations: 2, intensity: 1.3 },
  },
];

export function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
  const n = parseInt(full, 16);
  if (Number.isNaN(n)) return [249, 115, 22];
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
