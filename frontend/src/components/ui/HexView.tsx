import { cx } from "./primitives";

const ROW_BYTES = 16;

/** Classic offset · hex · ASCII dump of a hex string. Non-printable bytes render as "·". */
export default function HexView({ hex, totalBytes, className }: { hex: string; totalBytes?: number; className?: string }) {
  const bytes = (hex.match(/[0-9a-f]{2}/gi) ?? []).map((h) => parseInt(h, 16));
  const rows: number[][] = [];
  for (let i = 0; i < bytes.length; i += ROW_BYTES) rows.push(bytes.slice(i, i + ROW_BYTES));
  const truncated = totalBytes !== undefined && totalBytes > bytes.length;

  return (
    <div className={cx("scrollbar-thin overflow-x-auto rounded-xl border border-line bg-black/35 p-3 font-mono text-[11.5px] leading-[1.7]", className)}>
      {rows.length === 0 && <p className="text-subtle">(empty value)</p>}
      {rows.map((row, r) => (
        <div key={r} className="flex gap-4 whitespace-pre">
          <span className="text-subtle">{(r * ROW_BYTES).toString(16).padStart(4, "0")}</span>
          <span className="text-code">
            {Array.from({ length: ROW_BYTES }, (_, i) => (i < row.length ? row[i].toString(16).padStart(2, "0") : "  ")).join(" ")}
          </span>
          <span className="text-accent/80">{row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·")).join("")}</span>
        </div>
      ))}
      {truncated && (
        <p className="mt-1 text-subtle">
          … {totalBytes - bytes.length} more byte(s) withheld — quarantine keeps at most {bytes.length} bytes
        </p>
      )}
    </div>
  );
}
