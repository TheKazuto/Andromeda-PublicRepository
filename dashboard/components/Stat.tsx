type Props = {
  label: string;
  value: string;
  sublabel?: string;
  trend?: { value: string; positive?: boolean };
  Icon?: React.ComponentType<{ size?: number; strokeWidth?: number; className?: string }>;
};

export function Stat({ label, value, sublabel, trend, Icon }: Props) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="label-base">{label}</span>
        {Icon && (
          <span className="w-7 h-7 rounded-lg bg-ember/10 border border-ember/20 grid place-items-center text-ember">
            <Icon size={14} strokeWidth={1.6} />
          </span>
        )}
      </div>
      <div className="text-[28px] font-semibold tracking-display leading-none">{value}</div>
      <div className="mt-2 flex items-center gap-2 text-xs">
        {trend && (
          <span
            className={
              trend.positive
                ? "text-signal-mint"
                : "text-ember-soft"
            }
          >
            {trend.value}
          </span>
        )}
        {sublabel && <span className="text-slate-400">{sublabel}</span>}
      </div>
    </div>
  );
}
