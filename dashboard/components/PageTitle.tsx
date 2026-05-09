type Props = {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
};

export function PageTitle({ eyebrow, title, description, actions }: Props) {
  return (
    <div className="flex items-start justify-between gap-6 mb-8">
      <div>
        {eyebrow && (
          <div className="text-[11px] uppercase tracking-[0.16em] text-ember font-medium font-mono mb-2">
            {eyebrow}
          </div>
        )}
        <h2 className="text-[28px] font-semibold tracking-tighter leading-tight">{title}</h2>
        {description && <p className="mt-2 text-sm text-slate-300 max-w-xl">{description}</p>}
      </div>
      {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
    </div>
  );
}
