interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3 mb-6">
      <div>
        <p className="text-[11px] font-mono uppercase tracking-[0.18em] text-ember">
          Operator console
        </p>
        <h1 className="text-2xl font-semibold tracking-tight mt-1">{title}</h1>
        {description && (
          <p className="text-sm text-slate-300 mt-1.5 max-w-2xl">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
