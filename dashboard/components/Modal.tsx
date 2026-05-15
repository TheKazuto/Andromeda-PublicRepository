"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
  maxWidth?: number;
  // Tone overrides the border colour — `danger` for destructive flows.
  tone?: "default" | "danger";
  hideClose?: boolean;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Modal centralises overlay + focus-trap + ESC handling so every confirmation
// and form modal in the dashboard behaves the same way. Renders nothing when
// `open` is false so callers can drive it from local state without ceremony.
export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  maxWidth = 480,
  tone = "default",
  hideClose,
}: ModalProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !ref.current) return;

      const focusable = ref.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKey);

    // Defer focus by a frame so any autoFocus inside `children` resolves first.
    const t = window.setTimeout(() => {
      const first = ref.current?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      first?.focus();
    }, 0);

    return () => {
      document.removeEventListener("keydown", onKey);
      window.clearTimeout(t);
      document.body.style.overflow = prevOverflow;
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  const borderTone = tone === "danger" ? " border-ember/30" : "";

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm px-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        ref={ref}
        className={"card w-full p-6 animate-fade-up" + borderTone}
        style={{ maxWidth: `${maxWidth}px` }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 mb-1">
          <h3 className="text-[17px] font-semibold tracking-tight">{title}</h3>
          {!hideClose && (
            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-snow -mr-1 -mt-1"
              aria-label="Close"
            >
              <X size={16} strokeWidth={1.6} />
            </button>
          )}
        </div>
        {description && (
          <div className="text-sm text-slate-300 mb-5">{description}</div>
        )}
        {children}
      </div>
    </div>
  );
}
