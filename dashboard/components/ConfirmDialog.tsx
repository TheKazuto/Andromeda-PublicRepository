"use client";

import { useState, type ReactNode } from "react";
import { Modal } from "./Modal";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  busyLabel?: string;
  // `danger` styles the primary action red; use it for irreversible flows.
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}

// ConfirmDialog replaces `window.confirm()` so destructive actions match the
// design system, stay inside the focus trap, and disable the primary button
// while the async handler is in flight.
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  busyLabel = "Working…",
  danger,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handle() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  function handleCancel() {
    if (busy) return;
    setError(null);
    onCancel();
  }

  return (
    <Modal
      open={open}
      onClose={handleCancel}
      title={title}
      tone={danger ? "danger" : "default"}
    >
      <div className="text-sm text-slate-300 mb-5">{description}</div>
      {error && (
        <div className="text-xs text-ember-soft bg-ember/10 border border-ember/20 rounded-lg px-3 py-2 mb-4">
          {error}
        </div>
      )}
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={handleCancel}
          className="btn-ghost"
          disabled={busy}
        >
          {cancelLabel}
        </button>
        <button
          type="button"
          onClick={handle}
          disabled={busy}
          className={danger ? "btn-danger" : "btn-primary"}
        >
          {busy ? busyLabel : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}
