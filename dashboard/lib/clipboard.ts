// Best-effort clipboard copy. Returns `true` when the write succeeds.
// Browsers reject `writeText` outside secure contexts, inside cross-origin
// iframes, and when the user denies the permission prompt; surface those
// failures so the UI can fall back to "copy manually" messaging.
export async function copyToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
