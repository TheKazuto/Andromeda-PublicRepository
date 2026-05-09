type Props = { size?: number; className?: string };

export function Logo({ size = 24, className }: Props) {
  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={className}
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="andromeda-logo-g" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#ff4d4d" />
          <stop offset="60%" stopColor="#c11b1b" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#040506" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx="32" cy="32" r="28" fill="url(#andromeda-logo-g)" />
      <ellipse
        cx="32"
        cy="32"
        rx="26"
        ry="8"
        fill="none"
        stroke="white"
        strokeOpacity="0.55"
        strokeWidth="1.4"
        transform="rotate(-22 32 32)"
      />
      <ellipse
        cx="32"
        cy="32"
        rx="18"
        ry="5"
        fill="none"
        stroke="white"
        strokeOpacity="0.85"
        strokeWidth="1.4"
        transform="rotate(-22 32 32)"
      />
      <circle cx="32" cy="32" r="2.6" fill="white" />
    </svg>
  );
}
