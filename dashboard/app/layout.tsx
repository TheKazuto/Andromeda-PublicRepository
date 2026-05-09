import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Andromeda — Dashboard",
  description: "Manage your Andromeda API and MCP server access",
  icons: {
    icon: "/Logo.png",
    apple: "/Logo.png",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Instrument+Serif:ital@0;1&family=JetBrains+Mono:wght@300;400;500&display=swap"
        />
      </head>
      <body className="min-h-screen bg-void text-snow antialiased">{children}</body>
    </html>
  );
}
