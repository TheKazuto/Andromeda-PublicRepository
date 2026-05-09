/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Static export — compatible with Cloudflare Pages out of the box.
  output: "export",
  // Trailing slash makes static hosts (including Cloudflare Pages)
  // resolve /login -> /login/index.html cleanly.
  trailingSlash: true,
  // next/image optimization is server-side; turn off for static export.
  images: { unoptimized: true },
};

module.exports = nextConfig;
