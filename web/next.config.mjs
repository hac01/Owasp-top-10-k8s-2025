/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server bundle for the container image.
  output: "standalone",
};

export default nextConfig;
