/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output is useful for Docker images, but it can conflict with "next start" workflows.
  // Enable it only when explicitly requested (e.g. Docker build sets NEXT_STANDALONE=1).
  ...(process.env.NEXT_STANDALONE === '1' ? { output: 'standalone' } : {}),
  transpilePackages: ['@massvision/shared'],
  webpack: (config) => {
    // Support NodeNext .js extension imports resolving to .ts source files
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js', '.jsx'],
      '.mjs': ['.mts', '.mjs'],
    };
    return config;
  },
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api'}/:path*` },
    ];
  },
};

export default nextConfig;
