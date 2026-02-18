module.exports = {
  apps: [
    {
      name: "reap3r-backend",
      script: "dist/index.js",
      cwd: "/var/www/reap3r-2/backend",
      instances: 1,
      env: {
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://reap3r:reap3r_secret@localhost:5432/reap3r",
        JWT_SECRET: "c236f8e9a7995af5a80b5ed7b8ee9da85f0c8e80c5d2d008163083b3381b1c72",
        HMAC_SECRET: "02112c233d93de28a79a032737873b2b59586c891ea3b9e2a9776414e4bbddfd",
        VAULT_MASTER_KEY: "02112c233d93de28a79a032737873b2b59586c891ea3b9e2a9776414e4bbddfd",
        LOG_LEVEL: "info",
        PORT: "4000",
        WS_PORT: "4001",
        API_BASE_URL: "https://massvision.pro"
      }
    }
  ]
};
