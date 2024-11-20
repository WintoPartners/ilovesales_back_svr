module.exports = {
  apps: [{
    name: 'ilovesales-backend',
    script: 'server.js',
    env: {
      PORT: 3000,
      NODE_ENV: 'production'
    },
    instances: 1,
    exec_mode: 'cluster',
    listen_address: '0.0.0.0',
    env_file: '/home/user/app/.env'
  }]
};
