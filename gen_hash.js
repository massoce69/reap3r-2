const bcrypt = require('/app/massvision-reap3r/node_modules/bcrypt');
bcrypt.hash('Admin123!', 12).then(h => {
  console.log(h);
});
