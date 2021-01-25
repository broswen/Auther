var crypto = require('crypto');

const hashSaltPassword = password => {
  const hash = crypto.createHash('sha256');
  const saltedPassword = `${password}${process.env.SALT}`;
  const saltedAndHashedPassword = hash.update(saltedPassword).digest('hex');
 
  return saltedAndHashedPassword;
} 

module.exports = {hashSaltPassword}