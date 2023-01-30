const crypto = require('crypto');

let salt = crypto.randomBytes(16);
let saltString = salt.toString('hex');
crypto.pbkdf2('859617', saltString, 310000, 32, 'sha256', (err, result) => {
    console.log(result);
});
crypto.pbkdf2('859617', saltString, 310000, 32, 'sha256', (err, result) => {
    console.log(result)
});
