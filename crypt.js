const crypt = require('bcrypt');


exports.decode = async (hash,password)=>{
    return crypt.compare(password,hash);
}