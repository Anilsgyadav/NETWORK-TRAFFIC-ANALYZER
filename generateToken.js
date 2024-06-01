const jwt = require('jsonwebtoken');


exports.genToken = async(details)=>{
    return jwt.sign(details,process.env.JWT_SECRET);
}