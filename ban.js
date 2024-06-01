const mongoose = require('mongoose');

const Ban = mongoose.Schema({
    domain: {
        type:String,
        required:true
    },
    category:{
        type: String,
        required: true
    },
    ip: {
        type:String,
        required:true,
    },
    ping: {
        type:String,
        required:true
    },
    ping_time: {
        type:String,
        required:true
    },
    online: {
        type:String,
        required:true
    },
    statusCode:{
        type:String,
        required:true
    },
    success: {
        type:String,
        required:true
    }
}
);

module.exports = mongoose.model("Ban",Ban);