const mongoose = require('mongoose');

exports.connect = ()=>{
    // ${process.env.DB_NAME}
    mongoose.connect(`${process.env.DB_URI}`,()=>{
        console.log("connected to the database!");
    })
}