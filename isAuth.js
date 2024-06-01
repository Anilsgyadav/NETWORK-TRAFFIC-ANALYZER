const jwt = require('jsonwebtoken');


exports.isAuthenticated = async (req,res,next)=>{
    let cookie = req.headers.cookie; // we need to access the cookies from the header.
    if(cookie===undefined || !cookie.includes("token")){
        return res.render('login',{
            message:"You are not authorized.",
            username:""
        })
    }
    let token = cookie.split("token=")[1];
    // console.log(token);
    jwt.verify(token,process.env.JWT_SECRET,(err,user)=>{
        //now token is valid and we can proceed further
        if(err)
        {
            return res.render('login',{
                message:'session expired.',
                username:""
            })
        }
        // console.log(user);
        req.user=user;
        next();
    });
}