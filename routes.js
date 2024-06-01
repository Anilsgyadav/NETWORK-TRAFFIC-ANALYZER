const express = require('express');
const app = express();

const banController = require('../controllers/Ban.controller');
const DetectController = require('../controllers/detect.Controller');
const LoginController = require('../controllers/login.controller');
const isAuth = require('../middleware/isAuth');

app.get('/health',(req,res)=>{
    return res.status(200).json({
        message: "~App is live~"
    })
})
app.get('/',(req,res)=>{
    return res.redirect('/login');
})

//Login route.
app.get('/login',LoginController.ShowLoginPage);
app.post('/login',LoginController.ActionLoginPage);

app.get('/add',isAuth.isAuthenticated,banController.Showpage);
app.post('/addban',isAuth.isAuthenticated,banController.AddData);

app.get('/detect',isAuth.isAuthenticated,DetectController.check);
app.get('/live',isAuth.isAuthenticated,DetectController.livePage);
app.get('/bannedpage', isAuth.isAuthenticated, banController.BannedData);

// app.get('/live-detect', isAuth.isAuthenticated);


app.get('/logout',LoginController.logout);

module.exports = app;