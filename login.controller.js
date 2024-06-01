const User = require('../models/user');
const crypt = require('../utils/crypt');
const tokenGen = require('../utils/generateToken');

exports.ShowLoginPage = (req, res) => {
    // console.log(req.headers.cookie);
    res.render('login', {
        message: "",
        username: ""
    });
}

exports.ActionLoginPage = async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.render('login', {
                message: 'Account not found!',
                username
            })
        }

        if (await crypt.decode(user.password, password)) {
            const token = await tokenGen.genToken({
                username
            });
            // console.log(token);
            res.cookie("token", token);
            return res.redirect('/add');
        }
        else {
            return res.render('login', {
                message: "Invalid email or password.",
                username
            })
        }
    }
    catch (error) {
        console.log("some error occured");
    }
}

exports.logout = async (req, res) => {
    res.clearCookie("token");
    return res.redirect("/login");
}