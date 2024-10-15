//jshint esversion:6
require ('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

const secret = process.env.SECRET;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect(process.env.MONGO_URI + "userDB", {});

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});


userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {
    console.log(req.body); // Log the incoming data

    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    newUser.save()
        .then(() => {
            res.render("secrets");
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("Error saving user.");
        });
});

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username})
        .then(foundUser => {
            if (foundUser){
                if (foundUser.password === password) {
                    res.render("secrets");
                } else {
                    res.status(401).send("Incorrect password.");
                }
            } else {
                res.status(404).send("User not found.");
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("Error occurred during login.");
        });
    });

const PORT = process.env.PORT || 3000;

app.listen(3000, () => {
    console.log(`Server started on port ${PORT}.`);
});