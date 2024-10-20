// jshint esversion:6
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const flash = require("connect-flash");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log("MongoDB connection error: ", err));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secrets: [String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        if (user) {
            console.log("User found: ", user);
            done(null, user);
        } else {
            done(null, false);
        }
    } catch (err) {
        done(err);
    }
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    (accessToken, refreshToken, profile, cb) => {
        User.findOrCreate({ googleId: profile.id }, (err, user) => {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile"]
    })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    (req, res) => {
        res.redirect("/secrets");
    }
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const foundUser = await User.findById(req.user.id);
            res.render("secrets", {
                messages: {
                    success: req.flash("success"),
                    error: req.flash("error")
                },
                secrets: foundUser.secrets // Pass the secrets array to the view
            });
        } catch (err) {
            console.log(err);
            req.flash("error", "There was an error retrieving your secrets.");
            res.redirect("/secrets");
        }
    } else {
        res.redirect("/login");
    }
});


app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit", {
            messages: {
                success: req.flash("success"),
                error: req.flash("error")
            }
        });
    } else {
        res.redirect("/login");
    }
});


app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
        res.redirect("/");
    });
});

app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                req.session.save((err) => {
                    if (err) console.log(err);
                    res.redirect("/secrets");
                });
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, () => {
                req.session.save((err) => {
                    if (err) console.log(err);
                    res.redirect("/secrets");
                });
            });
        }
    });
});

app.post("/submit", async (req, res) => {
    if (req.isAuthenticated()) {
        const submittedSecret = req.body.secret;

        try {
            const foundUser = await User.findById(req.user.id);
            if (foundUser) {
                foundUser.secrets.push(submittedSecret); // Add new secret to the array
                await foundUser.save();

                req.flash("success", "Secret submitted successfully!");
                return res.redirect("/secrets");
            } else {
                req.flash("error", "User not found.");
                return res.redirect("/submit");
            }
        } catch (err) {
            console.log(err);
            req.flash("error", "There was an error submitting your secret.");
            return res.redirect("/submit");
        }
    } else {
        req.flash("error", "You must be logged in to submit a secret.");
        res.redirect("/login");
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}.`);
});
