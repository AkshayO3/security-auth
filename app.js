require('dotenv').config(); // Loads environment variables from a .env file

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public")); // Serve static files from the "public" directory
app.set('view engine', 'ejs'); // Set the view engine to use EJS templating
app.use(bodyParser.urlencoded({extended: true})); // Parse URL-encoded bodies
app.use(session({
    secret: process.env.SECRET, // Secret used to sign the session ID cookie
    resave: false, // Forces the session to be saved back to the session store, even if it wasn't modified during the request
    saveUninitialized: false // Ensures uninitialized sessions are not saved to the session store
}));
app.use(passport.initialize()); // Initialize Passport.js
app.use(passport.session()); // Enable persistent login sessions using Passport.js

mongoose.connect(process.env.URI, {useNewUrlParser: true, useUnifiedTopology: true}); // Connect to MongoDB using Mongoose

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    google_ID: String,
    secret: String
});
userSchema.plugin(passportLocalMongoose); // Simplifies Passport authentication with username and password
userSchema.plugin(findOrCreate); // Adds the "findOrCreate" method to the user schema

const User = mongoose.model('User', userSchema); // Create a User model using the user schema
passport.use(User.createStrategy()); // Set up Passport to use the local strategy for authentication

// Serialize and deserialize user instances to and from the session
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
});

// Configure Passport to use the Google OAuth 2.0 strategy for authentication
passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "https://secrets-fplp.onrender.com/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({google_ID: profile.id}, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home"); // Render the "home" template
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]})); // Authenticate with Google

app.get('/auth/google/secrets',
    passport.authenticate('google', {failureRedirect: '/login'}),
    function (req, res) {
        // Successful authentication, redirect to the "/secrets" page
        res.redirect("/secrets");
    });

app.get("/login", (req, res) => {
    res.render("login"); // Render the "login" template
});

app.get("/register", (req, res) => {
    res.render("register"); // Render the "register" template
});

app.get("/secrets", (req, res) => {
    User.find({'secret': {$ne: null}}).then((found) => {
        res.render("secrets", {usersWithSecrets: found}); // Render the "secrets" template with the found users who have secrets
    }).catch((err) => {
        console.log("Error in rendering secrets => " + err);
    });
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets"); // Redirect to the "/secrets" page after successful registration and authentication
            });
        }
    });
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets", // Redirect to the "/secrets" page after successful login
    failureRedirect: "/login" // Redirect to the "/login" page if login fails
}));

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit"); // Render the "submit" template if the user is authenticated
    } else {
        res.redirect("/login"); // Redirect to the "/login" page if the user is not authenticated
    }
});

app.post("/submit", (req, res) => {
    const secret = req.body.secret;
    User.findById(req.user.id).then((found) => {
        found.secret = secret;
        found.save().then(() => {
            res.redirect("/secrets"); // Redirect to the "/secrets" page after saving the user's secret
        });
    }).catch(() => {
        console.log("Error, couldn't submit secret");
    });
});

app.listen(3000, () => {
    console.log("Server ON"); // Start the server on port 3000
});
