const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const session = require('express-session');
const cors = require('cors');

const app = express();
const port = 6700;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));


// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from public directory
app.use(express.static('public'));

// Setup session
app.use(session({
    secret: '6LcN_kgqAAAAAIOTdzmSZfPksnReJ01Ecs5j1AUe',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/connection')
    .then(() => console.log("MongoDB connection successful"))
    .catch(err => console.error("MongoDB connection error:", err));

// Define user schema
const userSchema = new mongoose.Schema({
    fullname: String,
    email: { type: String, unique: true },
    password: String, // Hashed password
    resetToken: String,
    resetTokenExpiration: Date,
    isEmailConfirmed: { type: Boolean, default: false }, // Added for email verification
    verificationToken: String // Added for email verification token
});

const User = mongoose.model("User", userSchema);

// Google reCAPTCHA secret key
const recaptchaSecretKey = '6LcN_kgqAAAAAIOTdzmSZfPksnReJ01Ecs5j1AUe';

// Configure Nodemailer transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'kcbarsat0055@gmail.com',
        pass: 'xpak vtje olxb psxy' // Use app-specific password if 2FA is enabled
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Add root route to avoid "Cannot GET /" error
app.get('/', (req, res) => {
    if (!req.session.user) {
        // If the user is not logged in, redirect to the login page
        return res.redirect('/login');
    }
    // If the user is logged in, redirect to the home page
    res.redirect('/home');
});

// Home route
app.get('/home', (req, res) => {
    // Check if user is logged in, if not redirect to login
    if (!req.session.user) {
        return res.redirect('/login');
    }
    // Render home.ejs and pass the session user
    res.render('home', { user: req.session.user });
});

// Add register route (GET) to render the register page
app.get('/register', (req, res) => {
    res.render('register');
});

// Handle registration form submission (POST)
app.post('/register', async (req, res) => {
    const { fullname, email, password, 'confirm-password': confirmPassword } = req.body;

    // Simple password match validation
    if (password !== confirmPassword) {
        return res.render('register', { errorMessage: "Passwords do not match." });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render('register', { errorMessage: "Email already in use." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate email verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');

        // Create a new user (isEmailConfirmed is false until email is verified)
        const user = new User({
            fullname,
            email,
            password: hashedPassword,
            isEmailConfirmed: false,
            verificationToken
        });

        await user.save();

        // Send verification email
        const verificationLink = `http://localhost:${port}/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: 'kcbarsat0055@gmail.com',
            to: email,
            subject: 'Email Verification',
            text: `Click the following link to verify your email: ${verificationLink}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.render('register', { errorMessage: "Error sending verification email." });
            }
            res.render('register', { successMessage: 'Registration successful! Please check your email to verify your account.' });
        });

    } catch (err) {
        res.status(500).send("Error during registration.");
    }
});

// Email verification route
app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        // Find user by verification token
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.send('Invalid or expired verification token.');
        }

        // Mark the user as verified
        user.isEmailConfirmed = true;
        user.verificationToken = undefined; // Clear the verification token
        await user.save();

        res.send('Email verified successfully! You can now log in.');
    } catch (err) {
        res.status(500).send("Error during email verification.");
    }
});

// Add login route (GET) to render the login page
app.get('/login', (req, res) => {
    res.render('login', { errorMessage: null });
});

// Handle login POST request
app.post('/login', async (req, res) => {
    const { email, password, 'g-recaptcha-response': captchaResponse } = req.body;

    // Verify Google reCAPTCHA
    const recaptchaVerificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecretKey}&response=${captchaResponse}`;

    try {
        const verificationResponse = await axios.post(recaptchaVerificationUrl);
        const verificationData = verificationResponse.data;

        if (!verificationData.success) {
            return res.render('login', { errorMessage: "CAPTCHA verification failed." });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.render('login', { errorMessage: "Invalid email or password." });
        }

        // Check if email is verified
        if (!user.isEmailConfirmed) {
            return res.render('login', { errorMessage: "Email not confirmed. Please check your inbox for the verification email." });
        }

        // Check if the password is correct
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { errorMessage: "Invalid password." });
        }

        // Set session after successful login
        req.session.user = user; // Set session user data
        res.redirect('/home'); // Redirect to home after login
    } catch (err) {
        res.status(500).send("Error during login.");
    }
});

// Forgot password page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password'); // Make sure `forgot-password.ejs` exists in the views directory
});

// Forgot password route (send reset link)
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send("No user with that email found.");
        }

        // Generate a reset token and expiration date
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiration = Date.now() + 3600000; // 1 hour expiration

        user.resetToken = resetToken;
        user.resetTokenExpiration = resetTokenExpiration;
        await user.save();

        // Create a reset link
        const resetLink = `http://localhost:${port}/reset-password/${resetToken}`;
        const mailOptions = {
            from: 'kcbarsat0055@gmail.com',
            to: email,
            subject: 'Password Reset',
            text: `You requested a password reset. Please click the following link to reset your password: ${resetLink}`
        };

        // Send reset password email
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("Error sending email: ", err);
                return res.status(500).send("Error sending reset password email.");
            }
            res.send("Password reset link has been sent to your email.");
        });

    } catch (err) {
        console.error("Error handling forgot password request: ", err);
        res.status(500).send("Error handling forgot password request.");
    }
});

// Reset password page route
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send("Invalid or expired reset token.");
        }

        // Render reset password form with token
        res.render('reset-password', { token });
    } catch (err) {
        console.error("Error accessing password reset page: ", err);
        res.status(500).send("Error accessing password reset page.");
    }
});

// Handle password reset POST request
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password, 'confirm-password': confirmPassword } = req.body;

    try {
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send("Invalid or expired reset token.");
        }

        if (password !== confirmPassword) {
            return res.status(400).send("Passwords do not match.");
        }

        // Hash the new password and update the user
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;

        // Mark email as confirmed (if this is required post password reset)
        user.isEmailConfirmed = true;  // <-- Added to ensure email is confirmed after password reset
        await user.save();

        // Redirect to login page after successful reset
        res.redirect('/login');
    } catch (err) {
        console.error("Error resetting password: ", err);
        res.status(500).send("Error resetting password.");
    }
});

// Logout route (POST)
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login'); // Redirect to login after logout
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
