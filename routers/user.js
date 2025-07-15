// routers/user.js
import { Router } from "express";
import jwt from 'jsonwebtoken';
import User from "../models/users.model.js";
import passport from "../config/passport.js";
import { JWT_SECRET, JWT_EXPIRES_IN } from '../config/jwt.js';
import nodemailer from "nodemailer";
import crypto from "crypto";
import upload from '../modules/upload.module.js';

const router = Router();

const signToken = (id) => {
    return jwt.sign({ id }, JWT_SECRET, {
        expiresIn: JWT_EXPIRES_IN,
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(statusCode).json({
        status: 'success',
        token,
        user: userResponse,
    });
};

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "giovaldi8@gmail.com",
        pass: process.env.GOOGLE_APP_PASSWORD
    }
});

// POST /auth/signup - Mendaftarkan pengguna baru
router.post("/signup", upload.single('profileImage'), async (req, res, next) => {
    try {
        const { email, username, password } = req.body;
        const profileImageUrl = req.file ? req.file.location : undefined
        if (!username || !email || !password) {
            return res.status(400).json({ message: "Username, email, and password are required." });
        }

        // --- PERBAIKAN DI SINI: Lakukan kedua pengecekan dulu ---
        let errorMessages = []; // Array untuk menyimpan pesan error

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            errorMessages.push("Email already registered.");
        }

        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            errorMessages.push("Username already taken.");
        }

        // Jika ada pesan error, gabungkan dan kirim
        if (errorMessages.length > 0) {
            return res.status(409).json({ message: errorMessages.join(" and ") }); // Gabungkan pesan
        }
        // --- AKHIR PERBAIKAN ---

        const user = await User.create({
            username,
            email,
            password,
            registerType: 'normal',
            profileImageUrl
        });

        createSendToken(user, 201, res);

    } catch (error) {
        console.error("Signup error:", error);
        next(error);
    }
});

router.post("/login", (req, res, next) => {
    passport.authenticate("local", { session: false }, (err, user, info) => {
        if (err) {
            console.error("Passport authentication error:", err);
            return next(err);
        }
        if (!user) {
            return res.status(401).json({ message: info.message || 'Login failed' });
        }

        createSendToken(user, 200, res);
    })(req, res, next);
});

router.post("/logout", (req, res, next) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.error("Session destruction error on logout:", err);
                return next(err);
            }
            res.clearCookie('connect.sid');
            res.status(200).json({ message: "Logged out successfully (session cleared)." });
        });
    } else {
        res.status(200).json({ message: "Logged out successfully." });
    }
});

router.get("/status", passport.authenticate('jwt', { session: false }), (req, res) => {
    const userResponse = req.user.toObject();
    delete userResponse.password;
    res.json({ loggedIn: true, user: userResponse });
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

router.get('/login/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', session: false }),
    (req, res) => {
        createSendToken(req.user, 200, res);
    }
);

router.get("/users/:userId", async (req, res, next) => {
    try {
        const user = await User.findById(req.params.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.json({ status: "success", user });
    } catch (error) {
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        next(error);
    }
});

router.post("/send-email", async (req, res, next) => {
    const { to, subject, text, html } = req.body;
    try {
        if (!to || !subject || (!text && !html)) {
            return res.status(400).json({ success: false, message: "Recipient, subject, and either text or html content are required." });
        }

        await transporter.sendMail({
            from: "giovaldi8@gmail.com",
            to,
            subject,
            text,
            html
        });
        res.json({ success: true, message: "Email sent successfully!" });
    } catch (err) {
        console.error("Error sending email:", err);
        next(err);
    }
});

router.post('/forgot-password', async (req, res, next) => {
    let user;
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: 'Email is required.' });
        }

        user = await User.findOne({ email });
        if (!user) {
            return res.status(200).json({ message: 'If a user with that email exists, a password reset email will be sent.' });
        }

        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        const resetURL = `http://localhost:5173/reset-password/${resetToken}`;
        const message = `Anda menerima email ini karena Anda (atau orang lain) telah meminta reset kata sandi Anda.\n\n` +
                        `Silakan klik tautan ini untuk mereset kata sandi Anda: ${resetURL}\n\n` +
                        `Tautan ini akan kedaluwarsa dalam 10 menit. Jika Anda tidak meminta ini, abaikan email ini.`;

        await transporter.sendMail({
            from: "giovaldi8@gmail.com",
            to: user.email,
            subject: 'Reset Kata Sandi Anda',
            text: message
        });

        res.status(200).json({
            status: 'success',
            message: 'Jika pengguna dengan email tersebut ada, email reset kata sandi akan dikirim.'
        });

    } catch (err) {
        if (user) { 
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({ validateBeforeSave: false });
        }
        console.error("Error sending reset password email:", err);
        return next(err);
    }
});

router.post('/reset-password/:token', async (req, res, next) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ message: 'New password is required.' });
        }

        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Token tidak valid atau sudah kedaluwarsa.' });
        }

        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        createSendToken(user, 200, res);

    } catch (err) {
        console.error("Error resetting password:", err);
        next(err);
    }
});

export default router;