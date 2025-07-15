// config/passport.js (VERSI GABUNGAN TERBAIK)
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';
// Import strategi JWT dan Google OAuth2
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt'; 
import { Strategy as GoogleStrategy } from 'passport-google-oauth2'; 
import User from '../models/users.model.js';
import { JWT_SECRET } from './jwt.js'; // Pastikan JWT_SECRET diimpor

// Hapus dotenv.config() dari sini karena sudah ada di index.js
import dotenv from 'dotenv';
dotenv.config();

// --- LocalStrategy (Validasi Email/Password) ---
const localConfig = {
    usernameField: 'email',
    passwordField: 'password'
};

passport.use(
    new LocalStrategy(localConfig, async (email, password, done) => {
        try {
            const user = await User.findOne({ email });

            if (!user) {
                return done(null, false, { message: 'Incorrect email or password' });
            }
            // Logika untuk mencegah login normal bagi pengguna Google OAuth atau yang tidak punya password
            if (user.registerType !== 'normal' || !user.password) {
                return done(null, false, { message: 'Please login using your Google account.' });
            }

            const compareResult = await bcrypt.compare(password, user.password);

            if (!compareResult) {
                return done(null, false, { message: 'Incorrect email or password' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
);

// --- JwtStrategy (Verifikasi Token dari Header Authorization) ---
const jwtOptions = {
    // Memberitahu Passport JWT untuk mengekstrak token dari header "Authorization: Bearer <token>"
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), 
    secretOrKey: JWT_SECRET, // Menggunakan secret key dari config/jwt.js
    passReqToCallback: true // Agar callback menerima 'req' sebagai argumen pertama
};

passport.use(
    new JwtStrategy(jwtOptions, async (req, jwt_payload, done) => { // Callback menerima req, jwt_payload
        try {
            // Cari user berdasarkan ID dari payload token
            const user = await User.findById(jwt_payload.id).select('-password');

            if (!user) {
                // User tidak ditemukan (mungkin akun dihapus setelah token dibuat)
                return done(null, false); 
            }
            // Lampirkan user ke req.user agar bisa diakses di route handler
            req.user = user; 
            return done(null, user);
        } catch (error) {
            return done(error, false); 
        }
    })
);

// --- GoogleStrategy (OAuth2) ---
const googleConfig = {
    clientID: process.env.GOOGLE_CLIENT_ID, 
    clientSecret: process.env.GOOGLE_SECRET, 
    callbackURL: 'http://localhost:3000/auth/login/google/callback' 
};

passport.use(
    new GoogleStrategy(googleConfig, async (accessToken, refreshToken, profile, done) => {
        try {
            // Cek apakah user sudah ada di DB berdasarkan socialId (Google ID)
            let user = await User.findOne({ socialId: profile.id, registerType: 'google' });

            if (user) {
                return done(null, user); 
            }

            // Jika belum ada user Google, cek apakah email sudah terdaftar via normal login
            user = await User.findOne({ email: profile.emails[0].value, registerType: 'normal' });
            if (user) {
                // Email sudah terdaftar secara normal, jangan izinkan login Google dengan email yang sama
                return done(null, false, { message: 'Email already registered with normal account. Please login normally.' });
            }

            // Jika user belum ada, buat user baru
            const newUser = await User.create({
                username: profile.displayName,
                email: profile.emails[0].value,
                registerType: 'google', 
                socialId: profile.id, 
                password: null, // Password disetel null untuk social login
            });

            return done(null, newUser);
        } catch (err) {
            console.error("Google OAuth error:", err);
            return done(err, false);
        }
    })
);

// Catatan: serializeUser dan deserializeUser tidak digunakan dalam alur JWT murni
// karena autentikasi bersifat stateless. Mereka bisa dihapus.

export default passport;