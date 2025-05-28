const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const generateToken = require('../functions/generateToken');
const authorize = require('../middleware/authorization');

// Register
router.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ error: true, message: "Request body incomplete, email and password needed." });

        const userExists = await req.db('movies.users').where({ email }).first();
        if (userExists)
            return res.status(409).json({ error: true, message: "User already exists." });

        const hash = bcrypt.hashSync(password, 10);
        await req.db('movies.users').insert({ email, hash, firstName: null, lastName: null, dob: null, address: null });
        res.status(201).json({ message: "User created" });
    } catch (err) {
        res.status(500).json({ error: true, message: "Internal server error" });
    }
});

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: true, message: "Request body incomplete, email and password needed." });

    const user = await req.db('movies.users').where({ email }).first();
    if (!user || !await bcrypt.compare(password, user.hash))
        return res.status(401).json({ error: true, message: "Incorrect email or password." });

    const tokens = generateToken(email, 600, 86400);
    res.status(200).json({
        bearerToken: tokens.bearerToken,
        refreshToken: tokens.refreshToken
    });
});

// Profile retrieval
router.get('/:email/profile', async (req, res) => {
    const userData = await req.db
        .from("movies.users")
        .select("email", "firstName", "lastName", "dob", "address")
        .where("email", "=", req.params.email);

    if (userData.length === 0) {
        return res.status(404).json({
            error: true,
            message: "User not found."
        });
    }

    // No auth header
    if (!("authorization" in req.headers)) {
        const info = {
            email: userData[0].email,
            firstName: userData[0].firstName,
            lastName: userData[0].lastName
        };
        return res.status(200).json(info);
    }

    // Bearer token
    if (req.headers.authorization.match(/^Bearer /)) {
        const token = req.headers.authorization.replace(/^Bearer /, "");
        try {
            const verified = jwt.verify(token, process.env.JWT_SECRET);
            if (verified.email === req.params.email) {
                return res.status(200).json(userData[0]);
            } else {
                // Authenticated as another user: only public info
                const info = {
                    email: userData[0].email,
                    firstName: userData[0].firstName,
                    lastName: userData[0].lastName
                };
                return res.status(200).json(info);
            }
        } catch (e) {
            if (e.name === "TokenExpiredError") {
                return res.status(401).json({ error: true, message: "JWT token has expired" });
            } else {
                return res.status(401).json({ error: true, message: "Invalid JWT token" });
            }
        }
    } else {
        return res.status(401).json({ error: true, message: "Authorization header is malformed" });
    }
});

// Profile update
router.put('/:email/profile', authorize, async (req, res) => {
    const { firstName, lastName, dob, address } = req.body;
    const email = req.params.email;

    // Validate request body
    if (!firstName && !lastName && !dob && !address) {
        return res.status(400).json({ error: true, message: "Request body incomplete. At least one of firstName, lastName, dob, or address required." });
    }

    // Check if user exists
    const user = await req.db('movies.users').where({ email }).first();
    if (!user) {
        return res.status(404).json({ error: true, message: "User not found." });
    }

    // Update user data
    try {
        await req.db('movies.users').where({ email }).update({ firstName, lastName, dob, address });
        // Fetch and return the updated user
        const updatedUser = await req.db('movies.users')
            .select('email', 'firstName', 'lastName', 'dob', 'address')
            .where({ email })
            .first();
        res.status(200).json(updatedUser);
    } catch (err) {
        res.status(500).json({ error: true, message: "Internal server error" });
    }
});

// Logout
router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: true, message: "Request body incomplete, refresh token required" });
    }

    try {
        jwt.verify(refreshToken, process.env.JWT_SECRET);
        // In a real app, you would blacklist the token here
        return res.status(200).json({ error: false, message: "Token successfully invalidated" });
    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({ error: true, message: "JWT token has expired" });
        }
        return res.status(401).json({ error: true, message: "Invalid JWT token" });
    }
});

// Refresh tokens
router.post('/tokens/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: true, message: "Request body incomplete, refresh token required" });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        // Issue new tokens
        const tokens = generateToken(decoded.email, 600, 86400);
        return res.status(200).json({
            bearerToken: tokens.bearerToken,
            refreshToken: tokens.refreshToken
        });
    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({ error: true, message: "JWT token has expired" });
        }
        return res.status(401).json({ error: true, message: "Invalid JWT token" });
    }
});

module.exports = router;