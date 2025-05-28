const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authorisation = require("../middleware/authorization");
const validDate = require("../functions/validDate");
const notFuture = require("../functions/notFuture");
const generateToken = require("../functions/generateToken");

// Helper: Validate date format YYYY-MM-DD
function isValidDateFormat(date) {
    return /^\d{4}-\d{2}-\d{2}$/.test(date) && validDate(date);
}

// Helper: Date not in future
function dateNotInFuture(date) {
    return notFuture(date);
}

// POST /user/register
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: true, message: "Request body incomplete, email and password needed." });

    const userExists = await req.db('movies.users').where({ email }).first();
    if (userExists)
        return res.status(409).json({ error: true, message: "User already exists." });

    const hash = bcrypt.hashSync(password, 10);
    await req.db('movies.users').insert({ email, hash, firstName: null, lastName: null, dob: null, address: null });
    res.status(201).json({ message: "User created" });
});

// POST /user/login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: true, message: "Request body incomplete, email and password needed." });

    const user = await req.db('movies.users').where({ email }).first();
    if (!user || !await bcrypt.compare(password, user.hash))
        return res.status(401).json({ error: true, message: "Incorrect email or password." });

    const tokens = generateToken(email, 600, 86400);
    res.status(200).json(tokens);
});

// POST /user/refresh
router.post('/refresh', async (req, res) => {
    const userRefreshToken = req.body.refreshToken;
    if (!userRefreshToken) {
        return res.status(400).json({
            error: true,
            message: "Request body incomplete, refresh token required"
        });
    }

    // Check if token is invalidated
    let tokens = [];
    try {
        const invalidTokens = await req.db.from("movies.invalidTokens").select("*");
        invalidTokens.forEach(token => {
            tokens.push(token.tokens);
        });
    } catch {
        return res.status(500).json({ error: true, message: "Internal server error" });
    }
    if (tokens.includes(userRefreshToken))
        return res.status(401).json({ error: true, message: "JWT token is invalidated" });

    // Verify refresh token
    try {
        const verified = jwt.verify(userRefreshToken, process.env.JWT_SECRET, { ignoreExpiration: false });
        const response = generateToken(verified.email, 600, 86400);
        res.status(200).json(response);
    } catch (e) {
        if (e.name === "TokenExpiredError")
            res.status(401).json({ error: true, message: "JWT token has expired" });
        else
            res.status(401).json({ error: true, message: "Invalid JWT token" });
    }
});

// POST /user/logout
router.post('/logout', async (req, res) => {
    if (!req.body.refreshToken) {
        return res.status(400).json({ error: true, message: "Request body incomplete, refresh token required" });
    }
    const token = req.body.refreshToken;
    try {
        jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        if (e.name === "TokenExpiredError") {
            return res.status(401).json({ error: true, message: "JWT token has expired" });
        } else {
            return res.status(401).json({ error: true, message: "Invalid JWT token" });
        }
    }
    try {
        await req.db.from("movies.invalidTokens").insert({ tokens: token });
        res.status(200).json({ error: false, message: "Token successfully invalidated" });
    } catch {
        res.status(500).json({ error: true, message: "Error with database" });
    }
});

// GET /user/:email/profile
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

// PUT /user/:email/profile
router.put('/:email/profile', authorisation, async (req, res) => {
    const { firstName, lastName, dob, address } = req.body;

    // Check for missing fields
    if (!firstName || !lastName || !dob || !address) {
        return res.status(400).json({ error: true, message: "Request body incomplete: firstName, lastName, dob and address are required." });
    }
    // Check types
    if (typeof firstName !== "string" || typeof lastName !== "string" || typeof dob !== "string" || typeof address !== "string") {
        return res.status(400).json({ error: true, message: "Request body invalid: firstName, lastName and address must be strings only." });
    }
    // Validate date format
    if (!isValidDateFormat(dob)) {
        return res.status(400).json({ error: true, message: "Invalid input: dob must be a real date in format YYYY-MM-DD." });
    }
    // Validate not future
    if (!dateNotInFuture(dob)) {
        return res.status(400).json({ error: true, message: "Invalid input: dob must be a date in the past." });
    }

    // Check user exists
    const userData = await req.db('movies.users')
        .select('email')
        .where('email', req.params.email)
        .limit(1);
    if (userData.length === 0) {
        return res.status(404).json({ error: true, message: "User not found" });
    }

    // Check token matches email
    const token = req.headers.authorization.replace('Bearer ', '');
    let verified;
    try {
        verified = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        if (e.name === "TokenExpiredError") {
            return res.status(401).json({ error: true, message: "JWT token has expired" });
        } else {
            return res.status(401).json({ error: true, message: "Invalid JWT token" });
        }
    }
    if (verified.email !== req.params.email) {
        return res.status(403).json({ error: true, message: "Forbidden" });
    }

    // Update
    await req.db("movies.users")
        .where("email", "=", req.params.email)
        .update({ firstName, lastName, dob, address });

    res.status(200).json({ email: userData[0].email, firstName, lastName, dob, address });
});

module.exports = router;