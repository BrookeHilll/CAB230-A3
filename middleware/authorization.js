const jwt = require('jsonwebtoken');

module.exports = async (req, res, next) => {
    // check if nothing has been provided or is incorrect
    if (!("authorization" in req.headers) || !req.headers.authorization.match(/^Bearer /)) {
        return res.status(401).json({ error: true, message: "Authorization header ('Bearer token') not found" });
    }

    const token = req.headers.authorization.replace(/^Bearer /, "");
    
    try { jwt.verify(token, process.env.JWT_SECRET) }
    catch (e) {
        if (e.name === "TokenExpiredError") {
            res.status(401).json({ error: true, message: "JWT Token has Expired" });
        } else {
            res.status(401).json({ error: true, message: "Invalid JWT token" });
        }
        return;
    }

    next();
}