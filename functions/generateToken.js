// JSON Web Tokens
const jwt = require('jsonwebtoken');

module.exports = (email, bearerExpiresInSeconds, refreshExpiresInSeconds) => {
    let exp = Math.floor(Date.now() / 1000) + bearerExpiresInSeconds;
    const token = jwt.sign({ email, exp }, process.env.JWT_SECRET);

    exp = Math.floor(Date.now() / 1000) + refreshExpiresInSeconds;
    const refreshToken = jwt.sign({ email, exp }, process.env.JWT_SECRET);

    return {
        bearerToken: { token, token_type: "Bearer", expires_in: bearerExpiresInSeconds },
        refreshToken: { token: refreshToken, token_type: "Refresh", expires_in: refreshExpiresInSeconds }
    };
}