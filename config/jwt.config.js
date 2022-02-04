const jwt = require("jsonwebtoken");

module.exports = function generateToken(user) {
  // Sending User data to Front-End
  const { _id, name, email } = user;

  // JWT Config
  const signature = process.env.TOKEN_SIGN_SECRET;
  const expiration = "6h";

  return jwt.sign({ _id, name, email }, signature, {
    expiresIn: expiration,
  });
};
