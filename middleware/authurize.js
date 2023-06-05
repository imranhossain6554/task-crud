const jsonwebtoken = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/user");
const { expressjwt: expressJwt } = require("express-jwt");
var jwks = require("jwks-rsa");

var jwtCheck = expressJwt({
  secret: jwks.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
  }),

  algorithms: ["RS256"],
});
exports.authenticate = async (req, res, next) => {
  let token = req.header("Authorization");

  if (!token) {
    // Check if the session contains the user ID
    if (req.session && req.session.user && req.session.user._id) {
      req.ID = req.session.user._id;
      return next();
    }
    return res.status(401).json({ msg: "Authentication failed" });
  }

  token = token.replace("Bearer ", "");

  try {
    // Verify the JWT token
    const vrfy = jsonwebtoken.verify(token, process.env.JWT_SECRET);
    req.ID = vrfy._id;
    return next();
  } catch (err) {
    // Check if the session contains the user ID
    if (req.session && req.session.user && req.session.user._id) {
      req.ID = req.session.user._id;
      return next();
    }
    return res.status(401).json({ msg: "Authentication failed" });
  }
};
exports.checkSenderUserId = (req, res, next) => {
  const { sender_userId } = req.body;

  console.log("fisrt ", sender_userId);
  if (sender_userId && sender_userId === req.ID) {
    next();
  } else {
    const { sender_userId } = req.query;
    console.log("second ", sender_userId);
    console.log("req.ID ", req.ID);

    if (sender_userId && sender_userId == req.ID) {
      next();
    } else {
      return res
        .status(404)
        .json({ msg: "You are not authorized to send this request" });
    }
  }
};

exports.resetToken = (req, res, next) => {
  const token = req.header("auth-Token");
  // console.log(token);
  if (!token) return res.status(404).json({ msg: "Token not found!" });
  try {
    const vrfy = jsonwebtoken.verify(token, process.env.PASSWORD_RESET_TOKEN);
    req.ID = vrfy.ID;
    next();
  } catch (_) {
    res.status(401).json({ msg: "Invalid Token" });
  }
};
