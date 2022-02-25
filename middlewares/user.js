const User = require("../models/user");
const BigPromise = require("../middlewares/bigPromise");
const jwt = require("jsonwebtoken");

exports.isLoggedIn = BigPromise(async (req, res, next) => {
  const token =
    req.cookies.token || req.header("Authorization").replace("Bearer ", "");

  if (!token) {
    return next(new Error("Login first to access this page"));
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  // console.log("ID " + decoded.id);

  req.user = await User.findById(decoded.id);

  // console.log(req.user);

  next();
});

exports.customRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new Error("You are not allowed for this resource"));
    }
    next();
  };
};
