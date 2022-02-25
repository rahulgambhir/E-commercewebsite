const User = require("../models/user");
const BigPromise = require("../middlewares/bigPromise");
const cookieToken = require("../utils/cookieToken");
const cloudinary = require("cloudinary");
const mailHelper = require("../utils/emailHelper");
const crypto = require("crypto");

exports.signup = BigPromise(async (req, res, next) => {
  // let result;

  if (!req.files) {
    return next(new Error("photo is required for signup"));
  }

  const { name, email, password } = req.body;

  if (!email || !name || !password) {
    return next(new Error("Name, email and password are required"));
  }

  let file = req.files.photo;

  const result = await cloudinary.v2.uploader.upload(file.tempFilePath, {
    folder: "users",
    width: 150,
    crop: "scale",
  });

  const user = await User.create({
    name,
    email,
    password,
    photo: {
      id: result.public_id,
      secure_url: result.secure_url,
    },
  });

  cookieToken(user, res);
});

exports.login = BigPromise(async (req, res, next) => {
  const { email, password } = req.body;

  // check for presence of email & password entered by user
  if (!email || !password) {
    return next(new Error("please provide email and password"));
  }

  // get user from DB
  const user = await User.findOne({ email }).select("+password"); // in user model, password is written as - select: false but here we need password too to match it in DB

  // if user not found in DB
  if (!user) {
    return next(new Error("Email or password does not match or exist"));
  }

  // match the password
  const isPasswordCorrect = await user.isvalidatedPassword(password);

  // if password do not match
  if (!isPasswordCorrect) {
    return next(new Error("Email or password does not match or exist"));
  }

  // if all goes good, send the token
  cookieToken(user, res);
});

exports.logout = BigPromise(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    message: "Logout success",
  });
});

exports.forgotPassword = BigPromise(async (req, res, next) => {
  const { email } = req.body;

  // checking user in DB
  const user = await User.findOne({ email });

  // if user not found in DB
  if (!user) {
    return next(new Error("Email not found as registered"));
  }

  // get token from user model methods
  const forgotToken = user.getForgotPassword();

  // save user fields in DB
  await user.save({ validateBeforeSave: false }); // there are some required fields in model but we are not passing that here. To handle that situation, we're turning off the validation here

  // create a URL
  const myUrl = `${req.protocol}://${req.get(
    "host"
  )}/api/v1//password/reset/${forgotToken}`;

  // craft a message
  const message = `Copy paste this link in your URL and hit enter \n\n ${myUrl}`;

  // attempt to send email
  try {
    await mailHelper({
      email: user.email,
      subject: "TStore - Password reset email",
      message,
    });

    // json response if email is success
    res.status(200).json({
      success: true,
      message: "Email sent successfully",
    });
  } catch (error) {
    // reset user fileds if things goes wrong
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new Error(error.message));
  }
});

exports.passwordReset = BigPromise(async (req, res, next) => {
  const token = req.params.token;

  const encryToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    encryToken,

    // also check if token is expired or it's still valid
    forgotPasswordExpiry: { $gt: Date.now() }, // It is a classic mongoDB query, gt means greater than
  });

  if (!user) {
    return next(new Error("Token is invalid or expired"));
  }

  if (req.body.password !== req.body.confirmPassword) {
    return next(new Error("Password & confirm password do not match"));
  }

  user.password = req.body.password;

  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;

  await user.save();

  // send a json response OR send token

  cookieToken(user, res);
});

exports.getLoggedInUserDetails = BigPromise(async (req, res, next) => {
  // console.log(req.user.id);
  const user = await User.findById(req.user.id);
  // console.log(user);

  res.status(200).json({
    success: true,
    user,
  });
});

exports.changePassword = BigPromise(async (req, res, next) => {
  const userId = req.user.id;
  const user = await User.findById(userId).select("+password");

  const isCorrectOldPassword = await user.isvalidatedPassword(
    req.body.oldPassword
  );

  if (!isCorrectOldPassword) {
    return next(new Error("Old password is incorrect"));
  }

  user.password = req.body.password;

  await user.save();

  // since information has been changed, kind of necessary to go ahead & change the token
  cookieToken(user, res);
});

exports.updateUserDetails = BigPromise(async (req, res, next) => {
  // check for email & name in body
  if (!req.body.name || !req.body.email) {
    return next(new Error("Name and Email should be there"));
  }

  const newData = {
    name: req.body.name,
    email: req.body.email,
  };

  if (req.files) {
    const user = await User.findById(req.user.id);

    const imageId = user.photo.id;

    // delete photo from cloudinary
    const resp = await cloudinary.v2.uploader.destroy(imageId);

    // upload new photo on cloudinary
    const result = await cloudinary.v2.uploader.upload(
      req.files.photo.tempFilePath,
      {
        folder: "users",
        width: 150,
        crop: "scale",
      }
    );

    newData.photo = {
      id: result.public_id,
      secure_url: result.secure_url,
    };
  }

  const user = await User.findByIdAndUpdate(req.user.id, newData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });

  res.status(200).json({
    success: true,
  });
});

exports.adminAllUsers = BigPromise(async (req, res, next) => {
  const users = await User.find({}); // array of all the values it found in DB

  res.status(200).json({
    success: true,
    users,
  });
});

exports.admingetOneUser = BigPromise(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    next(new Error("No user found"));
  }

  res.status(200).json({
    success: true,
    user,
  });
});

exports.adminUpdateOneUserDetails = BigPromise(async (req, res, next) => {
  // check for email & name in body
  if (!req.body.name || !req.body.email) {
    return next(new Error("Name and Email should be there"));
  }

  const newData = {
    name: req.body.name,
    email: req.body.email,
    role: req.body.role,
  };

  const user = await User.findByIdAndUpdate(req.params.id, newData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });

  res.status(200).json({
    success: true,
  });
});

exports.adminDeleteOneUser = BigPromise(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new Error("No such user found"));
  }

  const imageId = user.photo.idl;

  await cloudinary.v2.uploader.destroy(imageId);

  await user.remove();

  res.status(200).json({
    success: true,
  })

});



exports.managerAllUsers = BigPromise(async (req, res, next) => {
  const users = await User.find({ role: "user" }); // array of all the values it found in DB

  res.status(200).json({
    success: true,
    users,
  });
});
