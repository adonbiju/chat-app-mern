const jwt = require("jsonwebtoken");

const filterObj = require("../utils/filterObj");

// Model
const User = require("../models/user");

// this function will return you jwt token
const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

exports.register = async (req, res, next) => {
    const { firstName, lastName, email, password } = req.body;
  
    const filteredBody = filterObj(
      req.body,
      "firstName",
      "lastName",
      "email",
      "password"
    );
  
    // check if a verified user with given email exists
  
    const existing_user = await User.findOne({ email: email });
  
    if (existing_user && existing_user.verified) {
      // user with this email already exists, Please login
      res.status(400).json({
        status: "error",
        message: "Email already in use, Please login.",
      });
    } else if (existing_user) {
      // if not verified than update prev one
  
      await User.findOneAndUpdate({ email: email }, filteredBody, {
        new: true,
        validateModifiedOnly: true,
      });
  
      // generate an otp and send to email
      req.userId = existing_user._id;
      next();
    } else {
      // if user is not created before than create a new one
      const new_user = await User.create(filteredBody);
  
      // generate an otp and send to email
      req.userId = new_user._id;
      next();
    }
  };
  
  exports.sendOTP = async (req, res, next) => {
    const { userId } = req;
    const new_otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      specialChars: false,
      lowerCaseAlphabets: false,
    });
  
    const otp_expiry_time = Date.now() + 10 * 60 * 1000; // 10 Mins after otp is sent
  
    await User.findByIdAndUpdate(userId, {
      otp: new_otp,
      otp_expiry_time: otp_expiry_time,
    });
  
    // TODO send mail
  
    res.status(200).json({
      status: "success",
      message: "OTP Sent Successfully!",
    });
  };


  exports.verifyOTP = async (req, res, next) => {
    // verify otp and update user accordingly
    const { email, otp } = req.body;
    const user = await User.findOne({
      email,
      otp_expiry_time: { $gt: Date.now() },
    });
  
    if (!user) {
      res.status(400).json({
        status: "error",
        message: "Email is invalid or OTP expired",
      });
    }
  
    if (!(await user.correctOTP(otp, user.otp))) {
      res.status(400).json({
        status: "error",
        message: "OTP is incorrect",
      });
  
      return;
    }
  
    // OTP is correct
  
    user.verified = true;
    user.otp = undefined;
    await user.save({ new: true, validateModifiedOnly: true });
  
    const token = signToken(user._id);
  
    res.status(200).json({
      status: "success",
      message: "OTP verified Successfully!",
      token,
    });
  };


// User Login
exports.login = async (req, res, next) => {
    const { email, password } = req.body;
  
    // console.log(email, password);
  
    if (!email || !password) {
      res.status(400).json({
        status: "error",
        message: "Both email and password are required",
      });
      return;
    }
  
    const user = await User.findOne({ email: email }).select("+password");
  
    if (!user || !user.password) {
      res.status(400).json({
        status: "error",
        message: "Incorrect password",
      });
  
      return;
    }
  
    if (!user || !(await user.correctPassword(password, user.password))) {
      res.status(400).json({
        status: "error",
        message: "Email or password is incorrect",
      });
  
      return;
    }
  
    const token = signToken(user._id);
  
    res.status(200).json({
      status: "success",
      message: "Logged in successfully!",
      token,
    });
  };

  exports.forgotPassword = async (req, res, next) => {
    // 1) Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return next(new AppError("There is no user with email address.", 404));
    }
  
    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
  
    // 3) Send it to user's email
    try {
      const resetURL = `https://adon.com/auth/reset-password/${resetToken}`;
      // TODO => Send Email with this Reset URL to user's email address
  
      res.status(200).json({
        status: "success",
        message: "Token sent to email!",
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
  
      return next(
        new AppError("There was an error sending the email. Try again later!"),
        500
      );
    }
  };
  