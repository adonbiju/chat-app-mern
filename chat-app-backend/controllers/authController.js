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