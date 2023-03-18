const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");

// Model
const User = require("../models/user");

// this function will return you jwt token
const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

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