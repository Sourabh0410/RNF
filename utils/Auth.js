const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/User");
const { SECRET } = require("../config");

/**
 * @DESC To register the user (Student,Teacher)
 */
const userRegister = async (userDets,role, res) => {
  try {


    // validate the email
    let emailNotRegistered = await validateEmail(userDets.email);
    if (!emailNotRegistered) {
      return res.status(400).json({
        message: `Email is already registered.`,
        success: false
      });
    }

    // Get the hashed password
  
    const password = await bcrypt.hash(userDets.password, 12);
    // create a new user
    const newUser = new User({
      ...userDets,
      password,
    role
    });

    await newUser.save();
    return res.status(201).json({
      message: "Hurry! now you are successfully registred. ",
      success: true
    });
  } catch (err) {
    console.log(err);
   
    return res.status(500).json({
      message: "Unable to create your account.",
      success: false
    });
  }
};

/**
 * @DESC To Login the user (Student, Teacher)
 */
const userLogin = async (userCreds, role, res) => {
try {
  let { email, password, role } = userCreds;
  // First Check if the email is in the database
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({
      message: "Username is not found. Invalid login credentials.",
      success: false
    });
  }
  // We will check the role
  if (user.role !== role) {
    return res.status(403).json({
      message: "Please make sure you are logging in from the right portal.",
      success: false
    });
  }
  // That means user is existing and trying to signin fro the right portal
  // Now check for the password
  let isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    // Sign in the token and issue it to the user
    let token = jwt.sign(
      {
        email: user.email, role: user.role
      },
      SECRET,
      { expiresIn: "1h" }
    );
    user.token = `Bearer ${token}`;
    let result = {
    
      token: `Bearer ${token}`,
     
    };
console.log(user.result.token,"user.token");
   await user.save();

    return res.status(200).json({...result, message: 'Login successful' });

  } else {
    return res.status(401).json({
      message: "Incorrect password.",
      success: false
    });
  }
} catch (error) {
  res.status(500).json({ message: 'Login failed' });
}
 
};



/**
 * @DESC Passport middleware
 */

const userAuth = passport.authenticate("jwt", { session: false });

const checkRole = roles => (req, res, next) => {
console.log("INSIDE checkRole")
  res.authorizes = req.user.role
  console.log("req.user.role",req.user.role,"roles",roles);
  if (!roles.includes(req.user.role)) {
    return res.status(401).json("Unauthorized");
  }
  next();
};



const validateEmail = async email => {
  let user = await User.findOne({ email });
  return user ? false : true;
};




const refreshToken = async (token, res) => {
  try {
    // Validate the token
   token = token.split(' ')[1]
    console.log(token);
    const decodedToken = jwt.verify(token, SECRET);
    if (!decodedToken) {
      return res.status(401).json({
        message: "Invalid token",
        success: false
      });
    }

    // Find the user by email and update the token
    const user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
        success: false
      });
    }
console.log("3456789",user);
    // Generate a new token
    const newToken = jwt.sign(
      {
        email: user.email,
        role: user.role
      },
      SECRET,
      { expiresIn: "1h" }
    );

    // Update the token in the user collection
  
    user.token = `Bearer ${newToken}`;
    await user.save();

    return res.status(200).json({
      token: `Bearer ${newToken}`,
      message: "Token refreshed successfully",
      success: true
    });
  } catch (error) {
    console.log("2345678",error);
    return res.status(500).json({
      message: "Token refresh failed",
      success: false
    });
  }
};


const getStudents = async (req,res)=>{
try {
const Users = await User.find({role:'student'});
res.status(200).json({ Users, message: 'Students retrieved successfully' });
} catch (error) {
console.error('Get Users error:', error);
return res.status(403).json({ message: 'Access forbidden' });
}
}

const getTeachers = async (req,res)=>{
  try {
  const Users = await User.find({role:'teacher'});
  res.status(200).json({ Users, message: 'Teacher retrieved successfully' });
  } catch (error) {
  console.error('Get Users error:', error);
  return res.status(403).json({ message: 'Access forbidden' });
  }
  }
module.exports = {
  userAuth,
  checkRole,
  userLogin,
  userRegister,
 
  refreshToken,
  getStudents,
  getTeachers
};
