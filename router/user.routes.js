// Config express to crete routers server
const router = require("express").Router();

// Encrypt password
const bcrypt = require("bcryptjs");
const salt_rounds = 10;

// User structure
const UserModel = require("../models/User.model");

// Create Token for user logged
const generateToken = require("../config/jwt.config");

// User Auth
const isAuthenticated = require("../middlewares/isAuthenticated");
const attachCurrentUser = require("../middlewares/attachCurrentUser");

router.post("/signup", async (req, res) => {
  try {
    const { password, email } = req.body;

    // Password validation
    if (
      !password ||
      !password.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$/)
    ) {
      return res.status(400).json({
        msg: "Password is required and must have at least 8 characters, uppercase and lowercase letters and numbers.",
      });
    }

    // E-mail validation
    if (!email || !email.match(/[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+/gm)) {
      return res.status(400).json({
        msg: "Invalid E-mail",
      });
    }

    // Searching for email, if email already existed in the DB, back-end will send error message.
    const userEmail = await UserModel.findOne({ email });

    if (userEmail) {
      return res.status(404).json({ msg: "Email address is already in use." });
    }

    // Password encryption
    // The higher salt is the more time the hashing takes, I select a number that is high enough to prevent attacks, but not slower than potential user patience. I'm using default value, 10.
    const salt = await bcrypt.genSalt(salt_rounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Saving email and password in DB
    const result = await UserModel.create({
      ...req.body,
      passwordHash: hashedPassword,
    });

    return res.status(201).json(result);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

router.post("/login", async (req, res) => {
  try {
    // Request email and password from body.
    const { email, password } = req.body;

    // Searching for user email.
    const user = await UserModel.findOne({ email });

    // If user email does not existed, that means user is not registered.
    // Validating email.
    if (
      !email ||
      !user ||
      !email.match(/[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+/gm)
    ) {
      return res.status(400).json({
        msg: "Invalid email address or password.",
      });
    }

    // Password validating if is null or undefined
    if (!password) {
      return res.status(400).json({
        msg: "Invalid email address or password.",
      });
    }

    // unHash password from DB, to compare both password
    if (await bcrypt.compare(password, user.passwordHash)) {
      // If password is OK, will generate new token using TWJ Auth
      const token = generateToken(user);

      return res.status(200).json({
        user: {
          name: user.name,
          email: user.email,
          _id: user._id,
        },
        token,
      });
    } else {
      return res.status(401).json({
        msg: "Invalid email address or password.",
      });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

// Reset password
// to reset password user needs to be logged, to check if user is logged I create "isAuthenticated" to check user permission and attachCurrentUser to current user data.
router.post(
  "/password-reset",
  isAuthenticated,
  attachCurrentUser,
  async (req, res) => {
    try {
      // Request current password and new password from body.
      const { currentPassword, newPassword, confirmPassword } = req.body;

      // Search for logged user using email.
      const loggedInUser = req.currentUser.email;
      const user = await UserModel.findOne({ loggedInUser });

      // If some field is empty error message will be send
      if (!currentPassword || !confirmPassword || !newPassword) {
        return res.status(400).json({
          msg: "All fields is require.",
        });
      }

      // Checking is new password and confirm password is a valid password
      if (
        !confirmPassword.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$/) ||
        !newPassword.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$/)
      ) {
        return res.status(400).json({
          msg: "New password and confirm password must have at least 8 characters, uppercase and lowercase letters, and numbers.",
        });
      }

      // Checking is confirm password and new password match
      if (confirmPassword != newPassword) {
        return res.status(400).json({
          msg: "New password and confirm password must be match.",
        });
      }

      // If current password is match with new password or confirm password will be send error message
      if (
        currentPassword === newPassword ||
        currentPassword === confirmPassword
      ) {
        return res.status(400).json({
          msg: "Your new password cannot be the same as your current password.",
        });
      }

      // Comparing current password with user password stored in DB.
      if (await bcrypt.compare(currentPassword, user.passwordHash)) {
        // If both password match, I will create saltRounds to hash password.
        // The higher salt is the more time the hashing takes, I select a number that is high enough to prevent attacks, but not slower than potential user patience. I I'm using default value, 10.
        const salt = await bcrypt.genSalt(salt_rounds);

        // hashed password
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Updating user password.
        const response = await UserModel.findByIdAndUpdate(
          { _id: user._id },
          { passwordHash: hashedPassword }
        );
        console.log("response findUser -> ", response);
        return await res.status(200).json(response);
      } else {
        // If current password does not match, will be send error message.
        return res.status(401).json({
          msg: "try again, that is not your current password.",
        });
      }
    } catch (err) {
      console.log(err);
      return res.status(404).json({ msg: JSON.stringify(err) });
    }
  }
);

// If user is logged, user will be able to see his profile.
// isAuthenticated: is User Authorized
// attachCurrentUser: Current User logged data.
router.get("/profile", isAuthenticated, attachCurrentUser, (req, res) => {
  try {
    // Requesting current user logged data
    const loggedInUser = req.currentUser;

    // If user is logged, user will be able to see his profile.
    if (loggedInUser) {
      return res.status(200).json(loggedInUser);
    } else {
      // If user is not logged, user will not be able to see his profile.
      return res.status(404).json({ msg: "User not found." });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

module.exports = router;
