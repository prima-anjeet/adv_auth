import express from "express";
import {
  registerUser,
  verifyUser,
  loginUser,
  verifyOtp,
  resendOtp,
  myProfile,
  refreshToken,
  logoutUser,
  refreshCsrf,
  forgotPassword,
  resetPassword,
} from "../controllers/authController.js";
import isAuth from "../middlewares/isAuth.js";
import { verifyCsrfToken } from "../config/csrfMiddleware.js";
const router = express.Router();

// Registration route
router.post("/register", registerUser);
// Email verification route
router.get("/verify/:token", verifyUser);
// Login route
router.post("/login", loginUser);
// otp verification route
router.post("/verify-otp", verifyOtp);
// resend otp route
router.post("/resend-otp", resendOtp);
// forgot password route
router.post("/forgot-password", forgotPassword);
// reset password route
router.post("/reset-password", resetPassword);
// profile route
router.get("/my-profile", isAuth, myProfile);
// refresh token route
router.get("/refresh-token", refreshToken);
// logout route
router.post("/logout", isAuth, verifyCsrfToken, logoutUser);
// refresh csrf token route
router.post("/refresh-csrf", isAuth, refreshCsrf);
export default router;
