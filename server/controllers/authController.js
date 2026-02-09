import TryCatch from "../middlewares/TryCatch.js";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import sanitize from "mongo-sanitize";
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from "../config/zod.js";
import { redisClient } from "../index.js";
import crypto from "crypto";
import sendEmail from "../config/sendMail.js";
import {
  getOtpHtml,
  getVerifyEmailHtml,
  getResetPasswordHtml,
} from "../config/html.js";
import {
  clearTokens,
  generateAccessToken,
  generateToken,
  verifyRefreshToken,
} from "../config/generateToken.js";
import { refreshCsrfToken } from "../config/csrfMiddleware.js";

const registerUser = TryCatch(async (req, res) => {
  const sanitizedBody = sanitize(req.body);
  // Validate input using Zod schema
  const parseResult = registerSchema.safeParse(sanitizedBody);
  if (!parseResult.success) {
    const zodErrors = parseResult.error.flatten().fieldErrors;
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: zodErrors,
    });
  }
  const { username, email, password } = parseResult.data;

  // Rate limiting (IP based to prevent spam)
  const ipRateLimitKey = `register_ip_limit:${req.ip}`;
  if (redisClient && (await redisClient.get(ipRateLimitKey))) {
    return res.status(429).json({
      success: false,
      message:
        "Too many registration attempts from this IP. Please try again later.",
    });
  }

  const ratelimitKey = `register_rate_limit:${req.ip}:${email}`;

  if (redisClient && (await redisClient.get(ratelimitKey))) {
    return res.status(429).json({
      success: false,
      message:
        "Too many registration attempts for this email. Please try again later.",
    });
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: "User with this email already exists.",
    });
  }
  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  // verify token
  const verifyToken = crypto.randomBytes(32).toString("hex");
  const verifyKey = `verify_token:${verifyToken}`;

  const dataToStore = JSON.stringify({
    username,
    email,
    password: hashedPassword,
  });
  if (redisClient) {
    await redisClient.set(verifyKey, dataToStore, { EX: 300 }); // Expires in 5 minutes
  }

  const subject = "Verify your email";
  const html = getVerifyEmailHtml({ email, token: verifyToken });

  await sendEmail(email, subject, html);

  // Set rate limit key with expiration of 60 seconds
  if (redisClient) {
    await redisClient.set(ratelimitKey, "true", { EX: 60 });
    await redisClient.set(ipRateLimitKey, "true", { EX: 60 });
  }

  return res.json({
    message: "Please verify your email to activate your account.",
  });
});

const verifyUser = TryCatch(async (req, res) => {
  const { token } = req.params;
  const verifyKey = `verify_token:${token}`;
  if (!redisClient) {
    return res.status(500).json({
      success: false,
      message: "Internal server error. Please try again later.",
    });
  }

  const userData = await redisClient.get(verifyKey);
  if (!userData) {
    return res.status(400).json({
      success: false,
      message: "Invalid or expired verification Link.",
    });
  }

  const { username, email, password } = JSON.parse(userData);

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: "User with this email already exists.",
    });
  }

  const newUser = await User.create({
    username,
    email,
    password,
  });

  await redisClient.del(verifyKey);

  return res.json({
    success: true,
    message: "Email verified successfully. You can now log in.",
    user: {
      id: newUser._id,
      username: newUser.username,
      email: newUser.email,
    },
  });
});

const loginUser = TryCatch(async (req, res) => {
  const sanitizedBody = sanitize(req.body);
  // Validate input using Zod schema
  const parseResult = loginSchema.safeParse(sanitizedBody);

  if (!parseResult.success) {
    const zodErrors = parseResult.error.flatten().fieldErrors;
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: zodErrors,
    });
  }

  const { email, password } = parseResult.data;

  // Security: Check brute force limits
  const ipFailKey = `login_fail_ip:${req.ip}`;
  const userFailKey = `login_fail_user:${email}`;

  const [ipFails, userFails] = await Promise.all([
    redisClient.get(ipFailKey),
    redisClient.get(userFailKey),
  ]);

  if (
    (ipFails && parseInt(ipFails) > 20) ||
    (userFails && parseInt(userFails) > 5)
  ) {
    return res.status(429).json({
      success: false,
      message: "Too many failed login attempts. Try again later.",
    });
  }

  const ratelimitKey = `login_rate_limit:${req.ip}:${email}`;

  if (await redisClient.get(ratelimitKey)) {
    return res.status(429).json({
      success: false,
      message: "Too many login attempts. Please try again later.",
    });
  }
  const user = await User.findOne({ email });

  // Timing attack protection: Always compare hash
  const dummyHash =
    "$2b$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
  const isPasswordValid = await bcrypt.compare(
    password,
    user ? user.password : dummyHash,
  );

  if (!user || !isPasswordValid) {
    // Record Failure
    await redisClient.incr(ipFailKey);
    await redisClient.expire(ipFailKey, 900); // 15m
    await redisClient.incr(userFailKey);
    await redisClient.expire(userFailKey, 900);

    return res.status(400).json({
      success: false,
      message: "Invalid email or password.",
    });
  }

  // Success - clear failure count for user
  await redisClient.del(userFailKey);

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const otpKey = `otp:${email}`;
  await redisClient.set(otpKey, otp, { EX: 300 }); // Expires in 5 minutes

  const subject = "Your Login OTP";
  const html = getOtpHtml({ email, otp });

  // Send OTP email (note: helper expects positional args)
  await sendEmail(email, subject, html);

  // Set rate limit key with expiration of 60 seconds
  await redisClient.set(ratelimitKey, "true", { EX: 60 });

  res.json({
    success: true,
    message: "OTP sent to your email. Please verify to complete login.",
  });
});

const verifyOtp = TryCatch(async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      message: "Email and OTP are required.",
    });
  }

  // Rate Limiting for OTP
  const attemptsKey = `verify_otp_attempts:${email}`;
  const attempts = await redisClient.get(attemptsKey);
  if (attempts && parseInt(attempts) > 5) {
    await redisClient.del(`otp:${email}`); // Invalidate OTP
    return res.status(429).json({
      success: false,
      message: "Too many failed attempts. Please login again.",
    });
  }

  const otpKey = `otp:${email}`;
  const storedOtpString = await redisClient.get(otpKey);

  if (!storedOtpString) {
    return res.status(400).json({
      success: false,
      message: "expired OTP.",
    });
  }

  const storedOtp = storedOtpString.trim();
  const providedOtp = String(otp).trim();

  if (storedOtp !== providedOtp) {
    await redisClient.incr(attemptsKey);
    await redisClient.expire(attemptsKey, 600); // 10 minutes
    return res.status(400).json({
      success: false,
      message: "Invalid OTP.",
    });
  }

  await redisClient.del(attemptsKey); // Clear attempts
  await redisClient.del(otpKey);

  const user = await User.findOne({ email });
  const tokenData = await generateToken(user._id, res);

  return res.json({
    success: true,
    message: "Login successful.",
    user,
  });
});

const myProfile = TryCatch(async (req, res) => {
  const myuser = req.user;
  return res.json({
    success: true,
    user: myuser,
  });
});

const refreshToken = TryCatch(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res
      .status(403)
      .json({ success: false, message: "Please login first, no token" });
  }
  const decoded = await verifyRefreshToken(refreshToken);
  if (!decoded) {
    return res.status(400).json({
      message: "Invalid or expired refresh token",
    });
  }

  const accessToken = generateAccessToken(decoded.id);

  // Set new access token cookie so isAuth can read it
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: 2 * 60 * 1000, // 2 minutes
  });

  return res.status(200).json({
    message: "Access token generated successfully",
    accessToken,
  });
});

const logoutUser = TryCatch(async (req, res) => {
  const userId = req.user._id;
  await clearTokens(userId, res);
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.clearCookie("csrfToken");
  await redisClient.del(`user:${userId}`);
  return res.json({
    success: true,
    message: "Logged out successfully.",
  });
});

const refreshCsrf = TryCatch(async (req, res) => {
  const userId = req.user._id;
  const newCsrfToken = await refreshCsrfToken(userId, res);
  return res.json({
    success: true,
    message: "CSRF token refreshed successfully.",
    csrfToken: newCsrfToken,
  });
});

const forgotPassword = TryCatch(async (req, res) => {
  const sanitizedBody = sanitize(req.body);
  const parseResult = forgotPasswordSchema.safeParse(sanitizedBody);
  if (!parseResult.success) {
    const zodErrors = parseResult.error.flatten().fieldErrors;
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: zodErrors,
    });
  }

  const { email } = parseResult.data;

  // Rate Limiting
  const rateLimitKey = `forgot_password_limit:${req.ip}`;
  const isRateLimited = await redisClient.get(rateLimitKey);
  if (isRateLimited) {
    return res.status(429).json({
      success: false,
      message: "Too many requests. Please try again later.",
    });
  }
  await redisClient.set(rateLimitKey, "true", { EX: 60 });

  const user = await User.findOne({ email });
  // Always return success to prevent Email Enumeration
  if (!user) {
    return res.json({
      success: true,
      message:
        "If an account with that email exists, we have sent a password reset link.",
    });
  }

  const resetToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Store Hashed Token
  const resetKey = `reset_token:${hashedToken}`;
  await redisClient.set(resetKey, user._id.toString(), { EX: 15 * 60 }); // 15 mins

  const subject = "Reset Your Password";
  const html = getResetPasswordHtml({ email, token: resetToken });
  await sendEmail(email, subject, html);

  return res.json({
    success: true,
    message:
      "If an account with that email exists, we have sent a password reset link.",
  });
});

const resetPassword = TryCatch(async (req, res) => {
  const sanitizedBody = sanitize(req.body);
  const parseResult = resetPasswordSchema.safeParse(sanitizedBody);

  if (!parseResult.success) {
    return res
      .status(400)
      .json({ success: false, message: "Validation failed" });
  }

  const { token, password } = parseResult.data;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const resetKey = `reset_token:${hashedToken}`;

  const userId = await redisClient.get(resetKey);
  if (!userId) {
    return res.status(400).json({
      success: false,
      message: "Invalid or expired password reset token",
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await User.findByIdAndUpdate(userId, { password: hashedPassword });

  // Invalidate sessions and token
  await redisClient.del(resetKey);
  await clearTokens(userId, res);
  await redisClient.del(`user:${userId}`);
  await redisClient.del(`refresh_token:${userId}`);

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.clearCookie("csrfToken");

  return res.json({
    success: true,
    message:
      "Password reset successfully. Please login with your new password.",
  });
});

const resendOtp = TryCatch(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email is required.",
    });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({
      success: false,
      message: "User not found.",
    });
  }

  const ratelimitKey = `resend_otp_limit:${req.ip}:${email}`;
  if (await redisClient.get(ratelimitKey)) {
    return res.status(429).json({
      success: false,
      message: "Please wait before resending OTP.",
    });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpKey = `otp:${email}`;

  await redisClient.set(otpKey, otp, { EX: 300 }); // Expires in 5 minutes

  const subject = "Your New Login OTP";
  const html = getOtpHtml({ email, otp });

  await sendEmail(email, subject, html);

  // Set rate limit for 60 seconds
  await redisClient.set(ratelimitKey, "true", { EX: 60 });

  return res.json({
    success: true,
    message: "OTP resent successfully.",
  });
});

export {
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
};
