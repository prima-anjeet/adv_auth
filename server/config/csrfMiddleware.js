import crepto from "crypto";
import { redisClient } from "../index.js";

export const generateCsrfToken = async (userId, res) => {
  const csrfToken = crepto.randomBytes(32).toString("hex");

  const csrfKey = `csrf:${userId}`;
  await redisClient.setEx(csrfKey, 60 * 60, csrfToken); // 1 hour expiration
  res.cookie("csrfToken", csrfToken, {
    httpOnly: false,
    secure: true, // set to true if using https
    sameSite: "none",
    maxAge: 60 * 60 * 1000, // 1 hour
  });
  return csrfToken;
};

export const verifyCsrfToken = async (req, res, next) => {
  try {
    if (
      req.method === "GET" ||
      req.method === "HEAD" ||
      req.method === "OPTIONS"
    ) {
      return next();
    }
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ message: "User not authenticated" });
    }
    const clientCsrfToken =
      req.headers["x-csrf-token"] ||
      req.headers["csrf-token"] ||
      req.headers["x-xsrf-token"];
     if (!clientCsrfToken) {
      return res.status(403).json({ message: "CSRF token missing. Please refresh the page",code:"CSRF_TOKEN_MISSING" });
    }
    const csrfKey = `csrf:${userId}`;
    const storedCsrfToken = await redisClient.get(csrfKey);
    if (!storedCsrfToken) {
      return res.status(403).json({ message: "CSRF token expired.",code:"CSRF_TOKEN_EXPIRED" });
    }
    if (storedCsrfToken !== clientCsrfToken) {
      return res.status(403).json({ message: "Invalid CSRF token. Please refresh the page",code:"CSRF_TOKEN_INVALID" });
    }
    next();
  } catch (error) {
    console.error("CSRF token verification failed:", error);
    return res.status(500).json({ message: "CSRF token verification failed",code:"CSRF_VERIFICATION_ERROR" });
  }
};

export const clearCsrfToken = async (userId) => {
  const csrfKey = `csrf:${userId}`;
  await redisClient.del(csrfKey);
};

export const refreshCsrfToken = async (userId, res) => {
   await clearCsrfToken(userId);
  return await generateCsrfToken(userId, res);
};
