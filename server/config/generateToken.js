import jwt from "jsonwebtoken";
import { redisClient } from "../index.js";
import { clearCsrfToken, generateCsrfToken } from "./csrfMiddleware.js";
export const generateToken = async (id, res) => {
  const accessToken = jwt.sign({ id }, process.env.ACCESS_SECRET_KEY, {
    expiresIn: "2m",
  });

  const refreshToken = jwt.sign({ id }, process.env.REFRESH_SECRET_KEY, {
    expiresIn: "7d",
  });

  const refreshTokenKey = `refresh_token:${id}`;

  // node-redis v4 setEx signature: setEx(key, ttl, value)
  await redisClient.setEx(refreshTokenKey, 7 * 24 * 60 * 60, refreshToken); // 7 days expiration

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: true, // set to true if using https
    sameSite: "none",
    maxAge: 2 * 60 * 1000, // 2 minutes
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true, // set to true if using https
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 day
  });
 const csrfToken = await generateCsrfToken(id, res);
  return { accessToken, refreshToken ,csrfToken};
};

export const verifyRefreshToken = async (refreshToken) => {
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY);
    const refreshTokenKey = `refresh_token:${decoded.id}`;

    const storedRefreshToken = await redisClient.get(refreshTokenKey);

    if (storedRefreshToken !== refreshToken) {
      throw new Error("Invalid refresh token");
    }
    return decoded;
  } catch (error) {
    throw new Error("Invalid or expired refresh token");
  }
};

export const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.ACCESS_SECRET_KEY, {
    expiresIn: "1m",
  });
};

export const clearTokens = async (id, res) => {
  const refreshTokenKey = `refresh_token:${id}`;
  await redisClient.del(refreshTokenKey);
  await clearCsrfToken(id);
}