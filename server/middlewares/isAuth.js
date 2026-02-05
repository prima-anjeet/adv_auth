import jwt from "jsonwebtoken";
import { redisClient } from "../index.js";
import User from "../models/user.js";

const isAuth = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) {
      return res
        .status(403)
        .json({ success: false, message: "Please login first, no token" });
    }

    const decoded = jwt.verify(token, process.env.ACCESS_SECRET_KEY);

    if (!decoded) {
      return res.status(400).json({
        success: false,
        message: "token expired",
      });
    }

    const cacheUser = await redisClient.get(`user:${decoded.id}`);
    if (cacheUser) {
      req.user = JSON.parse(cacheUser);
      return next();
    }

    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    await redisClient.setEx(`user:${user._id}`, 3600, JSON.stringify(user));

    req.user = user;
    return next();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};
export default isAuth;
