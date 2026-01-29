import jwt from "jsonwebtoken";
import { redisClient } from "../index.js";

const generateToken = async (id, res) => {
  const accessToken = jwt.sign({ userId:id }, process.env.ACCESS_SECRET_KEY, {
    expiresIn: "1m",
  });
 
  const refreshToken = jwt.sign(
    { userId: id },
    process.env.REFRESH_SECRET_KEY,
    { expiresIn: "7d" }
  );

  const refreshTokenKey = `refresh_token:${id}`;

    // node-redis v4 setEx signature: setEx(key, ttl, value)
    await redisClient.setEx(
      refreshTokenKey,7 * 24 * 60 * 60,refreshToken); // 7 days expiration
    res
    .status(200)
    .cookie("accessToken", accessToken, {
      httpOnly: true,
    //   secure: true,// set to true if using https 
      sameSite: "strict",
      maxAge: 1* 60 * 1000, // 1minute
    })

     res
    .status(200)
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
    //   secure: true,// set to true if using https 
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 day
    })
    return { accessToken, refreshToken };
};

export { generateToken };