import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import { createClient } from "redis";
import cookieParser from "cookie-parser";
const app = express();
import authRoutes from "./routes/authRoutes.js";
import cors from "cors";
dotenv.config();

app.set("trust proxy", 1); // Trust first proxy (critical for rate limiting behind load balancers)

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin:process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  }),
);
app.use("/api/v1", authRoutes);
const port = process.env.PORT || 8000;

connectDB();
const redisUrl = process.env.REDIS_URL;
let redisClient;

if (!redisUrl) {
  console.log("REDIS_URL not provided");
} else {
  redisClient = createClient({
    url: redisUrl,
  });

  redisClient
    .connect()
    .then(() => {
      console.log("Connected to Redis");
    })
    .catch((err) => {
      console.log("Redis connection error:", err);
    });
}

export { redisClient };

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

app.get("/", (req, res) => {
  res.send("Hello, World!");
});
