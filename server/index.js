import express from "express";
import dotenv from "dotenv";
dotenv.config();
import connectDB from "./config/db.js";
import { createClient } from "redis";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

app.set("trust proxy", 1); // Trust first proxy (critical for rate limiting behind load balancers)

app.use(express.json());
app.use(cookieParser());

// CORS: normalize origins to handle trailing slash mismatches
const allowedOrigin = (process.env.FRONTEND_URL || "").replace(/\/+$/, "");
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, server-to-server)
      if (!origin) return callback(null, true);
      if (origin.replace(/\/+$/, "") === allowedOrigin) {
        return callback(null, true);
      }
      console.warn(`CORS blocked: ${origin} !== ${allowedOrigin}`);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  }),
);

// Redis setup
const redisUrl = process.env.REDIS_URL;
let redisClient;

if (!redisUrl) {
  console.error(
    "REDIS_URL not provided. Server cannot function without Redis.",
  );
  process.exit(1);
} else {
  redisClient = createClient({
    url: redisUrl,
  });
  redisClient.on("error", (err) => console.error("Redis Client Error:", err));
}

export { redisClient };

// Import routes AFTER redisClient is declared (circular dependency safety)
import authRoutes from "./routes/authRoutes.js";
app.use("/api/v1", authRoutes);

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

// Start server only after all connections are ready
const port = process.env.PORT || 8000;

const startServer = async () => {
  try {
    await connectDB();
    await redisClient.connect();
    console.log("Connected to Redis");

    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
};

startServer();
