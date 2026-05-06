import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import morgan from "morgan";
import dbConnection from "./utils/index.js";
import { errorHandler, routeNotFound } from "./middlewares/errorMiddlewares.js";

import routes from "./routes/index.js"

dotenv.config()

const PORT = process.env.PORT || 5000 
const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:3001",
    /^https:\/\/.*\.vercel\.app$/,
    ...((process.env.CORS_ORIGIN || "")
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean)),
];

const app = express();

app.use(
    cors({
        origin: allowedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
    })
);

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ limit: "5mb", extended: true }));

app.use(cookieParser());
app.use(morgan("dev"));
app.use("/api", routes)

app.use(routeNotFound);
app.use(errorHandler);

const startServer = async () => {
    try {
        await dbConnection();
        app.listen(PORT, ()=> console.log(`Server listening on ${PORT}`));
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
};

startServer();
