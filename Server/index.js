const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./models/User");

const app = express();

app.use(express.json());
app.use(cors());

// MongoDB connect
mongoose.connect("mongodb://127.0.0.1:27017/authDB")
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// Test route
app.get("/", (req, res) => {
    res.send("API Working");
});

// ================= SIGNUP =================
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // check duplicate email
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.send("Email already registered");
        }

        // password hash
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        res.send("User Registered");

    } catch (error) {
        res.send("Error");
    }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.send("User not found");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.send("Invalid password");
        }

        // JWT token generate
        const token = jwt.sign({ id: user._id }, "secretkey", {
            expiresIn: "1h"
        });

        res.json({
            message: "Login Successful",
            token: token
        });

    } catch (error) {
        res.send("Error");
    }
});

// ================= AUTH MIDDLEWARE =================
const authMiddleware = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.send("Access Denied");
    }

    try {
        const verified = jwt.verify(token, "secretkey");
        req.user = verified;
        next();
    } catch (err) {
        res.send("Invalid Token");
    }
};

// ================= PROTECTED ROUTE =================
app.get("/profile", authMiddleware, (req, res) => {
    res.send("Welcome to your profile");
});

// Server start
app.listen(5000, () => {
    console.log("Server running on port 5000");
});