require("dotenv").config();
const connectDB = require("./config/db");
connectDB();
const jwt = require("jsonwebtoken");
const cors = require("cors");
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const User = require("./models/User");
const SECRET_KEY = process.env.JWT_SECRET;  

function authenticateToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if(!authHeader) {

        return res.status(401).json({
            message: "Access Denied"
        });
    }

    const token = authHeader.split(" ")[1];

    try {

        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified;
        next();

    } catch(error) {

        return res.status(403).json({
            message: "Invalid token"
        });
    }
}

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Server is running");
});

app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    console.log("Email:", email);
    console.log("Password:", password);

    if (!email || !password) {
        return res.status(400).json({
            message: "All fields are required"
        });
    }

    const user = await User.findOne({email});

    if (!user) {

        return res.status(401).json({
            message: "User not found!",
        });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {

        return res.status(401).json({
            message: "Incorrect password",
        });
    }

    const token = jwt.sign(
        {email: user.email},
        SECRET_KEY,
        {expiresIn: "1h"}
    );

    return res.status(200).json({
        message: "Login successfully",
        token
    });

});

app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "All fields are required"
        });
    }

    const existingUser = await User.findOne({email});

    if (existingUser) {
        return res.status(409).json({
            message: "Email already registered"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        email,
        password: hashedPassword
    }

    await User.create(newUser);
    console.log("Registered Users:", newUser);

    return res.status(201).json({
        message: "Registration successful",
    })

});

app.get("/profile", authenticateToken, function(req, res) {

        res.status(200).json({
            message: "Protected profile data",
            user: req.user
        });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {

    console.log(`Server is running on port ${PORT}`);
});