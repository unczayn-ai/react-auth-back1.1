require("dotenv").config();
const cors = require("cors");
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const users = [];

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

    const user = users.find(function(user){
        return user.email === email;
    });

    if (!user) {

        return res.status(401).json({
            message: "User not found!",
            color: "#ef4444"
        });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {

        return res.status(401).json({
            message: "Incorrect password",
            color: "#ef4444"
        });
    }

    return res.status(200).json({
        message: "Login successfully"
    });

});

app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "All fields are required",
            color: "#ef4444"
        });
    }

    const existingUser = users.find(function(user) {
        return user.email === email;
    });

    if (existingUser) {
        return res.status(409).json({
            message: "Email already registered",
            color: "#ef4444"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        email,
        password: hashedPassword
    }

    users.push(newUser);
    console.log("Registered Users:", users);

    return res.status(201).json({
        message: "Registration successful",
    })

});

const PORT = process.env.PORT || 500;

app.listen(PORT, () => {
    console.log("Server is running on port ${PORT}");
});
