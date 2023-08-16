import express from "express";
import path from 'path'
import mongoose from 'mongoose'
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt';

// Connecting with MongoDB
mongoose.connect("mongodb://localhost:27017", {
    dbName: "backend"
}).then(() => console.log("Database Connected"))
    .catch((e) => console.log(e));

// Creating Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password:String
});

// Creating Model
const User = mongoose.model("User", userSchema);

const app = express()

// Using Middleware
app.use( express.static( path.join( path.resolve(), "public" ) ) );
app.use( express.urlencoded( { extended: true } ) );
app.use( cookieParser() );

app.set("view engine", "ejs");

const isAuthenticated = async(req, res,next) => {
        const { token } = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, "kjsdkfndsf");
        req.user = await User.findById(decoded._id);
        next();
    } else {
        res.redirect("/login");
    }
}

app.get("/", isAuthenticated, (req, res) => {
    res.render("logout",{name:req.user.name})
});

app.get("/register", (req, res) => {
    res.render("register")
});

app.get("/login", (req, res) => {
    res.render("login")
});

// Login Function
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    let user = await User.findOne({ email });
    if (!user) return res.redirect("/register");

    const isMatch = bcrypt.compare(password, user.password)
    if (!isMatch) return res.render("login", { email: email, message: "Incorrect Password" });
        
    const token = jwt.sign({ _id: user._id }, "kjsdkfndsf")
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date( Date.now() + 60 * 1000 )
    });
    res.redirect("/")
})


// Register Function
app.post("/register", async (req, res) => {

    const { name, email ,password} = req.body;
    let user = await User.findOne({ email })

    if (user) return res.redirect("/login");

    // Password Hashing using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Creating user
    user = await User.create({ name, email, password:hashedPassword });
    
    const token = jwt.sign({ _id: user._id }, "kjsdkfndsf")
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date( Date.now() + 60 * 1000 )
    });
    res.redirect("/")
});

// Logout Function
app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date( Date.now())
    });
    res.redirect("/")
});

app.listen(5000, () => {
    console.log('Server is working');
})