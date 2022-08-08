var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
dotenv.config();

const createUser = async (username, passwordHash) => {
  try {
    const user = {
      username: username,
      password: passwordHash,
      uid: uuid(), // uid stands for User ID. This will be a unique string that we will can to identify our user
    };

    const collection = await blogsDB().collection("users");
    await collection.insertOne(user);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
};

router.post("/register-user", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    const saltRounds = 5; // In a real application, this number would be somewhere between 5 and 10
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);

    res.json({ success: userSaveSuccess });
  } catch (e) {
    console.error(e);
    res.json({ success: false });
  }
});

router.post("/login-user", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const collection = await blogsDB().collection("users");
    const user = await collection.findOne({
      username,
    });

    if (!user) {
      res.json({ success: false, message: "Could not find user." }).status(204);
      return;
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      res
        .json({ success: false, message: "Password was incorrect." })
        .status(204);
      return;
    }

    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const expiration = Math.floor(Date.now() / 1000) + 60 * 60;

    const userType = username.includes("codeimmersives.com") ? "admin" : "user";

    const data = {
      time: new Date(),
      userId: user.uid, // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user
      scope: userType,
    };

    const token = jwt.sign({ data, exp: expiration }, jwtSecretKey);

    res.json({ success: true, token, userType });
    return;
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: e });
  }
});

router.get("/hello-auth", (req, res) => {
  res.json({ message: "Hello from auth" });
});

router.get("/validate-admin", (req, res) => {
  try {
    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = req.header(tokenHeaderKey);
    const verified = jwt.verify(token, jwtSecretKey);
    
    if (!verified) {
        return res.json({ success: false, isAdmin: false });
    }
    
    const userData = verified.data

    if (userData && userData.scope === "admin") {
      return res.json({
        success: true,
        isAdmin: true,
      });
    }

    if (userData && userData.scope === "user") {
      return res.json({ success: true, isAdmin: false });
    }

    throw Error("Access Denied");
  } catch (error) {
    // Access Denied
    return res.status(401).json({ success: false, message: error });
  }
});

module.exports = router;
