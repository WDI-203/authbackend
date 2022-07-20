var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

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
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      res.json({ success: true });
      return;
    }
    res.json({ success: false });
  } catch (e) {
    console.error(e);
    res.json({ success: false });
  }
});

router.get("/hello-auth", (req, res) => {
  res.json({ message: "Hello from auth" });
});

module.exports = router;
