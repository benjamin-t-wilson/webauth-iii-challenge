const db = require("./apiHelper.js");
const express = require("express");
const crypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const secrets = require("../../config/secrets.js");

const router = express.Router();

router.post("/register", (req, res) => {
  const creds = req.body;

  const hash = crypt.hashSync(creds.password, 8);
  creds.password = hash;

  db.addUser(creds)
    .then(id => {
      res.status(201).json(id);
    })
    .catch(err => {
      res.status(500).json({
        message:
          "Error adding new user to database. Make sure username is unique and password is present"
      });
    });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.findBy({ username })
    .then(user => {
      if (user && crypt.compareSync(password, user.password)) {
        let token = generateToken(user);
        res.status(200).json({ message: `Welcome ${user.username}!`, token });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    })
    .catch(err => {
      res.status(500).json({ message: "Error finding user in database" });
    });
});

router.get("/users", tokenAuth, (req, res) => {
  db.getUsers()
    .then(users => {
      res.status(200).json(users);
    })
    .catch(err => {
      res.status(500).json({ message: "Error retrieving users from database" });
    });
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  };

  const options = {
    expiresIn: "30s"
  };

  return jwt.sign(payload, secrets.jwtSecret, options);
}

function tokenAuth(req, res, next) {
  const token = req.headers.authorization;

  if (req.decodedJwt) {
    next();
  } else if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedJwt) => {
      if (err) {
        res.status(401).json({ message: "Failed to verify authorization" });
      } else {
        req.decodedJwt = decodedJwt;
        next();
      }
    });
  } else {
    res.status(401).json({ message: "Failed to verify authorization" });
  }
}

module.exports = router;
