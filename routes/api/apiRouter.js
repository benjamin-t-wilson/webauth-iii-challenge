const db = require("./apiHelper.js");
const express = require("express");
const crypt = require("bcryptjs"); // for whatever reason I can never type bcrypt on my first try
const jwt = require("jsonwebtoken");
const secrets = require("../../config/secrets.js"); // external file so in production I can add to the gitignore

const router = express.Router();

router.post("/register", (req, res) => {
  const creds = req.body;

  const hash = crypt.hashSync(creds.password, 8); // hashes the password 8 times
  creds.password = hash; // resets the password to the hashed string, so we don't store sensitive data

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
  db.findBy({ username }) // runs the filter by username
    .then(user => {
      if (user && crypt.compareSync(password, user.password)) {
        // if the resolution is truthy AND the password guess matches stored hash
        let token = generateToken(user); // creates a token using JWT, go to this function
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
  // this is a good candidate to go in an external file and ignored
  // must pass 3 args with .sign, payload, a secret, options obj
  const payload = {
    subject: user.id, // almost always have subject line, refers to ID
    username: user.username // for reference?
    // ... anything else
  };

  const options = {
    expiresIn: "30s" // common option, how long the token lasts
  };
  // note, objects may be passed in line; the following is legal
  // return jwt.sign({subject: user.id}, "Give me something to shoot", {expiresIn: 9000d})
  return jwt.sign(payload, secrets.jwtSecret, options);
}

function tokenAuth(req, res, next) {
  const token = req.headers.authorization;

  if (req.decodedJwt) {
    // if we have a token already decoded
    next();
  } else if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedJwt) => {
      //pass the current token and the secret to check the signature
      if (err) {
        // if an error occurs
        res.status(401).json({ message: "Failed to verify authorization" });
      } else {
        req.decodedJwt = decodedJwt; // set to speed up future auth
        next();
      }
    });
  } else {
    res.status(401).json({ message: "Failed to verify authorization" }); // overall failure
  }
}

module.exports = router;
