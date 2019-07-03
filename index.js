const express = require("express");
const helmet = require("helmet");
const knex = require("knex");
const dbConfig = require("./knexfile");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const server = express();
const db = knex(dbConfig.development);

server.use(cors());
server.use(express.json());
server.use(helmet());
server.set("port", process.env.PORT || 8000);

// Loads secret key fron .env file
const secret = process.env.SECRET;

// Create JWT upon login
function generateToken(user) {
  const payload = {
    email: user.email
  };

  const options = {
    expiresIn: "1hr",
    jwtid: "12345"
  };

  if (secret) return jwt.sign(payload, secret, options);
  return null;
}

// Protected middleware. Verifies JWT upon protected endpoint access
function protected(req, res, next) {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        if (err.name == "TokenExpiredError") {
          res.status(401).json({ message: "Token has expired", error: err });
        } else {
          res.status(401).json({ message: "Bad token", error: err });
        }
      } else {
        req.user = { email: decodedToken.email };

        next();
      }
    });
  } else {
    res.status(401).json({ message: "no token provided" });
  }
}

server.get("/", (req, res) => {
  res.status(200).json("API is running");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  user.password = bcrypt.hashSync(user.password, 16);

  // Check for secret key, valid email, and valid password before
  // inserting new user
  if (!secret) {
    res.status(400).json({ message: "Missing secret key" });
  } else if (user.email.length < 3 || !user.email) {
    res
      .status(400)
      .json({ message: "email must be at least 3 characters long" });
  } else if (user.password.length < 8 || !user.password) {
    res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  } else {
    db("users")
      .where({ email: user.email })
      .then(names => {
        // If email doesn't exist insert new user and return a signed JWT
        if (names.length === 0) {
          db("users")
            .insert(user)
            .then(ids => {
              const id = ids[0];

              db("users")
                .where({ id: id })
                .first()
                .then(user => {
                  const token = generateToken(user);
                  res
                    .status(201)
                    .json({ id: user.id, token, email: user.email });
                })
                .catch(err => {
                  res.status(500).json(err);
                });
            })
            .catch(err => {
              res.status(500).json(err);
            });
        } else {
          res.status(400).json({ message: "The email has already been used" });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).json(err);
      });
  }
});

// Login user. Request body must contain email and password
server.post("/api/login", (req, res) => {
  const creds = req.body;

  if (!creds.email || !creds.password) {
    res.status(400).json({ message: "Both email and password required" });
  } else {
    db("users")
      .where({ email: creds.email })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(creds.password, user.password)) {
          const token = generateToken(user);

          if (token) res.status(200).json({ token, email: user.email });
          else res.status(401).json({ message: "Unauthorized login attempt" });
        } else {
          res.status(400).json({ message: "Incorrect email or password" });
        }
      })
      .catch(err => res.status(500).json(err));
  }
});

// Change password. Request body must contain email, old password,
// and new password. New password must be at least 8 characters
server.put("/api/passchange", protected, (req, res) => {
  let creds = req.body;

  if (!creds.email || !creds.oldPassword || !creds.newPassword) {
    res
      .status(400)
      .json({ message: "Both email and old and new password required" });
  } else if (creds.newPassword.length < 8) {
    res
      .status(400)
      .json({ message: "New password must be at least 8 characters long" });
  } else {
    db("users")
      .where({ email: creds.email })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(creds.oldPassword, user.password)) {
          let newPass = bcrypt.hashSync(creds.newPassword, 8);
          db("users")
            .where({ email: user.email })
            .update({ password: newPass })
            .then(() => {
              res.status(200).json({ message: "Password updated" });
            })
            .catch(err => {
              console.log("inner", err);
              res.status(500).json(err);
            });
        } else {
          res.status(400).json({ message: "Incorrect email or password" });
        }
      })
      .catch(err => {
        console.log("outer", err);
        res.status(500).json(err);
      });
  }
});

// Delete user. Request body must contain email and password
server.delete("/api/userdel", protected, (req, res) => {
  const creds = req.body;

  if (!creds.email || !creds.password) {
    res.status(400).json({ message: "Both email and password required" });
  } else {
    db("users")
      .where({ email: creds.email })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(creds.password, user.password)) {
          db("users")
            .where({ email: creds.email })
            .del()
            .then(deleted => {
              if (deleted > 0)
                res.status(200).json({ message: "User deleted" });
              else res.status(404).json({ message: "User not found" });
            });
        } else {
          res.status(400).json({ message: "Incorrect email or password" });
        }
      })
      .catch(err => res.status(500).json(err));
  }
});

server.listen(server.get("port"), () => {
  console.log("== LISTENING ON PORT", server.get("port"), "==");
});
