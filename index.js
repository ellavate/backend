const express = require("express");
const helmet = require("helmet");
// const knex = require("knex");
// const dbConfig = require("./knexfile");
const cors = require("cors");
// const bcrypt = require("bcryptjs");
// const jwt = require("jsonwebtoken");
require("dotenv").config();

const server = express();
// const db = knex(dbConfig.development);

server.use(cors());
server.use(express.json());
server.use(helmet());
server.set("port", process.env.PORT || 8000);

server.get("/", (req, res) => {
  res.status(200).json("API is running");
});

server.listen(server.get("port"), () => {
  console.log("== LISTENING ON PORT", server.get("port"), "==");
});
