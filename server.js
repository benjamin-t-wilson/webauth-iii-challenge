const express = require("express");
const helmet = require("helmet");
const apiRouter = require("./routes/api/apiRouter.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use("/api", apiRouter);

server.get("/", (req, res) => {
  res.status(200).json({ message: "Reporting for duty" });
});

module.exports = server;
