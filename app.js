// .env
require("dotenv").config();

// Express Config
const express = require("express");
const app = express();
app.use(express.json());

// Executing Cors
const cors = require("cors");
app.use(cors({ origin: process.env.REACT_APP_URL }));

// Config and calling MongoDB
require("./config/db.config")();

// User Router
const userRouter = require("./router/user.routes");
app.use("/", userRouter);

// Server connection
app.listen(Number(process.env.PORT), () =>
  console.log(`Server up and running at port ${process.env.PORT}`)
);
 