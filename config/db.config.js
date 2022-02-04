const mongoose = require("mongoose");

async function connect() {
  // MongoDB Config and connection

  try {
    const connection = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to DB: ", connection.connection.name);
  } catch (err) {
    console.error("Database connection error: ", err);
  }
}

module.exports = connect;
