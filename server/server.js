const express = require("express");
const app = express();
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const logger = require('morgan');
const cors = require("cors");

require("dotenv").config({ path: "./config.env" });
const port = process.env.PORT || 5000;

app.use(logger('dev'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SEC,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_SESS_URI,
    })
}));
app.use(passport.authenticate('session'));

app.use(require("./routes/auth"));
// get driver connection
const dbo = require("./db/conn");
 
app.listen(port, () => {
  // perform a database connection when server starts
  dbo.connectToServer(function (err) {
    if (err) console.error(err);
 
  });
  console.log(`Server is running on port: ${port}`);
});