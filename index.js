"use strict";

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const morgan = require('morgan');
const jwt    = require('jsonwebtoken');

const config = require('./config');

const app = express();

app.set('Secret', config.secret);
app.use(morgan('dev'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.raw());

const MongoClient = require('mongodb').MongoClient;

let db;

MongoClient.connect('mongodb://localhost:27017/exampleDb',{ useUnifiedTopology: true }, (err, client) => {
  if (!err) {
    db = client.db('testrun');
    console.log('MongoDB is connected!');
  } else {
    return console.log(err);
  };
});

app.get('/', (req, res) => {
  res.status(200).json({ 
    message: "API for the future!",
    endpoint: "/",
    get: [ "/", "/user" ]
   });
});

app.get('/user', (req, res) => {
  res.status(200).json({ 
    message: "User methods that are available.",
    endpoint: "/user",
    post: [ "register", "login", "verify", "delete" ]
  });
});

app.post('/user/register', (req, res) => {
  let errors = [];
  
  let username;
  let password;

  if (!req.body.username) {
    errors.push("Username was missing from query.");
  } else {
    username = req.body.username;
  };
  if (!req.body.password) {
    errors.push("Password was missing from query.");
  } else {
    password = req.body.password;
  };

  if (errors && errors.length) {
    res.status(400).json({ method: "register", status: "failure", data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, results) => {
      if (results != null) {
        errors.push("Username is already registered.");
      } else {
        let hash = bcrypt.hashSync(password, 10);
        let token = jwt.sign({ check: true }, app.get('Secret'), { expiresIn: 1440 });
        let user = { "username": username, "password": hash, created: Date.now(), token: token  };
        db.collection('users').insertOne(user, (err, result) => {
          res.status(201).json({ method: "register", status: "success", data: result["ops"] });
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "register", status: "failure", data: errors });
      };
    });
  };
});

app.post('/user/login', (req, res) => {
  let errors = [];

  let username;
  let password;

  if (!req.body.username) {
    errors.push("Username was missing from query.");
  } else {
    username = req.body.username;
  };
  if (!req.body.password) {
    errors.push("Password was missing from query.");
  } else {
    password = req.body.password;
  };

  db.collection('users').findOne({ username: username }, (err, results) => {
    if (results == null) {
      errors.push("User does not exist.");
    }
    if (results != null) {
      if (errors && errors.length) {
        // [x]
      } else {
        if (!bcrypt.compareSync(password, results.password)) {
          errors.push("Password was incorrect.");
        } else {
          jwt.verify(results.token, app.get('Secret'), (err, decoded) => {
            if (!err) {
              res.status(201).json({ method: "login", status: "success", data: results });
            } else {
              let newtoken = jwt.sign({ check: true }, app.get('Secret'), { expiresIn: 1440 });
              // Occasionally token will need updated.
              db.collection('users').updateOne({ _id: results._id }, { $set: { token: newtoken } }, { upsert: true }, (err, updated) => {
                res.status(201).json({ method: "login", status: "success", updated: newtoken });
              });
            };
          });
        };
      };
    };
    if (errors && errors.length) {
      res.status(400).json({ method: "login", status: "failure", data: errors });
    };
  });
});

app.post('/user/verify', (req, res) => {
  let errors = [];

  let username;
  let token;

  if (!req.body.username) {
    errors.push("Username was missing from query.");
  } else {
    username = req.body.username;
  };
  if (!req.body.token) {
    errors.push("Token was missing from query.");
  } else {
    token = req.body.token;
  };

  if (errors && errors.length) {
    res.status(400).json({ method: "verify", status: "failure", data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, results) => {
      if (results == null) {
        errors.push("User does not exist.");
      } else {
        jwt.verify(token, app.get('Secret'), (err, decoded) => {
          if (err && err.name == "TokenExpiredError") {
            errors.push("Token has expired."); //?
          };
          if (err && err.name == "JsonWebTokenError") {
            errors.push("Invalid token provided.");
          };
          if (decoded && decoded.check == true) {
            res.status(200).json({ method: "verify", status: "success", data: results, verified: decoded });
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "verify", status: "failure", data: errors });
      };
    });
  };
});

app.post('/user/delete', (req, res) => {
  let errors = [];

  let username;
  let token;

  if (!req.body.username) {
    errors.push("Username was missing from query.");
  } else {
    username = req.body.username;
  };
  if (!req.body.token) {
    errors.push("Token was missing from query.");
  } else {
    token = req.body.token;
  };

  if (errors && errors.length) {
    res.status(400).json({ method: "delete", status: "failure", data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, results) => {
      if (results == null) {
        errors.push("User does not exist.");
      } else {
        jwt.verify(token, app.get('Secret'), (err, decoded) => {
          if (err && err.name == "TokenExpiredError") {
            errors.push("Token has expired."); //?
          };
          if (err && err.name == "JsonWebTokenError") {
            errors.push("Invalid token provided.");
          };
          if (decoded && decoded.check == true) {
            db.collection('users').deleteOne({ _id: results._id }, (err, deleted) => {
              res.status(200).json({ method: "delete", status: "success", data: results});
            });
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "delete", status: "failure", data: errors });
      };
    });
  };
});

app.listen(8080, () => {
  console.log(`Webserver started at http://localhost:8080!`);
});