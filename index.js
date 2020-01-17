"use strict";

/**
 * A backend API for a future development.
 */

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

/**
 * So far there are two collections in the mongoDB.
 * 1. Users (usernames, passwords, profile info, tokens, ect.)
 * 2. Invites (invite codes, sponsor's name, createdat, ect.)
 */

MongoClient.connect('mongodb://localhost:27017/exampleDb',{ useUnifiedTopology: true }, (err, client) => {
  if (!err) {
    db = client.db('testrun');
    console.log('MongoDB is connected!');
  } else {
    return console.log(err);
  };
});

// ./
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: "API for the future!",
    endpoint: "/",
    get: [ "/", "/user" ]
   });
});

// ./user
app.get('/user', (req, res) => {
  db.collection('users').find({}).toArray((err, results) => {
    let userlist = [];
    for (let user in results) {
      userlist.push("/user/profile/" + results[user].username);
    };
    res.status(200).json({
      message: "User methods that are available.",
      endpoint: "/user",
      post: [ "register", "login", "verify", "delete", "invites", "invite", "invitee" ],
      users: userlist
    });
  });
});

// ./user/register
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
        let user = { 
          username: username,
          password: hash,
          created: Date.now(),
          token: token,
        };
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

// ./user/login
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

// ./user/verify
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

// ./user/invitee
app.post('/user/invitee', (req, res) => {
  let errors = [];

  let username;
  let password;
  let invite;

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
  if (!req.body.invite) {
    errors.push("Invite was missing from query.");
  } else {
    invite = req.body.invite;
  };

  if (errors && errors.length) {
    res.status(400).json({ method: "invitee", status: "failure", data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, results) => {
      if (results != null) {
        errors.push("Username is already registered.");
      } else {
        db.collection('invites').findOne({ invite: invite }, (err, results) => {
          if (results) {
            let hash = bcrypt.hashSync(password, 10);
            let token = jwt.sign({ check: true }, app.get('Secret'), { expiresIn: 1440 });
            let user = { 
              username: username,
              password: hash,
              created: Date.now(),
              token: token,
              sponsor: results.sponsor
            };
            db.collection('users').insertOne(user, (err, result) => {
              res.status(201).json({ method: "invitee", status: "success", data: result["ops"] });
            });
          } else {
            errors.push("Invite was not in database.");
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "invitee", status: "failure", data: errors });
      };
    });
  };
});

// ./user/invites
app.post('/user/invites', (req, res) => {
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
    res.status(400).json({ method: "invites", status: "failure", data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, found) => {
      if (found == null) {
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
            db.collection('invites').find({ sponsor: username }).toArray((err, results) => {
              res.status(200).json({ method: "invites", status: "success", invites: results });
            });
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "invites", status: "failure", data: errors });
      };
    });
  };
});

// ./user/invite
app.post('/user/invite', (req, res) => {
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
    res.status(400).json({ method: "invite", status: "failure", data: errors });
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
            let invite = jwt.sign({ check: true }, app.get('Secret'), { expiresIn: 604800 });
            db.collection('invites').insertOne({ sponsor: username,  invite: invite, created: Date.now()  }, (err, inserted) => {
              res.status(200).json({ method: "invite", status: "success", invites: inserted['ops'] });
            });
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "invite", status: "failure", data: errors });
      };
    });
  };
});

// ./user/delete
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
            // delete users collection data
            db.collection('users').deleteOne({ _id: results._id });
            // delete users invite collection data
            db.collection('invites').deleteMany({ sponsor: results.username });
            if (errors.length == 0) {
              res.status(200).json({ method: "delete", status: "success" });
            }
          };
        });
      };
      if (errors && errors.length) {
        res.status(400).json({ method: "delete", status: "failure", data: errors });
      };
    });
  };
});

// ./user/profile/:username
app.get('/user/profile/:username', (req, res) => {
  let errors = [];
  let username;

  if (!req.params.username) {
    errors.push("Username was missing from query.");
  } else {
    username = req.params.username;
  };

  if (errors && errors.length) {
    res.status(400).json({ endpoint: "/user/profile/" + username, success: false, data: errors });
  };

  if (errors.length == 0) {
    db.collection('users').findOne({ username: username }, (err, result) => {
      if (result == null) {
        errors.push("Username does not exist.");
      } else {
        delete(result.password);
        delete(result.token);
        res.status(201).json({ endpoint: "/user/profile/" + username, success: true, data: result });
      };
      if (errors && errors.length) {
        res.status(404).json({ endpoint: "/user/profile/" + username, success: false, data: errors });
      };
    });
  };
});

app.listen(8080, () => {
  console.log(`Webserver started at http://localhost:8080!`);
});