const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = "test";  // Replace this with your secret key

// User store
let users = {};  // This should be replaced with a proper database


// Sign up route
app.post('/signup', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  users[username] = hashedPassword;
  
  res.status(200).send({ message: f`User created successfully`,username:username, hashedPassword: hashedPassword });
});

// Login route
app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const hashedPassword = users[username];

  if (!hashedPassword) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  const match = await bcrypt.compare(password, hashedPassword);

  if (!match) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

  res.status(200).send({ message: 'Authenticated successfully', token });
});

// JWT middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  
  if (!token) {
    return res.sendStatus(403);
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
  res.status(200).send({ message: 'Protected content', user: req.user });
});

app.listen(3001, () => {
  console.log('Server started on port 3001');
});
