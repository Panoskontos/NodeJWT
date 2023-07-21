require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');


const app = express();
app.use(cors());  // Enable CORS for all routes
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = process.env.SECRET_KEY;

// User store
let users = {
    "test":"$2b$10$HmPBRGNW.12/aK7dOiRMS.CxIHhixA7felUEeJJC6jG5kJAj2SHse",
    "panos":"$2b$10$A0cPqJNfwyvzaKjJZUn0G.N51NN2SfIR6YynCdwOnWtqGBCv59lAu",
    "mata":"$2b$10$rYoBa/S6f9MuYnoU6Gl3ZuIpDG1bMX9fsSrEhBFRTqa9rne/GpArO"
};  // This should be replaced with a proper database


// Sign up route
app.post('/signup', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
  
    users[username] = hashedPassword;
  
    res.status(200).send({ message: 'User created successfully', hashedPassword: hashedPassword });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Error creating user' });
  }
});


// Login route
// also send role
app.post('/login', async (req, res) => {
  const username = req.body.email;
  const password = req.body.password;

  const hashedPassword = users[username];

  if (!hashedPassword) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  const match = await bcrypt.compare(password, hashedPassword);

  if (!match) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1d' });

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

// Unprotected route
app.get('/', (req, res) => {
  res.status(200).send({ message: 'Unrotected content' });
});

//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1hdGEiLCJpYXQiOjE2ODk4MDU2MjgsImV4cCI6MTY4OTg5MjAyOH0.syHaInv5Qreh9GJ360wtBjG-_KLbg2-wgRKJLb50l6o
// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
  res.status(200).send({ message: 'Protected content', user: req.user });
});

app.listen(3001, () => {
  console.log('Server started on port 3001');
});
