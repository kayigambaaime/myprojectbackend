const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

// User registration
const registerUser = async (req, res) => {
  const {
    firstname,
    lastname,
    email,
    role,
    password,
    confirmPassword,
    phone,
  } = req.body;

  // Validate input
  if (
    !firstname ||
    !lastname ||
    !email ||
    !role ||
    !password ||
    !confirmPassword ||
    !phone
  ) {
    return res
      .status(400)
      .json({ success: false, message: 'All fields are required' });
  }

  if (password !== confirmPassword) {
    return res
      .status(400)
      .json({ success: false, message: 'Passwords do not match' });
  }

  try {
    // Check if user already exists
    const checkUserSql = 'SELECT * FROM users WHERE email = ?';
    db.query(checkUserSql, [email], async (err, results) => {
      if (err) {
        console.error('Error checking user:', err);
        return res
          .status(500)
          .json({ success: false, message: 'Database error' });
      }

      if (results.length > 0) {
        return res
          .status(400)
          .json({ success: false, message: 'User already exists' });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Insert new user
      const insertUserSql =
        'INSERT INTO users (firstname, lastname, email, role, phone, hashed_password) VALUES (?, ?, ?, ?, ?, ?)';
      db.query(
        insertUserSql,
        [firstname, lastname, email, role, phone, hashedPassword],
        (err, result) => {
          if (err) {
            console.error('Error inserting user:', err);
            return res
              .status(500)
              .json({ success: false, message: 'Error creating user' });
          }

          res
            .status(201)
            .json({ success: true, message: 'User registered successfully' });
        }
      );
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// User login
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: 'Email and password are required' });
  }

  try {
    // Query user from database
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: 'Database error' });
      }

      const user = results[0];

      if (!user) {
        return res
          .status(401)
          .json({ success: false, message: 'Invalid email or password' });
      }

      // Compare entered password with hashed password
      const isPasswordValid = await bcrypt.compare(
        password,
        user.hashed_password
      );

      if (!isPasswordValid) {
        return res
          .status(401)
          .json({ success: false, message: 'Invalid email or password' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, role: user.role },
        'musinguziverelian23', // Replace with your own secret in production
        { expiresIn: '1h' }
      );

      // Include role in the response
      res.json({ success: true, token, role: user.role });
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  registerUser,
  loginUser,
};