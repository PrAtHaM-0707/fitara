const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));

mongoose.connect('mongodb+srv://codex-in2:codex-in2@codex-in2.gjv2c.mongodb.net/?retryWrites=true&w=majority')
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.log('Connection error:', err));

const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  resetToken: String,
  resetTokenExpiry: Date
});
const User = mongoose.model('User', UserSchema);

const FeedbackSchema = new mongoose.Schema({
  email: String,
  feedback: String,
  createdAt: { type: Date, default: Date.now }
});
const Feedback = mongoose.model('Feedback', FeedbackSchema);

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, 'collegeproject123', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already in use' });
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/.test(password)) {
      return res.status(400).json({ message: 'Password must include uppercase, lowercase, number, and special character' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.json({ message: 'Signup successful! Please log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/submit-feedback', authenticateToken, async (req, res) => {
  const { feedback } = req.body;
  try {
    const user = await User.findById(req.user.id).select('email');
    if (!user) return res.status(404).json({ message: 'User not found' });
    const newFeedback = new Feedback({
      email: user.email,
      feedback: feedback
    });
    await newFeedback.save();
    res.json({ message: 'Feedback submitted successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email doesn’t exist, please sign up' });
    if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Invalid password' });
    const token = jwt.sign({ id: user._id, email: user.email }, 'collegeproject123', { expiresIn: '1h' });
    res.json({ message: 'Login successful!', token });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email not found' });
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();
    const resetLink = `http://localhost:3000/reset-password.html?token=${resetToken}`;
    console.log(`Reset link for ${email}: ${resetLink}`);
    res.json({ message: 'Reset link generated. Check server console.' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must include uppercase, lowercase, number, and special character' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();
    res.json({ message: 'Password reset successful!' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -resetToken -resetTokenExpiry');
    res.json({ username: user.username, email: user.email });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  const { username } = req.body;
  try {
    const user = await User.findById(req.user.id);
    user.username = username;
    await user.save();
    res.json({ message: 'Username updated!' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.post('/reset-password-from-profile', authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  try {
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must include uppercase, lowercase, number, and special character' });
    }
    const user = await User.findById(req.user.id);
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password reset successful!' });
  } catch (error) {
    res.status(500).json({ message: 'Error: ' + error.message });
  }
});

app.listen(5000, () => console.log('Server running on port 3000'));