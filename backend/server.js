const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkeychangeit';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'anothersecretkeyforrefresh';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Lire/écrire DB
const readDB = () => {
  const data = fs.readFileSync(path.join(__dirname, 'db.json'));
  return JSON.parse(data);
};

const writeDB = (data) => {
  fs.writeFileSync(path.join(__dirname, 'db.json'), JSON.stringify(data, null, 2));
};

// Générer les tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Middleware access token
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Accès refusé' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.type !== 'access') {
      return res.status(401).json({ error: 'Token invalide' });
    }
    req.userId = decoded.userId;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expiré', code: 'TOKEN_EXPIRED' });
    }
    res.status(401).json({ error: 'Token invalide' });
  }
};

// ========== ROUTES API ==========

// REGISTER
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }
  
  const db = readDB();
  
  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email déjà utilisé' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const newUser = {
    id: Date.now().toString(),
    email,
    password: hashedPassword,
    name: name || email.split('@')[0],
    createdAt: new Date().toISOString(),
    profile: { avatar: null, bio: '' }
  };
  
  db.users.push(newUser);
  
  const { accessToken, refreshToken } = generateTokens(newUser.id);
  
  db.refreshTokens.push({
    token: refreshToken,
    userId: newUser.id,
    createdAt: new Date().toISOString()
  });
  
  writeDB(db);
  
  res.status(201).json({
    success: true,
    message: 'Inscription réussie',
    accessToken,
    refreshToken,
    user: { id: newUser.id, email: newUser.email, name: newUser.name }
  });
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const db = readDB();
  const user = db.users.find(u => u.email === email);
  
  if (!user) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  
  const { accessToken, refreshToken } = generateTokens(user.id);
  
  db.refreshTokens.push({
    token: refreshToken,
    userId: user.id,
    createdAt: new Date().toISOString()
  });
  
  // Nettoyer vieux refresh tokens
  const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
  db.refreshTokens = db.refreshTokens.filter(rt => 
    new Date(rt.createdAt).getTime() > sevenDaysAgo
  );
  
  writeDB(db);
  
  res.json({
    success: true,
    message: 'Connexion réussie',
    accessToken,
    refreshToken,
    user: { id: user.id, email: user.email, name: user.name }
  });
});

// REFRESH TOKEN
app.post('/api/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token requis' });
  }
  
  const db = readDB();
  const storedToken = db.refreshTokens.find(rt => rt.token === refreshToken);
  
  if (!storedToken) {
    return res.status(403).json({ error: 'Refresh token invalide' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    
    if (decoded.type !== 'refresh') {
      return res.status(403).json({ error: 'Token invalide' });
    }
    
    const user = db.users.find(u => u.id === decoded.userId);
    if (!user) {
      return res.status(403).json({ error: 'Utilisateur inexistant' });
    }
    
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.userId);
    
    const index = db.refreshTokens.findIndex(rt => rt.token === refreshToken);
    db.refreshTokens[index] = {
      token: newRefreshToken,
      userId: decoded.userId,
      createdAt: new Date().toISOString()
    };
    
    writeDB(db);
    
    res.json({
      success: true,
      accessToken,
      refreshToken: newRefreshToken
    });
    
  } catch (error) {
    const index = db.refreshTokens.findIndex(rt => rt.token === refreshToken);
    if (index !== -1) {
      db.refreshTokens.splice(index, 1);
      writeDB(db);
    }
    res.status(403).json({ error: 'Refresh token expiré' });
  }
});

// LOGOUT
app.post('/api/logout', authMiddleware, (req, res) => {
  const { refreshToken } = req.body;
  const db = readDB();
  
  if (refreshToken) {
    const index = db.refreshTokens.findIndex(rt => rt.token === refreshToken);
    if (index !== -1) {
      db.refreshTokens.splice(index, 1);
      writeDB(db);
    }
  } else {
    db.refreshTokens = db.refreshTokens.filter(rt => rt.userId !== req.userId);
    writeDB(db);
  }
  
  res.json({ success: true, message: 'Déconnexion réussie' });
});

// GET PROFILE
app.get('/api/profile', authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'Utilisateur non trouvé' });
  }
  
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    profile: user.profile,
    createdAt: user.createdAt
  });
});

// UPDATE PROFILE
app.put('/api/profile', authMiddleware, (req, res) => {
  const { name, bio, avatar } = req.body;
  const db = readDB();
  
  const userIndex = db.users.findIndex(u => u.id === req.userId);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Utilisateur non trouvé' });
  }
  
  if (name) db.users[userIndex].name = name;
  if (bio) db.users[userIndex].profile.bio = bio;
  if (avatar) db.users[userIndex].profile.avatar = avatar;
  
  writeDB(db);
  
  res.json({
    success: true,
    message: 'Profil mis à jour',
    user: {
      id: db.users[userIndex].id,
      email: db.users[userIndex].email,
      name: db.users[userIndex].name,
      profile: db.users[userIndex].profile
    }
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Lunari Studio API démarrée sur http://localhost:${PORT}`);
});