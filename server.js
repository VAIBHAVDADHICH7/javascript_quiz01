const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// Verify Node.js version for native SQLite support
let DatabaseSync;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (e) {
  console.error('CRITICAL: node:sqlite requires Node.js v22.5.0 or higher.');
  console.error('Current Node version is: ' + process.version);
  throw new Error('Node.js 22.5.0+ required for native SQLite (node:sqlite). Please configure Node.js 22 in your deployment settings.');
}

// Load environment configuration (.env)
if (process.loadEnvFile) {
  try { process.loadEnvFile(); } catch (e) {}
}

const app = express();
const PORT = process.env.PORT || 3000;

// Determine writable database path (Vercel/serverless environments require /tmp)
const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const DB_FILE = isServerless ? path.join('/tmp', 'quiz.db') : path.join(__dirname, 'quiz.db');

// Seed /tmp database from source file if running on serverless
if (isServerless && !fs.existsSync(DB_FILE)) {
  const sourceDb = path.join(__dirname, 'quiz.db');
  if (fs.existsSync(sourceDb)) {
    try {
      fs.copyFileSync(sourceDb, DB_FILE);
    } catch (e) {
      console.warn('Could not copy initial quiz.db to /tmp:', e);
    }
  }
}

const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || 'AdminQuiz_SecureKey_2026!';

// Initialize SQLite database
const db = new DatabaseSync(DB_FILE);

// Set PRAGMA journal_mode safely
try {
  db.exec('PRAGMA journal_mode = WAL;');
} catch (e) {
  try { db.exec('PRAGMA journal_mode = DELETE;'); } catch (err) {}
}

// Initialize Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    quiz_title TEXT DEFAULT 'JavaScript Mastery Quiz',
    status TEXT DEFAULT 'in_progress',
    score INTEGER DEFAULT 0,
    total_questions INTEGER DEFAULT 100,
    percentage REAL DEFAULT 0,
    time_taken_seconds INTEGER DEFAULT 0,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quiz_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    topic TEXT,
    difficulty TEXT,
    user_answer INTEGER,
    correct_answer INTEGER NOT NULL,
    is_correct INTEGER NOT NULL,
    time_spent_seconds INTEGER DEFAULT 0,
    answered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(attempt_id, question_id),
    FOREIGN KEY(attempt_id) REFERENCES quiz_attempts(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

function getFilePath(filename) {
  const p1 = path.join(__dirname, filename);
  if (fs.existsSync(p1)) return p1;
  const p2 = path.join(process.cwd(), filename);
  if (fs.existsSync(p2)) return p2;
  return p1;
}

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
app.use(express.static(process.cwd()));

// Explicit Root Routes for Candidate Portal
app.get('/', (req, res) => {
  res.sendFile(getFilePath('index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(getFilePath('index.html'));
});

// Password Hashing Utilities
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const hashBuffer = Buffer.from(crypto.scryptSync(password, salt, 64).toString('hex'), 'hex');
  const storedHashBuffer = Buffer.from(storedHash, 'hex');
  return crypto.timingSafeEqual(hashBuffer, storedHashBuffer);
}

function generateToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
  const insertToken = db.prepare('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)');
  insertToken.run(token, userId, expiresAt);
  return token;
}

// Authentication Middleware
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const query = db.prepare(`
      SELECT u.id, u.name, u.email, t.expires_at 
      FROM auth_tokens t 
      JOIN users u ON t.user_id = u.id 
      WHERE t.token = ?
    `);
    const user = query.get(token);

    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    if (new Date(user.expires_at) < new Date()) {
      db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(token);
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
}

// Optional Auth (returns user if token provided, else null)
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const user = db.prepare(`
        SELECT u.id, u.name, u.email 
        FROM auth_tokens t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.token = ?
      `).get(token);
      if (user) req.user = user;
    } catch (e) {}
  }
  next();
}

/* =========================================================================
   AUTH ROUTES
   ========================================================================= */

app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = name.trim();

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const { salt, hash } = hashPassword(password);
    const result = db.prepare('INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)').run(cleanName, cleanEmail, hash, salt);
    const userId = Number(result.lastInsertRowid);
    const token = generateToken(userId);

    res.status(201).json({
      success: true,
      token,
      user: { id: userId, name: cleanName, email: cleanEmail }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isValid = verifyPassword(password, user.salt, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = generateToken(user.id);

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login.' });
  }
});

app.get('/api/me', authenticate, (req, res) => {
  // Aggregate user statistics
  try {
    const stats = db.prepare(`
      SELECT 
        COUNT(id) as total_attempts,
        COALESCE(MAX(score), 0) as high_score,
        COALESCE(ROUND(AVG(percentage), 1), 0) as avg_percentage
      FROM quiz_attempts 
      WHERE user_id = ? AND status = 'completed'
    `).get(req.user.id);

    const answeredCount = db.prepare(`
      SELECT COUNT(id) as total_responses, SUM(is_correct) as total_correct
      FROM quiz_responses
      WHERE user_id = ?
    `).get(req.user.id);

    res.json({
      user: req.user,
      stats: {
        totalAttempts: stats.total_attempts || 0,
        highScore: stats.high_score || 0,
        avgPercentage: stats.avg_percentage || 0,
        totalAnswered: answeredCount.total_responses || 0,
        totalCorrect: answeredCount.total_correct || 0
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve user data.' });
  }
});

app.post('/api/logout', authenticate, (req, res) => {
  try {
    db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(req.token);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to logout.' });
  }
});

/* =========================================================================
   QUIZ ATTEMPTS & RESPONSES (DATABASE PERSISTENCE)
   ========================================================================= */

// Get or create current active attempt for user
app.post('/api/attempts/active', authenticate, (req, res) => {
  try {
    // Check if there's an ongoing attempt
    let attempt = db.prepare(`
      SELECT * FROM quiz_attempts 
      WHERE user_id = ? AND status = 'in_progress' 
      ORDER BY started_at DESC LIMIT 1
    `).get(req.user.id);

    if (!attempt) {
      const result = db.prepare(`
        INSERT INTO quiz_attempts (user_id, quiz_title, status) 
        VALUES (?, 'JavaScript Mastery Quiz', 'in_progress')
      `).run(req.user.id);
      
      attempt = db.prepare('SELECT * FROM quiz_attempts WHERE id = ?').get(Number(result.lastInsertRowid));
    }

    // Fetch any already saved responses for this attempt
    const responses = db.prepare(`
      SELECT question_id, user_answer, is_correct, answered_at 
      FROM quiz_responses 
      WHERE attempt_id = ?
    `).all(attempt.id);

    const answersMap = {};
    responses.forEach(r => {
      answersMap[r.question_id] = r.user_answer;
    });

    res.json({
      attempt,
      savedAnswers: answersMap
    });
  } catch (err) {
    console.error('Error fetching active attempt:', err);
    res.status(500).json({ error: 'Failed to get active attempt.' });
  }
});

// Save a single question response in real time to the database
app.post('/api/responses/save', authenticate, (req, res) => {
  const { attemptId, questionId, topic, difficulty, userAnswer, correctAnswer } = req.body;

  if (attemptId == null || questionId == null || userAnswer == null || correctAnswer == null) {
    return res.status(400).json({ error: 'Missing required response parameters.' });
  }

  const isCorrect = Number(userAnswer) === Number(correctAnswer) ? 1 : 0;

  try {
    // Upsert into quiz_responses table
    db.prepare(`
      INSERT INTO quiz_responses (attempt_id, user_id, question_id, topic, difficulty, user_answer, correct_answer, is_correct, answered_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(attempt_id, question_id) DO UPDATE SET
        user_answer = excluded.user_answer,
        is_correct = excluded.is_correct,
        answered_at = CURRENT_TIMESTAMP
    `).run(attemptId, req.user.id, questionId, topic || 'General', difficulty || 'Medium', userAnswer, correctAnswer, isCorrect);

    // Update real-time score count in attempt
    const totals = db.prepare(`
      SELECT COUNT(id) as count, COALESCE(SUM(is_correct), 0) as score 
      FROM quiz_responses 
      WHERE attempt_id = ?
    `).get(attemptId);

    const percentage = totals.count > 0 ? Number(((totals.score / 100) * 100).toFixed(1)) : 0;
    db.prepare('UPDATE quiz_attempts SET score = ?, percentage = ? WHERE id = ?').run(totals.score, percentage, attemptId);

    res.json({
      success: true,
      questionId,
      userAnswer,
      isCorrect: isCorrect === 1,
      currentScore: totals.score,
      totalAnswered: totals.count
    });
  } catch (err) {
    console.error('Failed to save response:', err);
    res.status(500).json({ error: 'Failed to save response to database.' });
  }
});

// Finalize/submit attempt
app.post('/api/attempts/complete', authenticate, (req, res) => {
  const { attemptId, timeTakenSeconds } = req.body;

  if (!attemptId) {
    return res.status(400).json({ error: 'Attempt ID is required.' });
  }

  try {
    const stats = db.prepare(`
      SELECT 
        COUNT(id) as answered_count,
        COALESCE(SUM(is_correct), 0) as total_correct
      FROM quiz_responses 
      WHERE attempt_id = ?
    `).get(attemptId);

    const totalQuestions = 100;
    const score = stats.total_correct;
    const percentage = Number(((score / totalQuestions) * 100).toFixed(1));

    db.prepare(`
      UPDATE quiz_attempts 
      SET status = 'completed', 
          score = ?, 
          total_questions = ?, 
          percentage = ?, 
          time_taken_seconds = ?, 
          completed_at = CURRENT_TIMESTAMP 
      WHERE id = ? AND user_id = ?
    `).run(score, totalQuestions, percentage, timeTakenSeconds || 0, attemptId, req.user.id);

    // Get breakdown by topic
    const topicBreakdown = db.prepare(`
      SELECT 
        topic, 
        COUNT(id) as answered, 
        SUM(is_correct) as correct 
      FROM quiz_responses 
      WHERE attempt_id = ? 
      GROUP BY topic
    `).all(attemptId);

    res.json({
      success: true,
      attemptId,
      score,
      totalQuestions,
      percentage,
      answeredCount: stats.answered_count,
      topicBreakdown
    });
  } catch (err) {
    console.error('Failed to complete attempt:', err);
    res.status(500).json({ error: 'Failed to complete attempt.' });
  }
});

// User's past quiz history
app.get('/api/attempts/history', authenticate, (req, res) => {
  try {
    const history = db.prepare(`
      SELECT id, quiz_title, status, score, total_questions, percentage, time_taken_seconds, started_at, completed_at
      FROM quiz_attempts
      WHERE user_id = ?
      ORDER BY started_at DESC
    `).all(req.user.id);

    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load history.' });
  }
});

// Detailed attempt breakdown with all individual responses
app.get('/api/attempts/:id/details', authenticate, (req, res) => {
  const attemptId = req.params.id;
  try {
    const attempt = db.prepare('SELECT * FROM quiz_attempts WHERE id = ? AND user_id = ?').get(attemptId, req.user.id);
    if (!attempt) return res.status(404).json({ error: 'Attempt not found.' });

    const responses = db.prepare(`
      SELECT question_id, topic, difficulty, user_answer, correct_answer, is_correct, answered_at 
      FROM quiz_responses 
      WHERE attempt_id = ?
      ORDER BY question_id ASC
    `).all(attemptId);

    res.json({ attempt, responses });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load attempt details.' });
  }
});

// Global Leaderboard
app.get('/api/leaderboard', (req, res) => {
  try {
    const leaderboard = db.prepare(`
      SELECT 
        u.name,
        MAX(a.score) as top_score,
        MAX(a.percentage) as top_percentage,
        MIN(a.time_taken_seconds) as best_time,
        a.completed_at
      FROM quiz_attempts a
      JOIN users u ON a.user_id = u.id
      WHERE a.status = 'completed'
      GROUP BY u.id
      ORDER BY top_score DESC, top_percentage DESC, best_time ASC
      LIMIT 10
    `).all();

    res.json({ leaderboard });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load leaderboard.' });
  }
});

// Detailed Candidate Statistics & Competency Analytics
app.get('/api/candidate/stats', authenticate, (req, res) => {
  try {
    const userId = req.user.id;

    // Attempts Overview
    const attempts = db.prepare(`
      SELECT id, score, total_questions, percentage, time_taken_seconds, status, started_at, completed_at 
      FROM quiz_attempts 
      WHERE user_id = ? 
      ORDER BY started_at DESC
    `).all(userId);

    const completed = attempts.filter(a => a.status === 'completed');
    const highScore = completed.length > 0 ? Math.max(...completed.map(a => a.score)) : 0;
    const avgScore = completed.length > 0 ? Number((completed.reduce((acc, a) => acc + a.score, 0) / completed.length).toFixed(1)) : 0;
    const avgPercentage = completed.length > 0 ? Number((completed.reduce((acc, a) => acc + a.percentage, 0) / completed.length).toFixed(1)) : 0;

    // Total responses by candidate
    const totalResponses = db.prepare(`
      SELECT COUNT(id) as count, COALESCE(SUM(is_correct), 0) as correct 
      FROM quiz_responses 
      WHERE user_id = ?
    `).get(userId);

    // Topic competency breakdown
    const topicStats = db.prepare(`
      SELECT 
        topic, 
        COUNT(id) as answered, 
        SUM(is_correct) as correct, 
        ROUND((CAST(SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as percentage
      FROM quiz_responses 
      WHERE user_id = ? 
      GROUP BY topic 
      ORDER BY percentage DESC
    `).all(userId);

    // Difficulty breakdown
    const diffStats = db.prepare(`
      SELECT 
        difficulty, 
        COUNT(id) as answered, 
        SUM(is_correct) as correct, 
        ROUND((CAST(SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as percentage
      FROM quiz_responses 
      WHERE user_id = ? 
      GROUP BY difficulty 
      ORDER BY CASE difficulty 
        WHEN 'Easy' THEN 1 
        WHEN 'Medium' THEN 2 
        WHEN 'Hard' THEN 3 
        WHEN 'Expert' THEN 4 
        ELSE 5 END
    `).all(userId);

    // Time & pacing
    const totalTimeSeconds = attempts.reduce((acc, a) => acc + (a.time_taken_seconds || 0), 0);
    const avgSecondsPerQuestion = totalResponses.count > 0 ? Number((totalTimeSeconds / totalResponses.count).toFixed(1)) : 0;
    let pace = 'Moderate';
    if (avgSecondsPerQuestion > 0 && avgSecondsPerQuestion < 20) pace = 'Rapid';
    else if (avgSecondsPerQuestion >= 45) pace = 'Deliberate & Thorough';

    // Global Rank among all candidates
    const allRanks = db.prepare(`
      SELECT user_id, MAX(score) as top_score 
      FROM quiz_attempts 
      WHERE status = 'completed' 
      GROUP BY user_id 
      ORDER BY top_score DESC
    `).all();
    const rankIndex = allRanks.findIndex(r => r.user_id === userId);
    const rank = rankIndex !== -1 ? rankIndex + 1 : '—';
    const totalRanked = allRanks.length;

    // Strengths and Focus areas
    const strengths = topicStats.filter(t => t.percentage >= 60).slice(0, 2);
    const weaknesses = topicStats.filter(t => t.percentage < 60).slice(-2);

    res.json({
      user: req.user,
      overview: {
        totalAttempts: attempts.length,
        completedAttempts: completed.length,
        highScore,
        avgScore,
        avgPercentage,
        totalAnswered: totalResponses.count,
        totalCorrect: totalResponses.correct,
        accuracy: totalResponses.count > 0 ? Number(((totalResponses.correct / totalResponses.count) * 100).toFixed(1)) : 0,
        rank,
        totalRanked
      },
      pacing: {
        totalTimeSeconds,
        avgSecondsPerQuestion,
        pace
      },
      topicStats,
      diffStats,
      strengths,
      weaknesses,
      recentAttempts: attempts.slice(0, 5)
    });
  } catch (err) {
    console.error('Candidate stats error:', err);
    res.status(500).json({ error: 'Failed to calculate candidate statistics.' });
  }
});

/* =========================================================================
   FORTIFIED ADMIN PORTAL SECURITY & ACCESS CONTROL
   ========================================================================= */
const adminLoginAttempts = new Map(); // IP -> { count, lockedUntil }
const activeAdminSessions = new Map(); // token -> { expiresAt }

function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

function checkAdminRateLimit(ip) {
  const now = Date.now();
  const record = adminLoginAttempts.get(ip);
  if (record && record.lockedUntil && record.lockedUntil > now) {
    const waitMins = Math.ceil((record.lockedUntil - now) / 60000);
    return `Security Alert: Too many failed passkey attempts. Access locked for ${waitMins} minute(s).`;
  }
  return null;
}

function recordFailedAdminAttempt(ip) {
  const now = Date.now();
  const record = adminLoginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  record.count++;
  if (record.count >= 5) {
    record.lockedUntil = now + 15 * 60 * 1000; // 15-minute lock
    record.count = 0;
  }
  adminLoginAttempts.set(ip, record);
}

function resetAdminAttempts(ip) {
  adminLoginAttempts.delete(ip);
}

// Middleware: Strict Administrator Authorization
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const adminKeyHeader = req.headers['x-admin-key'];
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (adminKeyHeader) {
    token = adminKeyHeader;
  }

  if (!token || !activeAdminSessions.has(token)) {
    return res.status(401).json({ error: 'Security Exception: Administrator authorization required.' });
  }

  const session = activeAdminSessions.get(token);
  if (Date.now() > session.expiresAt) {
    activeAdminSessions.delete(token);
    return res.status(401).json({ error: 'Admin session expired. Please authenticate again.' });
  }

  // Sliding 2-hour session expiration
  session.expiresAt = Date.now() + 2 * 60 * 60 * 1000;
  next();
}

// Admin Portal Static Route
app.get('/admin', (req, res) => {
  res.sendFile(getFilePath('admin.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(getFilePath('admin.html'));
});

// Admin Passkey Login Endpoint
app.post('/api/admin/login', (req, res) => {
  const ip = getClientIp(req);
  const lockoutMsg = checkAdminRateLimit(ip);
  if (lockoutMsg) {
    return res.status(429).json({ error: lockoutMsg });
  }

  const { passkey } = req.body;
  if (!passkey || typeof passkey !== 'string') {
    recordFailedAdminAttempt(ip);
    return res.status(400).json({ error: 'Administrator passkey is required.' });
  }

  const inputBuffer = Buffer.from(passkey.trim());
  const secretBuffer = Buffer.from(ADMIN_SECRET_KEY);

  // Constant-time comparison to prevent timing attacks
  const isValid = inputBuffer.length === secretBuffer.length && crypto.timingSafeEqual(inputBuffer, secretBuffer);

  if (!isValid) {
    recordFailedAdminAttempt(ip);
    return res.status(401).json({ error: 'Invalid administrator passkey.' });
  }

  resetAdminAttempts(ip);
  const adminToken = crypto.randomBytes(32).toString('hex');
  activeAdminSessions.set(adminToken, {
    expiresAt: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
  });

  res.json({
    success: true,
    adminToken,
    expiresIn: '2 hours'
  });
});

// Verify Admin Session
app.get('/api/admin/verify', requireAdminAuth, (req, res) => {
  res.json({ authorized: true });
});

// Admin Logout
app.post('/api/admin/logout', requireAdminAuth, (req, res) => {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '') || req.headers['x-admin-key'];
  if (token) activeAdminSessions.delete(token);
  res.json({ success: true, message: 'Admin session terminated.' });
});

// Protected & Sanitized Database API
app.get('/api/admin/database', requireAdminAuth, (req, res) => {
  try {
    const rawUsers = db.prepare('SELECT id, name, email, created_at FROM users ORDER BY id DESC').all();
    const users = rawUsers.map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      password_status: '🔒 Scrypt Encrypted (Protected)',
      credentials_security: 'Salted & Key-Stretched (Never Exposed)',
      created_at: u.created_at
    }));

    const attempts = db.prepare('SELECT a.id, u.name as candidate_name, u.email as candidate_email, a.quiz_title, a.status, a.score, a.total_questions, a.percentage, a.time_taken_seconds, a.started_at, a.completed_at FROM quiz_attempts a JOIN users u ON a.user_id = u.id ORDER BY a.id DESC').all();
    const responses = db.prepare('SELECT r.id, r.attempt_id, u.name as candidate_name, r.question_id, r.topic, r.difficulty, r.user_answer, r.correct_answer, r.is_correct, r.answered_at FROM quiz_responses r JOIN users u ON r.user_id = u.id ORDER BY r.id DESC LIMIT 100').all();
    
    // Privacy Shield: NEVER expose session token hashes over the wire to prevent hijacking
    const rawTokens = db.prepare('SELECT u.name, u.email, t.created_at, t.expires_at FROM auth_tokens t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC').all();
    const tokens = rawTokens.map(t => ({
      token: '•••••••••••••••••••••••• (TOKEN MASKED FOR PRIVACY)',
      name: t.name,
      email: t.email,
      created_at: t.created_at,
      expires_at: t.expires_at
    }));

    const totalResponsesCount = db.prepare('SELECT COUNT(id) as count FROM quiz_responses').get().count;

    res.json({
      dbFile: DB_FILE,
      stats: {
        totalUsers: users.length,
        totalAttempts: attempts.length,
        totalResponses: totalResponsesCount,
        totalTokens: tokens.length
      },
      tables: {
        users,
        attempts,
        responses,
        tokens
      }
    });
  } catch (err) {
    console.error('Admin database fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve database data.' });
  }
});

// Comprehensive Administrator Analytics API (Protected)
app.get('/api/admin/analytics', requireAdminAuth, (req, res) => {
  try {
    const totalUsers = db.prepare('SELECT COUNT(id) as count FROM users').get().count;
    const attemptStats = db.prepare(`
      SELECT 
        COUNT(id) as total_attempts,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_attempts,
        SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_attempts,
        COALESCE(ROUND(AVG(CASE WHEN status = 'completed' THEN score END), 1), 0) as avg_score,
        COALESCE(ROUND(AVG(CASE WHEN status = 'completed' THEN percentage END), 1), 0) as avg_percentage,
        COALESCE(MAX(CASE WHEN status = 'completed' THEN score END), 0) as max_score,
        COALESCE(MIN(CASE WHEN status = 'completed' THEN score END), 0) as min_score,
        COALESCE(ROUND(AVG(CASE WHEN status = 'completed' THEN time_taken_seconds END), 0), 0) as avg_duration,
        SUM(CASE WHEN status = 'completed' AND percentage >= 70 THEN 1 ELSE 0 END) as passed_attempts
      FROM quiz_attempts
    `).get();

    const completedCount = attemptStats.completed_attempts || 0;
    const passRate = completedCount > 0 
      ? Number(((attemptStats.passed_attempts / completedCount) * 100).toFixed(1)) 
      : 0;

    // Distribution bands
    const bands = db.prepare(`
      SELECT 
        SUM(CASE WHEN percentage >= 90 THEN 1 ELSE 0 END) as band_90_100,
        SUM(CASE WHEN percentage >= 70 AND percentage < 90 THEN 1 ELSE 0 END) as band_70_89,
        SUM(CASE WHEN percentage >= 50 AND percentage < 70 THEN 1 ELSE 0 END) as band_50_69,
        SUM(CASE WHEN percentage < 50 THEN 1 ELSE 0 END) as band_under_50
      FROM quiz_attempts 
      WHERE status = 'completed'
    `).get();

    // Topic Performance cohort-wide
    const topicPerformance = db.prepare(`
      SELECT 
        topic, 
        COUNT(id) as total_answers, 
        SUM(is_correct) as total_correct,
        ROUND((CAST(SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as accuracy
      FROM quiz_responses 
      GROUP BY topic 
      ORDER BY accuracy ASC
    `).all();

    // Difficulty Performance cohort-wide
    const difficultyPerformance = db.prepare(`
      SELECT 
        difficulty, 
        COUNT(id) as total_answers, 
        SUM(is_correct) as total_correct,
        ROUND((CAST(SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as accuracy
      FROM quiz_responses 
      GROUP BY difficulty 
      ORDER BY CASE difficulty 
        WHEN 'Easy' THEN 1 
        WHEN 'Medium' THEN 2 
        WHEN 'Hard' THEN 3 
        WHEN 'Expert' THEN 4 
        ELSE 5 END
    `).all();

    // Item Analysis: Hardest and Easiest Questions
    const questionAnalysis = db.prepare(`
      SELECT 
        question_id, 
        topic, 
        difficulty, 
        COUNT(id) as attempts, 
        SUM(is_correct) as correct,
        ROUND((CAST(SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as pass_rate,
        ROUND((CAST(COUNT(id) - SUM(is_correct) as REAL) / COUNT(id)) * 100, 1) as fail_rate
      FROM quiz_responses 
      GROUP BY question_id 
      HAVING attempts >= 1
      ORDER BY fail_rate DESC, attempts DESC
    `).all();

    const hardestQuestions = questionAnalysis.slice(0, 5);
    const easiestQuestions = [...questionAnalysis].sort((a, b) => b.pass_rate - a.pass_rate).slice(0, 5);

    res.json({
      cohort: {
        totalUsers,
        totalAttempts: attemptStats.total_attempts || 0,
        completedAttempts: completedCount,
        inProgressAttempts: attemptStats.in_progress_attempts || 0,
        passRate,
        passedCount: attemptStats.passed_attempts || 0,
        avgScore: attemptStats.avg_score,
        avgPercentage: attemptStats.avg_percentage,
        maxScore: attemptStats.max_score,
        minScore: attemptStats.min_score,
        avgDurationSeconds: attemptStats.avg_duration
      },
      distribution: {
        band90to100: bands.band_90_100 || 0,
        band70to89: bands.band_70_89 || 0,
        band50to69: bands.band_50_69 || 0,
        bandUnder50: bands.band_under_50 || 0
      },
      topicPerformance,
      difficultyPerformance,
      itemAnalysis: {
        hardestQuestions,
        easiestQuestions
      }
    });
  } catch (err) {
    console.error('Admin analytics error:', err);
    res.status(500).json({ error: 'Failed to compute admin analytics.' });
  }
});

// Start Server (only when run directly in Node, not as a serverless function export)
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` Professional Quiz Server Active at http://localhost:${PORT}`);
    console.log(` Database: SQLite (${DB_FILE})`);
    console.log(` Features: Registration, Sessions, Real-time DB Sync, Leaderboard`);
    console.log(`=======================================================`);
  });
}

module.exports = app;
