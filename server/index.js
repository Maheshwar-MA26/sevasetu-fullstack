import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 40 }));

const PORT = process.env.PORT || 5000;
const URI = process.env.MONGODB_URI;
const SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
let connected = false;
let memoryMode = false;

// MongoDB models. If MongoDB is unavailable, the API automatically falls back
// to in-memory storage so the hackathon MVP can still run locally.
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  mobile: { type: String, unique: true },
  email: String,
  passwordHash: String,
  verified: { type: Boolean, default: false }
}));
const OTP = mongoose.model('Otp', new mongoose.Schema({
  mobile: String, hash: String, purpose: String, expiresAt: Date,
  attempts: { type: Number, default: 0 }
}, { timestamps: true }));
const Application = mongoose.model('Application', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  service: String,
  trackingId: { type: String, unique: true },
  status: { type: String, default: 'Submitted' },
  createdAt: { type: Date, default: Date.now }
}));

const memUsers = new Map();
const memOtps = new Map();
const memApplications = new Map();
const fallbackFile = path.join(process.cwd(), 'fallback-db.json');
function loadFallback(){ try{ if(fs.existsSync(fallbackFile)){ const d=JSON.parse(fs.readFileSync(fallbackFile,'utf8')); (d.users||[]).forEach(u=>memUsers.set(u.mobile,u)); (d.applications||[]).forEach(a=>{const k=String(a.userId); const list=memApplications.get(k)||[]; memApplications.set(k,[a,...list]);}); } }catch(e){ console.warn('Could not load fallback database:',e.message); } }
function saveFallback(){ try{ fs.writeFileSync(fallbackFile,JSON.stringify({users:[...memUsers.values()],applications:[...memApplications.values()].flat()},null,2)); }catch(e){ console.warn('Could not save fallback database:',e.message); } }
loadFallback();

const makeId = () => crypto.randomBytes(12).toString('hex');
const token = u => jwt.sign({ sub: String(u._id), mobile: u.mobile }, SECRET, { expiresIn: '12h' });

async function findUserByMobile(mobile) {
  if (memoryMode) return memUsers.get(mobile) || null;
  return User.findOne({ mobile });
}

async function findUserById(id) {
  if (memoryMode) {
    for (const u of memUsers.values()) if (String(u._id) === String(id)) return u;
    return null;
  }
  return User.findById(id).select('-passwordHash');
}

async function createUser(data) {
  if (memoryMode) {
    const u = { _id: makeId(), ...data, verified: false };
    memUsers.set(data.mobile, u);
    saveFallback();
    return u;
  }
  return User.create(data);
}

async function markVerified(mobile) {
  if (memoryMode) {
    const u = memUsers.get(mobile);
    if (!u) return null;
    u.verified = true;
    saveFallback();
    return u;
  }
  return User.findOneAndUpdate({ mobile }, { verified: true }, { new: true });
}

async function updatePassword(mobile, passwordHash) {
  if (memoryMode) {
    const u = memUsers.get(mobile);
    if (!u) return null;
    u.passwordHash = passwordHash;
    saveFallback();
    return u;
  }
  const u = await User.findOne({ mobile });
  if (!u) return null;
  u.passwordHash = passwordHash;
  await u.save();
  return u;
}

const auth = async (req, res, next) => {
  try {
    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/, '');
    const p = jwt.verify(raw, SECRET);
    req.user = await findUserById(p.sub);
    if (!req.user) return res.status(401).json({ error: 'Account not found' });
    next();
  } catch {
    return res.status(401).json({ error: 'Sign in again' });
  }
};

async function makeOtp(mobile, purpose) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const expiresAt = new Date(Date.now() + (+process.env.OTP_TTL_MINUTES || 5) * 60000);
  const hash = await bcrypt.hash(code, 10);

  if (memoryMode) {
    memOtps.set(`${mobile}:${purpose}`, { hash, expiresAt, attempts: 0 });
  } else {
    await OTP.deleteMany({ mobile, purpose });
    await OTP.create({ mobile, purpose, hash, expiresAt });
  }

  // Development/hackathon OTP. Never expose this in production.
  if (process.env.NODE_ENV !== 'production') console.log(`[DEMO OTP] ${purpose} ${mobile} ${code}`);
}

async function checkOtp(mobile, code, purpose) {
  if (memoryMode) {
    const key = `${mobile}:${purpose}`;
    const o = memOtps.get(key);
    if (!o || o.expiresAt < new Date() || o.attempts >= 5) return false;
    o.attempts += 1;
    const ok = await bcrypt.compare(String(code), o.hash);
    if (ok) memOtps.delete(key);
    return ok;
  }

  const o = await OTP.findOne({ mobile, purpose }).sort({ createdAt: -1 });
  if (!o || o.expiresAt < new Date() || o.attempts >= 5) return false;
  o.attempts += 1;
  await o.save();
  const ok = await bcrypt.compare(String(code), o.hash);
  if (ok) await OTP.deleteMany({ mobile, purpose });
  return ok;
}

app.get('/api/health', (req, res) => res.json({
  ok: true,
  database: connected ? 'connected' : 'memory fallback',
  mode: 'prototype',
  message: connected ? 'MongoDB connected' : 'MongoDB unavailable; using temporary in-memory storage'
}));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, mobile, email, password } = req.body;
    if (!name || !/^[6-9]\d{9}$/.test(mobile || '') || !password || password.length < 8) {
      return res.status(400).json({ error: 'Name, valid mobile and password (8+ chars) required' });
    }
    if (await findUserByMobile(mobile)) return res.status(409).json({ error: 'Mobile already registered' });
    await createUser({ name, mobile, email, passwordHash: await bcrypt.hash(password, 12) });
    await makeOtp(mobile, 'verify');
    res.status(201).json({ message: 'Registered; verify OTP. Demo OTP is printed in the server console.' });
  } catch (e) {
    console.error('Registration error:', e.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { mobile, otp } = req.body;
    if (!await checkOtp(mobile, otp, 'verify')) return res.status(400).json({ error: 'Invalid or expired OTP' });
    const u = await markVerified(mobile);
    if (!u) return res.status(404).json({ error: 'Account not found' });
    res.json({ token: token(u), user: { name: u.name, mobile: u.mobile } });
  } catch (e) {
    console.error('OTP verification error:', e.message);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { mobile, password } = req.body;
    const u = await findUserByMobile(mobile);
    if (!u || !u.passwordHash || !await bcrypt.compare(password || '', u.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!u.verified) return res.status(403).json({ error: 'Verify mobile first' });
    res.json({ token: token(u), user: { name: u.name, mobile: u.mobile } });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/request-otp', async (req, res) => {
  try {
    const { mobile, purpose = 'login' } = req.body;
    if (!/^[6-9]\d{9}$/.test(mobile || '')) return res.status(400).json({ error: 'Valid mobile required' });
    if ((purpose === 'reset' || purpose === 'login') && !(await findUserByMobile(mobile))) {
      return res.status(404).json({ error: 'Account not found' });
    }
    await makeOtp(mobile, purpose);
    res.json({ message: 'Demo OTP printed in server console. SMS provider not configured.' });
  } catch (e) {
    console.error('OTP request error:', e.message);
    res.status(500).json({ error: 'Could not send OTP' });
  }
});

app.post('/api/auth/login-otp', async (req, res) => {
  try {
    const { mobile, otp } = req.body;
    if (!await checkOtp(mobile, otp, 'login')) return res.status(400).json({ error: 'Invalid or expired OTP' });
    const u = await findUserByMobile(mobile);
    if (!u?.verified) return res.status(404).json({ error: 'Verified account not found' });
    res.json({ token: token(u), user: { name: u.name, mobile: u.mobile } });
  } catch (e) {
    console.error('OTP login error:', e.message);
    res.status(500).json({ error: 'OTP login failed' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { mobile, otp, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be 8+ characters' });
    if (!await checkOtp(mobile, otp, 'reset')) return res.status(400).json({ error: 'Invalid or expired OTP' });
    const u = await updatePassword(mobile, await bcrypt.hash(newPassword, 12));
    if (!u) return res.status(404).json({ error: 'Account not found' });
    res.json({ message: 'Password reset successful' });
  } catch (e) {
    console.error('Reset password error:', e.message);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

app.get('/api/me', auth, async (req, res) => res.json({ user: req.user }));

app.get('/api/applications', auth, async (req, res) => {
  if (memoryMode) {
    return res.json({ applications: memApplications.get(String(req.user._id)) || [] });
  }
  res.json({ applications: await Application.find({ userId: req.user._id }).sort({ createdAt: -1 }) });
});

app.post('/api/applications', auth, async (req, res) => {
  try {
    if (!req.body.service) return res.status(400).json({ error: 'Service required' });
    const createdAt = new Date();
    const a = {
      _id: makeId(),
      userId: req.user._id,
      service: req.body.service,
      trackingId: 'SV-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
      status: 'Submitted',
      createdAt
    };
    if (memoryMode) {
      const key = String(req.user._id);
      const list = memApplications.get(key) || [];
      memApplications.set(key, [a, ...list]);
      saveFallback();
    } else {
      const dbA = await Application.create({ userId: req.user._id, service: a.service, trackingId: a.trackingId });
      a._id = dbA._id;
      a.createdAt = dbA.createdAt;
    }
    res.status(201).json({ application: a });
  } catch (e) {
    console.error('Application error:', e.message);
    res.status(500).json({ error: 'Could not create application' });
  }
});

async function start() {
  if (URI) {
    try {
      await mongoose.connect(URI, {
        serverSelectionTimeoutMS: 3000,
        connectTimeoutMS: 3000,
        socketTimeoutMS: 5000,
        bufferCommands: false
      });
      connected = true;
      memoryMode = false;
      console.log('MongoDB connected');
    } catch (e) {
      memoryMode = true;
      console.warn('MongoDB unavailable:', e.message);
      console.warn('SEVASETU is starting in temporary MEMORY FALLBACK mode. Your MongoDB data will be used automatically once MongoDB is available.');
    }
  } else {
    memoryMode = true;
    console.warn('MONGODB_URI not configured. Starting in temporary MEMORY FALLBACK mode.');
  }
  app.listen(PORT, '0.0.0.0', () => console.log('SEVASETU API on ' + PORT));
}

start();
