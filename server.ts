import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

app.use(express.json());
app.use(cors());

interface AuthRequest extends Request {
  user?: { id: number; username: string };
}

const verifyToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Access denied. No token provided.' });
    return;
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET) as { id: number; username: string };
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

app.get('/api/announcements', async (req: Request, res: Response) => {
  try {
    const [rows] = await pool.query('SELECT * FROM announcements ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

app.post('/api/login', async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  try {
    const [rows]: any = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      res.status(400).json({ error: 'Invalid username or password' });
      return;
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      res.status(400).json({ error: 'Invalid username or password' });
      return;
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/api/announcements', verifyToken, async (req: AuthRequest, res: Response) => {
  const { title, content } = req.body;
  const authorId = req.user?.id;

  try {
    const [result] = await pool.query(
      'INSERT INTO announcements (title, content, author_id) VALUES (?, ?, ?)',
      [title, content, authorId]
    );
    res.status(201).json({ message: 'Announcement created successfully', result });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save announcement' });
  }
});

app.listen(PORT, () => {
  console.log(`Secure backend server running on port ${PORT}`);
});
