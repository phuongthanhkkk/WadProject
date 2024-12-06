const express = require('express');
const crypto = require('crypto');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('.data/database.db');

db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS meetings (id TEXT, user_id INTEGER, name TEXT, description TEXT, FOREIGN KEY(user_id) REFERENCES users(id))");
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: { sameSite: 'strict' }
}));

function generateMeetingId() {
    return crypto.randomBytes(16).toString('hex');
}

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.json({ success: false, message: 'Failed to log out' });
        }
        res.redirect('/');
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err || !user || crypto.createHash('sha256').update(password).digest('hex') !== user.password) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }
        req.session.userId = user.id;
        res.json({ success: true });
    });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
        if (err) {
            return res.json({ success: false, message: 'Username already exists' });
        }
        res.json({ success: true });
    });
});

app.get('/meetings', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    db.all("SELECT * FROM meetings WHERE user_id = ?", [req.session.userId], (err, meetings) => {
        if (err) return res.sendStatus(500);
        res.render('meetings', { meetings });
    });
});

app.post('/meetings/create', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    const id = generateMeetingId();
    const { name, description } = req.body;
    db.run("INSERT INTO meetings (id, user_id, name, description) VALUES (?, ?, ?, ?)", [id, req.session.userId, name, description], (err) => {
        if (err) return res.sendStatus(500);
        res.redirect('/meetings');
    });
});

app.post('/meetings/delete/:id', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    const meetingId = req.params.id;
    db.run("DELETE FROM meetings WHERE id = ? AND user_id = ?", [meetingId, req.session.userId], (err) => {
        if (err) return res.sendStatus(500);
        res.redirect('/meetings');
    });
});

app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});
