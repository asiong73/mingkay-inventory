const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3000;

// --- Database Setup ---
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error("Error opening database", err.message);
    } else {
        console.log("Connected to the SQLite database.");
        // Create tables if they don't exist
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner', 'admin'))
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                position TEXT,
                hire_date DATE,
                photo_path TEXT
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                quantity INTEGER,
                price REAL
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                quantity_sold INTEGER,
                sale_date DATE,
                total_price REAL
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_date DATE NOT NULL,
                auditor_name TEXT,
                notes TEXT
            )`);
        });
    }
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'views')));

app.use(session({
    secret: 'a-very-secret-key-for-inventory',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// --- File Uploads (Multer) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'public/uploads/';
        fs.mkdirSync(uploadPath, { recursive: true }); // Ensure directory exists
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- Authentication Middleware ---
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login.html');
    }
};

const isOwner = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'owner') {
        next();
    } else {
        res.status(403).send('Forbidden: Owners only.');
    }
};

const isAdminOrOwner = (req, res, next) => {
    if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'owner')) {
        next();
    } else {
        res.status(403).send('Forbidden: Admins or Owners only.');
    }
};

// --- HTML Page Routes ---
app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/dashboard', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'owner') {
        res.redirect('/dashboard_owner.html');
    } else {
        res.redirect('/dashboard_admin.html');
    }
});

// --- API Routes ---

// User Authentication
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], function(err) {
        if (err) {
            return res.status(500).json({ message: 'Username already exists.' });
        }
        res.status(201).json({ message: 'User registered successfully.' });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ message: 'Login successful', role: user.role });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.redirect('/login.html');
    });
});

app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// Generic CRUD functions
function createCrudRoutes(tableName, router) {
    // GET all
    router.get(`/api/${tableName}`, isAdminOrOwner, (req, res) => {
        db.all(`SELECT * FROM ${tableName}`, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });

    // POST new
    router.post(`/api/${tableName}`, isAdminOrOwner, (req, res) => {
        const columns = Object.keys(req.body).join(', ');
        const placeholders = Object.keys(req.body).map(() => '?').join(', ');
        const values = Object.values(req.body);
        db.run(`INSERT INTO ${tableName} (${columns}) VALUES (${placeholders})`, values, function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: this.lastID });
        });
    });

    // DELETE one
    router.delete(`/api/${tableName}/:id`, isAdminOrOwner, (req, res) => {
        db.run(`DELETE FROM ${tableName} WHERE id = ?`, req.params.id, function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ deleted: this.changes });
        });
    });
}

createCrudRoutes('inventory', app);
createCrudRoutes('sales', app);
createCrudRoutes('audits', app);

// --- Special Employee Routes (with photo upload) ---
app.get('/api/employees', isAdminOrOwner, (req, res) => {
    db.all('SELECT * FROM employees', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/employees', isAdminOrOwner, upload.single('photo'), (req, res) => {
    const { name, position, hire_date } = req.body;
    const photo_path = req.file ? req.file.path.replace(/\\/g, "/").replace('public/', '') : null;

    db.run('INSERT INTO employees (name, position, hire_date, photo_path) VALUES (?, ?, ?, ?)',
        [name, position, hire_date, photo_path],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: this.lastID });
        }
    );
});

app.delete('/api/employees/:id', isAdminOrOwner, (req, res) => {
    // First, get the photo path to delete the file
    db.get('SELECT photo_path FROM employees WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row && row.photo_path) {
            fs.unlink(path.join(__dirname, 'public', row.photo_path), (unlinkErr) => {
                // Log error but don't block DB deletion
                if (unlinkErr) console.error("Error deleting photo file:", unlinkErr);
            });
        }

        // Then, delete the database record
        db.run('DELETE FROM employees WHERE id = ?', req.params.id, function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ deleted: this.changes });
        });
    });
});

// --- Owner's Special Search Route ---
app.get('/api/search', isOwner, async (req, res) => {
    const term = req.query.term;
    if (!term) {
        return res.status(400).json({ message: 'Search term is required.' });
    }

    const searchTerm = `%${term}%`;
    const results = {};

    const runQuery = (query, params) => new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });

    try {
        results.employees = await runQuery('SELECT id, name, position FROM employees WHERE name LIKE ?', [searchTerm]);
        results.inventory = await runQuery('SELECT id, item_name, quantity FROM inventory WHERE item_name LIKE ?', [searchTerm]);
        results.sales = await runQuery('SELECT id, item_name, sale_date FROM sales WHERE item_name LIKE ?', [searchTerm]);
        results.audits = await runQuery('SELECT id, auditor_name, audit_date FROM audits WHERE auditor_name LIKE ?', [searchTerm]);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// --- Protected Page Routes ---

// Owner-only pages
app.get('/dashboard_owner.html', isOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard_owner.html'));
});

// Admin & Owner pages
const adminAndOwnerPages = ['dashboard_admin.html', 'employees.html', 'inventory.html', 'sales.html', 'audits.html'];
adminAndOwnerPages.forEach(page => {
    app.get(`/${page}`, isAdminOrOwner, (req, res) => {
        res.sendFile(path.join(__dirname, 'views', page));
    });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});