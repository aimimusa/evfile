// --- Server-Side JavaScript (server.js) ---
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// --- IMPORTANT: MongoDB Connection String ---
const MONGO_URI = 'mongodb+srv://yami:ss36MtrPUa4CXrMd@yami.faf5uso.mongodb.net/?retryWrites=true&w=majority&appName=yami';
app.use(express.static('public'));
// --- Database Connection ---
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- Database Schemas ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Admin', 'CEO', 'Staff'], default: 'Staff' }
});

const fileSchema = new mongoose.Schema({
    displayName: String,
    category: String,
    company: String,
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number,
    uploadDate: { type: Date, default: Date.now },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const activityLogSchema = new mongoose.Schema({
    activity: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// --- Helper function for logging activity ---
const logActivity = async (activity, userId) => {
    try {
        const log = new ActivityLog({ activity, user: userId });
        await log.save();
    } catch (error) {
        console.error('Error logging activity:', error);
    }
};

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session Middleware
app.use(session({
    secret: 'a secret key for file management',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI })
}));

// --- Authentication Middleware ---
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) next();
    else res.redirect('/login');
};

const isAdmin = async (req, res, next) => {
    if (req.session.userId && req.session.role === 'Admin') next();
    else res.status(403).send('Access Forbidden: Admins only.');
};

// --- Page Serving Routes ---
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/add', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'add.html')));
app.get('/admin/panel', isAuthenticated, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin', 'panel.html')));
app.get('/admin/users', isAuthenticated, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin', 'users.html')));
app.get('/admin/dashboard', isAuthenticated, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin', 'dashboard.html')));
app.get('/admin/activity', isAuthenticated, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin', 'activity.html')));

// --- Multer Configuration ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(path.join(__dirname, 'admin'))) fs.mkdirSync(path.join(__dirname, 'admin'));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


// --- API Routes ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user._id;
            req.session.username = user.username;
            req.session.role = user.role;
            res.redirect('/');
        } else {
            res.redirect('/login?error=Invalid username or password');
        }
    } catch (error) {
        res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
    }
});
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.redirect('/');
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});
app.get('/api/user', (req, res) => {
    if (req.session.userId) {
        res.json({ username: req.session.username, role: req.session.role });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});


app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.redirect('/?status=fail&message=No file selected');
        const { displayName, category, company, date } = req.body;
        const newFile = new File({
            displayName: displayName || req.file.originalname,
            category, company,
            uploadDate: date ? new Date(date) : Date.now(),
            filename: req.file.filename,
            originalName: req.file.originalname,
            mimeType: req.file.mimetype,
            size: req.file.size,
            uploadedBy: req.session.userId
        });
        await newFile.save();
        await logActivity(`Added file "${newFile.displayName}"`, req.session.userId);
        res.redirect('/?status=success');
    } catch (error) {
        res.redirect(`/?status=fail&message=${encodeURIComponent(error.message)}`);
    }
});

app.delete('/files/:id', isAuthenticated, async (req, res) => {
    try {
        const file = await File.findByIdAndDelete(req.params.id);
        if (file) {
            const filePath = path.join(__dirname, uploadDir, file.filename);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            await logActivity(`Deleted file "${file.displayName}"`, req.session.userId);
        }
        res.json({ message: 'File deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting file.' });
    }
});

app.get('/files', isAuthenticated, async (req, res) => {
    try {
        const files = await File.find().sort({ uploadDate: -1 });
        res.json(files);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching files.' });
    }
});
app.get('/view/:filename', isAuthenticated, async (req, res) => {
    const filePath = path.join(__dirname, uploadDir, req.params.filename);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).send('File not found.');
    }
});
app.get('/api/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching users.' });
    }
});
app.get('/api/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id, '-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching user.' });
    }
});
app.post('/api/users', isAuthenticated, isAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    try {
        if (!username || !password || !role) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'Username already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();
        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error creating user.' });
    }
});
app.put('/api/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { username, role, password } = req.body;
    try {
        const updateData = { username, role };
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }
        const updatedUser = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error updating user.' });
    }
});
app.delete('/api/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting user.' });
    }
});
app.get('/api/dashboard-stats', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const fileCount = await File.countDocuments();
        const totalStorageResult = await File.aggregate([ { $group: { _id: null, totalSize: { $sum: "$size" } } } ]);
        const totalStorage = totalStorageResult.length > 0 ? totalStorageResult[0].totalSize : 0;
        
        // Find the most recent log entry instead of the most recent file for activity
        const recentLog = await ActivityLog.findOne().sort({ timestamp: -1 }).populate('user', 'username');
        
        // ** FIX **: Check if the user for the log still exists before creating the activity string
        let recentActivity = 'No recent activity';
        if (recentLog) {
            const userName = recentLog.user ? recentLog.user.username : 'A deleted user';
            recentActivity = `${userName} ${recentLog.activity.toLowerCase()}`;
        }

        res.json({
            userCount,
            fileCount,
            totalStorage,
            recentActivity
        });
    } catch (error) {
        console.error("Dashboard Stats Error:", error);
        res.status(500).json({ message: "Error fetching dashboard statistics." });
    }
});

app.get('/api/activity-log', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const logs = await ActivityLog.find().populate('user', 'username').sort({ timestamp: -1 });
        res.json(logs);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching activity logs.' });
    }
});

// --- Start the server ---
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
