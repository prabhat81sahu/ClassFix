require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_here'; 
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin123'; 
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'MISSING_KEY');

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json()); // CRITICAL: Allows server to read JSON body
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve HTML files

// --- MULTER SETUP FOR IMAGE UPLOADS ---
// Store files in memory (Buffer) to save into MongoDB (Buffer type)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- DATABASE CONNECTION (MongoDB) ---
// --- MODELS ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Student', 'Engineer', 'Admin'], default: 'Student' },
    domain: { type: String, enum: ['Hostel', 'Campus', 'All'], default: 'All' }, // For Engineer Specialization
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    receiveNotifications: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const complaintSchema = new mongoose.Schema({
    studentName: String,
    roomNumber: String,
    category: { type: String, enum: ['Hostel', 'Campus'], default: 'Campus' },
    issueType: String, // Dynamic based on category
    description: String,
    imageData: Buffer, // Binary data for the image
    imageMimeType: String,   // Mime type (e.g., image/png)
    status: { type: String, default: 'Pending' }, // Pending, In Progress, Resolved
    priority: { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium' },
    resolutionComment: { type: String, default: '' },
    resolvedAt: Date,
    aiIsRelated: { type: Boolean, default: null }, // Null=Not checked, True=Related, False=Not related
    aiSummary: { type: String, default: 'Pending AI Analysis' }
}, { timestamps: true });

const Complaint = mongoose.model('Complaint', complaintSchema);

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ message: "Access Denied" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        req.user = user;
        next();
    });
};

// --- EMAIL CONFIGURATION ---
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use your email provider (e.g., 'gmail', 'outlook')
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com', // Your Email
        pass: process.env.EMAIL_PASS || 'your-email-password'   // Your App Password
    }
});

// --- ROUTES ---

// 0. Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, firstName, middleName, lastName, email, password, role, adminCode, domain } = req.body;
        
        if (!username || !email || !password || !role) {
            return res.status(400).json({ message: 'Username, email, password, and role are required' });
        }
        // Check for existing user/email
        const usernameExists = await User.findOne({ username });
        if (usernameExists) {
            return res.status(409).json({ message: "Username already taken" });
        }
        const emailExists = await User.findOne({ email });
        if (emailExists) {
            return res.status(409).json({ message: "Email is already registered" });
        }

        // Require Admin Code for non-Student roles
        if ((role === 'Engineer' || role === 'Admin') && adminCode !== ADMIN_SECRET) {
            return res.status(403).json({ message: "Invalid Admin Code for this role" });
        }

        // Determine final domain: Admin get All, Students get All (default), Engineers get what they selected
        const finalDomain = (role === 'Engineer' && domain) ? domain : 'All';

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hashedPassword, role, domain: finalDomain });
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Registration failed", details: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(`Login Attempt: Username = "${username}"`); // Debug Log

        // Fix: Validate input to prevent crash if empty
        if (!username || !password) {
            return res.status(400).json({ message: "Please enter both username and password" });
        }

        const user = await User.findOne({ username });

        if (!user) {
            console.log("Login Failed: User not found in database."); // Debug Log
            return res.status(400).json({ message: "Invalid username or password" });
        }

        // Fix: Check if password hash exists in DB to prevent bcrypt crash
        if (!user.password) {
            console.error("Login Error: User found but password data is missing/corrupt.");
            return res.status(500).json({ message: "Account data error. Please ask admin to reset password." });
        }

        // To prevent user enumeration, we use a generic error message for both invalid username and password.
        // The `!user` check short-circuits to prevent an error if the user is not found.
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("Login Failed: Password does not match."); // Debug Log
            return res.status(400).json({ message: "Invalid username or password" });
        }

        console.log("Login Successful!"); // Debug Log
        const token = jwt.sign({ id: user.id, role: user.role, name: user.username, domain: user.domain || 'All' }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, role: user.role, username: user.username, domain: user.domain });
    } catch (error) {
        console.error("Login Error:", error);
        // Fix: Use 'message' key so frontend displays it correctly
        res.status(500).json({ message: "Login system error", details: error.message });
    }
});

// Forgot Password Route
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User with this email does not exist" });

        // Generate Token
        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send Email
        const resetUrl = `http://${req.headers.host}/reset-password.html?token=${token}`;
        const mailOptions = {
            to: user.email,
            from: 'ClassFix Support',
            subject: 'Password Reset Request',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                  `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                  `${resetUrl}\n\n` +
                  `If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'Reset link sent to email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error sending email' });
    }
});

// Reset Password Route
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ message: "Password reset token is invalid or has expired" });

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;
        await user.save();

        res.json({ message: "Password has been updated" });
    } catch (error) {
        res.status(500).json({ message: "Error resetting password" });
    }
});

// 4. Change Password
app.put('/api/users/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id; // from JWT

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: "Please provide both current and new passwords." });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect current password." });
        }

        // Hash new password and save
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;
        await user.save();

        res.json({ success: true, message: "Password changed successfully. Please log in again." });
    } catch (error) {
        console.error("Error changing password:", error);
        res.status(500).json({ message: "Server error while changing password." });
    }
});

// 5. Get User Profile
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('username email role receiveNotifications');
        if (!user) return res.status(404).json({ message: "User not found" }); // Fix: Prevents crash if DB was re-seeded
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Error fetching profile." });
    }
});

// 6. Update User Profile (Preferences)
app.put('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const { receiveNotifications } = req.body;
        const userId = req.user.id;
        
        await User.findByIdAndUpdate(userId, { receiveNotifications });
        
        res.json({ success: true, message: "Preferences updated." });
    } catch (error) {
        res.status(500).json({ message: "Error updating profile." });
    }
});

// 6.5. Get All Users (Admin Only)
app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: "Access Denied" });
    try {
        const users = await User.find().select('username email role domain receiveNotifications createdAt');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users" });
    }
});

// --- PUBLIC ROUTES (No Authentication Required) ---

// 0.5. Get Public Site Statistics for Landing Page
app.get('/api/public/stats', async (req, res) => {
    try {
        const totalComplaints = await Complaint.countDocuments();
        const resolvedComplaints = await Complaint.countDocuments({ status: 'Resolved' });
        res.json({
            totalComplaints: totalComplaints || 0,
            resolvedComplaints: resolvedComplaints || 0
        });
    } catch (error) {
        console.error("Error fetching public stats:", error);
        res.status(500).json({ error: "Failed to fetch public statistics" });
    }
});

// --- PROTECTED COMPLAINT ROUTES ---

// 1. Submit a Complaint
app.post('/api/complaints', authenticateToken, upload.single('complaintImage'), async (req, res) => {
    try {
        const complaintData = { ...req.body };
        complaintData.studentName = req.user.name; // Force linkage to the logged-in user

        if (req.file) {
            // Save buffer and mime type to database
            complaintData.imageData = req.file.buffer;
            complaintData.imageMimeType = req.file.mimetype;
        }

        // --- ALWAYS-ON AI ANALYSIS & AUTO-ROUTING ---
        if (process.env.GEMINI_API_KEY) {
            try {
                const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
                
                let prompt = `Act as an expert facility dispatcher. 
                A student has reported a "${complaintData.issueType}" issue with the description: "${complaintData.description}". 
                They *think* it belongs in the "${complaintData.category}" category.
                
                Your Jobs:
                1. Correct the category if they are wrong. 'Hostel' is for dorm rooms, beds, hostel bathrooms, hostel wifi. 'Campus' is for classrooms, labs, cafeterias, campus grounds, auditoriums.
                2. Provide a short 1-sentence summary of the problem.
                3. If an image is provided, determine if the image actually shows the reported issue. If no image is provided, set 'related' to null.

                Return a JSON object EXACTLY in this format: {"category": "Hostel" or "Campus", "summary": "Short explanation", "related": true/false/null}`;
                
                let contentArray = [prompt];

                if (req.file) {
                    contentArray.push({
                        inlineData: {
                            data: req.file.buffer.toString("base64"),
                            mimeType: req.file.mimetype
                        }
                    });
                }

                const result = await model.generateContent(contentArray);
                const responseText = result.response.text();
                
                // Parse the JSON. Gemini might wrap it in markdown block ```json
                const cleanedJson = responseText.replace(/```json/g, '').replace(/```/g, '').trim();
                const aiData = JSON.parse(cleanedJson);
                
                // AUTO-ROUTING: Override the student's selected category with the AI's determined category
                complaintData.category = aiData.category;
                
                // Strictly parse the related flag as Boolean or Null to fix the N/A bug
                let isRelated = null;
                if (aiData.related === true || String(aiData.related).toLowerCase() === 'true') {
                    isRelated = true;
                } else if (aiData.related === false || String(aiData.related).toLowerCase() === 'false') {
                    isRelated = false;
                }
                
                complaintData.aiIsRelated = isRelated;
                complaintData.aiSummary = aiData.summary;

                // IMAGE VERIFICATION: Hard block if AI determines image is fake or unrelated
                if (isRelated === false) {
                    return res.status(400).json({ 
                        error: "Image Verification Failed: AI analysis determined the uploaded image does not match the described issue. Please upload a clear, relevant photo or submit without an image." 
                    });
                }
            } catch (aiError) {
                console.error("AI Verification Failed:", aiError);
                complaintData.aiSummary = "AI analysis failed temporarily.";
                // On AI failure, default to the user's selected category so it still saves
            }
        } else {
            complaintData.aiSummary = "AI Verification disabled (No API Key).";
        }

        await Complaint.create(complaintData);
        res.status(201).json({ message: "Complaint submitted successfully!" });
    } catch (error) {
        console.error("Error submitting complaint:", error);
        res.status(500).json({ error: "Failed to save complaint", details: error.message });
    }
});

// 2. Get All Complaints (Protected - Engineer/Admin only)
app.get('/api/complaints', authenticateToken, async (req, res) => {
    try {
        let whereClause = {};
        // If the user is a Student, only return their own complaints
        if (req.user.role === 'Student') {
            whereClause = { studentName: req.user.name };
        } else if (req.user.role === 'Engineer' && req.user.domain !== 'All') {
            // Engineers only see their domain
            whereClause = { category: req.user.domain };
        }

        // Filter by issueType if provided
        if (req.query.issueType) {
            whereClause.issueType = req.query.issueType;
        }

        // Filter by category if provided
        if (req.query.category) {
            whereClause.category = req.query.category;
        }

        // Exclude the heavy 'imageData' BLOB from the list for performance
        const complaints = await Complaint.find(whereClause)
            .select('-imageData')
            .sort({ createdAt: -1 });

        // Add a virtual 'imageUrl' property pointing to the image route
        const results = complaints.map(c => {
            const json = c.toObject ? c.toObject() : c;
            // Mongoose object usually has .toJSON() or .toObject().
            // We need id, so ensure virtuals are used if using .toJSON(), but standard Mongo documents have _id.
            // Mongoose creates a virtual 'id' by default.
            json.id = c._id.toString(); // Fix: Ensure ID is a string for frontend compatibility
            if (json.imageMimeType) {
                json.imageUrl = `/api/complaints/${c.id}/image`;
            }
            return json;
        });
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch complaints" });
    }
});

// 2.1. Get Complaint Statistics
app.get('/api/complaints/stats', authenticateToken, async (req, res) => {
    try {
        const stats = await Complaint.aggregate([
            {
                $group: {
                    _id: "$status",
                    count: { $sum: 1 }
                }
            }
        ]);
        res.json(stats);
    } catch (error) {
        console.error("Error fetching stats:", error);
        res.status(500).json({ error: "Failed to fetch statistics" });
    }
});

// 2.2. Generate AI Summary of Current Complaints
app.get('/api/complaints/ai-summary', authenticateToken, async (req, res) => {
    try {
        if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'MISSING_KEY') {
            return res.json({ summaryHtml: "<div class='alert alert-warning'><i class='bi bi-exclamation-triangle'></i> AI Features are currently disabled (Missing API Key).</div>" });
        }

        let whereClause = {};
        // Engineers only summarize their own domain, Admins summarize everything
        if (req.user.role === 'Engineer' && req.user.domain !== 'All') {
            whereClause = { category: req.user.domain };
        }

        // Fetch active complaints (exclude resolved to save tokens and focus on current issues)
        const complaints = await Complaint.find({ ...whereClause, status: { $ne: 'Resolved' } })
            .select('roomNumber issueType priority -_id'); // Only grab what AI needs

        if (complaints.length === 0) {
            return res.json({ summaryHtml: "<div class='alert alert-success'><i class='bi bi-check-circle'></i> No active complaints to summarize at the moment. Great job!</div>" });
        }

        // Condense data for prompt
        const condensedData = complaints.map(c => `Room: ${c.roomNumber}, Issue: ${c.issueType}, Priority: ${c.priority}`).join('\n');
        
        try {
            const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
            const prompt = `
            Act as a facility manager data analyst. Analyze the following list of active infrastructure complaints.
            
            Tasks:
            1. Group the complaints by Room Number.
            2. If multiple people reported the exact same issue in the same room, COUNT them and highlight it as a highly reported issue.
            3. Provide a short, executive summary of the most critical problem areas.
            
            Format your response in clean, modern HTML. Use <h5> tags for room numbers, <ul> lists for issues, and <strong> for emphasis. Do NOT wrap the response in markdown code blocks like \`\`\`html. Just return the raw HTML string.
            
            Data:
            ${condensedData}
            `;

            const result = await model.generateContent(prompt);
            let htmlResponse = result.response.text();
            
            // Clean up markdown wrapping if Gemini ignores instructions
            htmlResponse = htmlResponse.replace(/```html/g, '').replace(/```/g, '').trim();

            res.json({ summaryHtml: htmlResponse });
        } catch (apiError) {
            console.error("Gemini API Error during summary:", apiError);
            res.json({ 
                summaryHtml: `
                <div class="alert alert-danger">
                    <h5><i class="bi bi-robot"></i> AI Analysis Temporarily Unavailable</h5>
                    <p class="small mb-0">The AI engine encountered an error or the API logic failed to generate a summary. Please review the ${complaints.length} active complaints manually below.</p>
                </div>` 
            });
        }
    } catch (error) {
        console.error("AI Summary Server Error:", error);
        res.status(500).json({ error: "Failed to generate AI summary due to a server error." });
    }
});

// 2.5. Get Complaint Image (Serve from DB)
app.get('/api/complaints/:id/image', async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint || !complaint.imageData) {
            return res.status(404).send('Image not found');
        }
        
        // Safety check for mimetype, fallback to jpeg if missing
        res.setHeader('Content-Type', complaint.imageMimeType || 'image/jpeg');
        res.send(complaint.imageData);
    } catch (error) {
        console.error("Error serving image:", error);
        res.status(500).send('Error fetching image');
    }
});

// 2.9 Batch Update Status (Grouped Complaints)
app.put('/api/complaints/batch', authenticateToken, async (req, res) => {
    const { ids, status, resolutionComment, priority } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "No complaint IDs provided." });
    }

    try {
        const updateData = { status };
        if (priority) {
            updateData.priority = priority;
        }

        // If resolved, add comment and timestamp
        if (status === 'Resolved') {
            updateData.resolutionComment = resolutionComment;
            updateData.resolvedAt = new Date();
        } else {
            // Reset resolution details if status changes back from Resolved
            updateData.resolutionComment = '';
            updateData.resolvedAt = null;
        }

        // Perform batch update in DB
        await Complaint.updateMany({ _id: { $in: ids } }, updateData);

        // Fetch the updated complaints to get student names and details for emails
        const updatedComplaints = await Complaint.find({ _id: { $in: ids } });

        // --- Send Email Notifications ---
        // Group by user to prevent spamming the same user multiple times if they submitted identical complaints
        const studentsToEmail = {};
        for (const complaint of updatedComplaints) {
            if (!studentsToEmail[complaint.studentName]) {
                studentsToEmail[complaint.studentName] = [];
            }
            studentsToEmail[complaint.studentName].push(complaint);
        }

        Object.keys(studentsToEmail).forEach(async (studentName) => {
            const complaintsForUser = studentsToEmail[studentName];
            try {
                const studentUser = await User.findOne({ username: studentName });
                if (studentUser && studentUser.email && studentUser.receiveNotifications) {
                    // Mention the number of identical reports if > 1
                    const reportCountStr = complaintsForUser.length > 1 ? ` (applicable to ${complaintsForUser.length} reports you submitted)` : '';
                    const sampleComplaint = complaintsForUser[0];

                    const mailOptions = {
                        to: studentUser.email,
                        from: 'ClassFix Support',
                        subject: `Complaint Status Updated: ${status}`,
                        text: `Hello ${studentName},\n\n` +
                              `The status of your complaint regarding "${sampleComplaint.issueType}" in ${sampleComplaint.roomNumber}${reportCountStr} has been updated to: ${status}.\n\n` +
                              (status === 'Resolved' ? `Resolution Comment: ${resolutionComment}\n\n` : '') +
                              `Thank you,\nClassFix Team`
                    };
                    // Send asynchronously
                    transporter.sendMail(mailOptions).catch(err => console.error("Email send failed:", err));
                }
            } catch (emailErr) {
                console.error("Error finding user for batch email:", emailErr);
            }
        });

        res.json({ success: true, message: "Batch update successful." });
    } catch (error) {
        console.error("Batch update error:", error);
        res.status(500).json({ message: "Server error during batch update" });
    }
});

// 3. Update Status (THE FIX FOR YOUR BUG)
app.put('/api/complaints/:id', authenticateToken, async (req, res) => {
    const { status, resolutionComment, priority } = req.body;
    const { id } = req.params;

    try {
        const complaint = await Complaint.findById(id);
        if (!complaint) {
            return res.status(404).json({ message: "Complaint not found" });
        }

        const updateData = { status };
        if (priority) {
            updateData.priority = priority;
        }
        
        // If resolved, add comment and timestamp
        if (status === 'Resolved') {
            updateData.resolutionComment = resolutionComment;
            updateData.resolvedAt = new Date();
        } else {
            // Reset resolution details if status changes back from Resolved
            updateData.resolutionComment = '';
            updateData.resolvedAt = null;
        }

        Object.assign(complaint, updateData);
        await complaint.save();

        // --- Send Email Notification ---
        try {
            const studentUser = await User.findOne({ username: complaint.studentName });
            if (studentUser && studentUser.email && studentUser.receiveNotifications) {
                const mailOptions = {
                    to: studentUser.email,
                    from: 'ClassFix Support',
                    subject: `Complaint Status Updated: ${status}`,
                    text: `Hello ${complaint.studentName},\n\n` +
                          `The status of your complaint regarding "${complaint.issueType}" in ${complaint.roomNumber} has been updated to: ${status}.\n\n` +
                          (status === 'Resolved' ? `Resolution Comment: ${resolutionComment}\n\n` : '') +
                          `Thank you,\nClassFix Team`
                };
                // Send asynchronously
                transporter.sendMail(mailOptions).catch(err => console.error("Email send failed:", err));
            }
        } catch (emailErr) {
            console.error("Error finding user for email:", emailErr);
        }

        res.json({ success: true, data: complaint });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error updating status" });
    }
});


// --- START SERVER AFTER DB CONNECTION ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/college_db';

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log("MongoDB Connected Successfully.");
        // Start Server only after the database is connected
        startServer(PORT);
    })
    .catch(err => console.error("Fatal DB Connection Error:", err));

// Dynamic Port Allocation
function startServer(portToTry) {
    const server = app.listen(portToTry, () => {
        console.log(`\n================================`);
        console.log(`Server running at http://localhost:${portToTry}`);
        console.log(`Student Dashboard: http://localhost:${portToTry}/student.html`);
        console.log(`Engineer View: http://localhost:${portToTry}/engineer.html`);
        console.log(`Admin Portal: http://localhost:${portToTry}/admin.html`);
        console.log(`================================\n`);
    });

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.log(`Port ${portToTry} is busy, trying port ${portToTry + 1}...`);
            startServer(portToTry + 1);
        } else {
            console.error(err);
        }
    });
}
