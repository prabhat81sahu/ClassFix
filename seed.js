require('dotenv').config();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/college_db';

// --- SCHEMAS (Must match server.js) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Student', 'Engineer', 'Admin'], default: 'Student' },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    receiveNotifications: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const complaintSchema = new mongoose.Schema({
    studentName: String,
    roomNumber: String,
    issueType: String,
    description: String,
    imageData: Buffer,
    imageMimeType: String,
    status: { type: String, default: 'Pending' },
    priority: { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium' },
    resolutionComment: { type: String, default: '' },
    resolvedAt: Date
}, { timestamps: true });

const Complaint = mongoose.model('Complaint', complaintSchema);

// --- SEED FUNCTION ---
const seedDatabase = async () => {
    try {
        // Connect to MongoDB
        await mongoose.connect(MONGO_URI);
        console.log("MongoDB Connected");

        // Sync and clear
        // In MongoDB we delete documents
        await User.deleteMany({});
        await Complaint.deleteMany({});

        // 1. Clear existing data
        console.log("Database cleared and tables created.");

        // 2. Create Users
        const hashedPassword = await bcrypt.hash('123456', 10); // Default password for all
        const adminPassword = await bcrypt.hash('admin123', 10); // Custom Admin Password

        const users = [
            { username: 'admin', email: 'admin@college.edu', password: adminPassword, role: 'Admin' },
            { username: 'engineer', email: 'engineer@college.edu', password: hashedPassword, role: 'Engineer' },
            { username: 'student', email: 'student@college.edu', password: hashedPassword, role: 'Student' }
        ];

        await User.insertMany(users);
        console.log("Users created: admin, engineer, student (Password: 123456)");
        console.log("Admin created with Password: admin123");

        // 3. Create Sample Complaints
        const complaints = [
            {
                studentName: "student",
                roomNumber: "Lab-101",
                issueType: "Projector",
                description: "Projector is flickering and turning off automatically.",
                status: "Pending",
                priority: "High"
            },
            {
                studentName: "student",
                roomNumber: "Class-202",
                issueType: "AC / Cooling",
                description: "AC is not cooling the room.",
                status: "In Progress",
                priority: "Medium"
            }
        ];

        await Complaint.insertMany(complaints);
        console.log("Sample complaints created for user 'student'.");

        console.log("Database seeded successfully!");
        process.exit();
    } catch (error) {
        console.error("Error seeding database:", error);
        process.exit(1);
    }
};

seedDatabase();