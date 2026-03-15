require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Sequelize, DataTypes } = require('sequelize');
const mysql = require('mysql2/promise');
const { URL } = require('url');

// Connect to MySQL
const sequelize = new Sequelize(process.env.MYSQL_URI || 'mysql://root:@localhost:3306/Prabhat_DB', {
    dialect: 'mysql',
    logging: false
});

// --- MODELS (Must match server.js) ---
const User = sequelize.define('User', {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    firstName: { type: DataTypes.STRING },
    lastName: { type: DataTypes.STRING },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.ENUM('Student', 'Engineer', 'Admin'), defaultValue: 'Student' },
    domain: { type: DataTypes.ENUM('Hostel', 'Campus', 'All'), defaultValue: 'All' },
    resetPasswordToken: DataTypes.STRING,
    resetPasswordExpires: DataTypes.DATE,
    receiveNotifications: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { timestamps: true });

const Complaint = sequelize.define('Complaint', {
    studentName: DataTypes.STRING,
    roomNumber: DataTypes.STRING,
    category: { type: DataTypes.ENUM('Hostel', 'Campus'), defaultValue: 'Campus' },
    issueType: DataTypes.STRING,
    description: DataTypes.TEXT,
    imageData: DataTypes.BLOB('long'),
    imageMimeType: DataTypes.STRING,
    status: { type: DataTypes.STRING, defaultValue: 'Pending' },
    priority: { type: DataTypes.ENUM('Low', 'Medium', 'High'), defaultValue: 'Medium' },
    resolutionComment: { type: DataTypes.TEXT, defaultValue: '' },
    resolvedAt: DataTypes.DATE,
    aiIsRelated: { type: DataTypes.BOOLEAN, defaultValue: null },
    aiSummary: { type: DataTypes.STRING, defaultValue: 'Pending AI Analysis' }
}, { timestamps: true });

// --- SEED FUNCTION ---
const seedDatabase = async () => {
    try {
        // 1. Parse URI and automatically create database if it doesn't exist
        const uriStr = process.env.MYSQL_URI || 'mysql://root:@localhost:3306/Prabhat_DB';
        const uri = new URL(uriStr);
        const databaseName = uri.pathname.replace('/', '');
        
        const connection = await mysql.createConnection({
            host: uri.hostname,
            port: uri.port || 3306,
            user: uri.username,
            password: uri.password
        });
        await connection.query(`CREATE DATABASE IF NOT EXISTS \`${databaseName}\`;`);
        await connection.end();

        // 2. Connect via Sequelize
        await sequelize.authenticate();
        console.log("MySQL Connected");

        // Sync and clear: force: true recreates the tables
        await sequelize.sync({ force: true });
        console.log("Database cleared and tables created.");

        // 2. Create Users
        const hashedPassword = await bcrypt.hash('123456', 10); // Default password for all
        const adminPassword = await bcrypt.hash('admin123', 10); // Custom Admin Password

        const users = [
            { username: 'admin', firstName: 'Admin', lastName: 'User', email: 'admin@college.edu', password: adminPassword, role: 'Admin', domain: 'All' },
            { username: 'engineer', firstName: 'Campus', lastName: 'Engineer', email: 'engineer@college.edu', password: hashedPassword, role: 'Engineer', domain: 'Campus' },
            { username: 'student', firstName: 'John', lastName: 'Doe', email: 'student@college.edu', password: hashedPassword, role: 'Student', domain: 'All' }
        ];

        await User.bulkCreate(users);
        console.log("Users created: admin, engineer, student (Password: 123456)");
        console.log("Admin created with Password: admin123");

        // 3. Create Sample Complaints
        const complaints = [
            {
                studentName: "student",
                roomNumber: "Lab-101",
                category: "Campus",
                issueType: "Projector",
                description: "Projector is flickering and turning off automatically.",
                status: "Pending",
                priority: "High"
            },
            {
                studentName: "student",
                roomNumber: "Class-202",
                category: "Campus",
                issueType: "AC / Cooling",
                description: "AC is not cooling the room.",
                status: "In Progress",
                priority: "Medium"
            }
        ];

        await Complaint.bulkCreate(complaints);
        console.log("Sample complaints created for user 'student'.");

        console.log("Database seeded successfully!");
        process.exit();
    } catch (error) {
        if (error.name === 'SequelizeAccessDeniedError' || error.code === 'ER_ACCESS_DENIED_ERROR' || error.message.includes('Access denied')) {
            console.error("\n❌ MYSQL ACCESS DENIED: The password in your .env file is incorrect for the 'root' user.");
            console.error("Please edit the .env file and put your real MySQL password.\n");
        } else {
            console.error("Error seeding database:", error);
        }
        process.exit(1);
    }
};

seedDatabase();