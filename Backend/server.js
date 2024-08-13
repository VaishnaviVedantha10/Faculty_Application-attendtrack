const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { promisify } = require('util');
const bcrypt = require('bcrypt');


dotenv.config();

const app = express();
const PORT = process.env.PORT;
const SALT_ROUNDS = 10;
const URL = process.env.REACT_APP_API_BASE_URL;

// Database connection pool
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  insecureAuth: true,
  connectionLimit: 100,
  queueLimit: 0
});

app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'faculty_id', 'stored-rollnumber'],
  credentials: true,
}));

// Generate random token
const generateToken = async () => {
  const randomBytes = promisify(crypto.randomBytes);
  const tokenBuffer = await randomBytes(20);
  return tokenBuffer.toString('hex');
};

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  let connection;
  try {
    console.log('Received login request for email:', email);

    connection = await pool.getConnection();
    const [loginRows] = await connection.query(
      'SELECT email, facultyid, password FROM faculty_login WHERE email = ?',
      [email]
    );

    // Log the fetched rows to check the data
    console.log('Fetched rows from database:', loginRows);

    if (loginRows.length > 0) {
      const user = loginRows[0];

      // Log the user object to check its properties
      console.log('User object:', user);

      // Directly compare plaintext passwords
      if (password !== user.password) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Log the response data before sending it
      console.log('Responding with user details:', {
        email: user.email,
        facultyId: user.facultyid // Ensure this field is present
      });

      // Respond with user details including facultyId
      res.status(200).json({
        message: 'Login successful',
        user: {
          email: user.email,
          facultyId: user.facultyid // Ensure this field is present
        }
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Error occurred during login:', error);
    res.status(500).json({ error: 'Login failed. Please try again.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});



// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER_EMAIL,
    pass: process.env.USER_PASSWORD,
  },
  secure: true,
  port: 465,
});

// Forgot password endpoint
app.post('/forgotpassword', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [user] = await connection.query('SELECT 1 FROM faculty_login WHERE email = ? LIMIT 1', [email]);

    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const resetToken = await generateToken();
    const resetLink = `${URL}/resetpassword/${resetToken}`;

    await connection.query(
      'INSERT INTO faculty_password_reset_tokens (email, token, expires_at) VALUES (?, ?, NOW() + INTERVAL 1 HOUR)',
      [email, resetToken]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
      <p>Hi,</p>
      <p>We received a request to reset your password for your account. If you did not make this request, please ignore this email.</p>
      <p>To reset your password, please click the link below:</p>
      <p><a href="${resetLink}">Reset Password</a></p>
      <p>Thank you,<br>
      Support Team</p>
    `,
    };

    await transporter.sendMail(mailOptions);
    return res.status(200).json({ message: 'Password reset email sent successfully.' });
  } catch (error) {
    console.error('Error during forgot password request:', error);
    return res.status(500).json({ error: 'Could not send reset email. Please try again later.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Reset password endpoint
app.post('/resetpassword/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    // Check if the token is valid
    const [tokenData] = await connection.query(
      'SELECT email FROM faculty_password_reset_tokens WHERE token = ? AND expires_at > NOW()',
      [token]
    );

    if (tokenData.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    const email = tokenData[0].email;

    // Update the password without hashing
    await connection.query(
      'UPDATE faculty_login SET password = ? WHERE email = ?',
      [password, email]
    );

    // Remove the reset token
    await connection.query(
      'DELETE FROM faculty_password_reset_tokens WHERE token = ?',
      [token]
    );

    return res.status(200).json({ message: 'Password reset successful.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ error: 'Password reset failed. Please try again later.' });
  } finally {
    if (connection) connection.release();
  }
});

//Fetch Subject name Endpoint
app.get('/facultySubjects', async (req, res) => {
  let connection = null;

  try {
      connection = await pool.getConnection();
      const facultyId = req.query.facultyId;

      if (!facultyId) {
          return res.status(400).json({ error: 'Faculty ID is required.' });
      }

      const [rows] = await connection.query(
          'SELECT subject_code, subject_name FROM faculty_permissions WHERE facultyid = ?',
          [facultyId]
      );

      if (rows.length === 0) {
          return res.status(404).json({ error: 'No subjects found for the specified faculty.' });
      }

      // Initialize empty arrays to hold split codes and names
      let subjectCodes = [];
      let subjectNames = [];

      rows.forEach(row => {
          // Split the comma-separated values
          const codes = row.subject_code.split(',');
          const names = row.subject_name.split(',');

          // Combine them into arrays
          subjectCodes = [...subjectCodes, ...codes];
          subjectNames = [...subjectNames, ...names];
      });

      // Create an array of subject objects
      const subjects = subjectCodes.map((code, index) => ({
          subject_code: code,
          subject_name: subjectNames[index] || '' // Handle potential mismatch in lengths
      }));

      // Log the subjects to verify
      console.log('Subjects:', subjects);

      res.status(200).json({ subjects });
  } catch (error) {
      console.error('Error occurred while fetching subjects:', error);
      res.status(500).json({ error: 'Unable to fetch subjects. Please try again later.', details: error.message });
  } finally {
      if (connection) connection.release();
  }
});

//Fetch student details endpoint
app.get('/facultydashboard', async (req, res) => {
  let connection = null;

  try {
    connection = await pool.getConnection();
    
    const { startDate, endDate } = req.query;
    const facultyId = req.headers['faculty_id'];

    console.log('Received startDate:', startDate, 'endDate:', endDate, 'facultyId:', facultyId);

    // Query for attendance records
    let query = `
      SELECT sd.*
      FROM student_details sd
      JOIN faculty_permissions fp ON sd.subject_code = fp.subject_code
      WHERE fp.facultyid = ?`;

    const params = [facultyId];

    if (startDate && endDate) {
      query += ' AND DATE(sd.created_at) BETWEEN ? AND ?';
      params.push(startDate, endDate);
    } else if (startDate) {
      query += ' AND DATE(sd.created_at) >= ?';
      params.push(startDate);
    } else if (endDate) {
      query += ' AND DATE(sd.created_at) <= ?';
      params.push(endDate);
    }
    
    query += ' ORDER BY sd.created_at DESC';

    console.log('Generated SQL query for attendance records:', query, 'with params:', params);

    const [attendanceRecords] = await connection.query(query, params);

    console.log('Attendance Records:', attendanceRecords);

    // Get the roll numbers of students who are present
    const presentStudentRollNumbers = new Set(attendanceRecords.map(student => student.roll_number));
    console.log('Present Student Roll Numbers:', presentStudentRollNumbers);

    // Fetch all students from the student_records table
    const [allStudents] = await connection.query('SELECT * FROM student_records');
    console.log('All Students:', allStudents);

    // Determine absent students
    const absentStudents = allStudents.filter(student => !presentStudentRollNumbers.has(student.roll_number));
    console.log('Absent Students:', absentStudents);

    // Send the response
    res.status(200).json({ attendanceRecords, presentStudents: Array.from(presentStudentRollNumbers), absentStudents });
  } catch (error) {
    console.error('Error occurred while fetching attendance records:', error);
    res.status(500).json({ error: 'Unable to fetch attendance records. Please try again later.', details: error.message });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});


//AttendanceStatus Endpoint
app.post('/updateAttendanceStatus', async (req, res) => {
  let connection = null;

  try {
    connection = await pool.getConnection();

    const { roll_number, faculty_id } = req.body; // Retrieve roll_number and faculty_id from request body
    console.log('Received roll_number:', roll_number, 'faculty_id:', faculty_id);

    // Query the faculty_permissions table to get the subject_code based on the faculty_id
    const permissionQuery = 'SELECT subject_code FROM faculty_permissions WHERE facultyid = ?';
    const [permissionRows] = await connection.query(permissionQuery, [faculty_id]);

    if (permissionRows.length === 0) {
      return res.status(404).json({ error: 'No permissions found for the specified faculty.' });
    }

    const subjectCode = permissionRows[0].subject_code;

    // Query the student_records table to get the student's information based on the roll_number
    const studentQuery = 'SELECT student_id, name, email, mobile_number FROM student_records WHERE roll_number = ?';
    const [studentRows] = await connection.query(studentQuery, [roll_number]);

    if (studentRows.length === 0) {
      return res.status(404).json({ error: 'No student found with the specified roll_number.' });
    }

    const { student_id, name, email, mobile_number } = studentRows[0];

    // Query the faculty_permissions table to get the subject_name based on the subject_code
    const qrCodeQuery = 'SELECT subject_name FROM faculty_permissions WHERE subject_code = ?';
    const [qrCodeRows] = await connection.query(qrCodeQuery, [subjectCode]);

    if (qrCodeRows.length === 0) {
      return res.status(404).json({ error: 'No subject_name found for the specified subject_code.' });
    }

    const subjectName = qrCodeRows[0].subject_name;

    // Construct the SQL query to insert into the student_details table
    const updateQuery = `
      INSERT INTO student_details (subject_code, subject_name, registrant_id, roll_number, name, email, mobile_number, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`;

    const updateParams = [subjectCode, subjectName, student_id, roll_number, name, email, mobile_number];

    console.log('Generated SQL query:', updateQuery, 'with params:', updateParams);

    const [updateResult] = await connection.query(updateQuery, updateParams);
    console.log('Update result:', updateResult);

    if (updateResult.affectedRows > 0) {
      res.status(200).json({ message: 'Attendance marked successfully.' });
    } else {
      res.status(500).json({ error: 'Failed to mark attendance.' });
    }
  } catch (error) {
    console.error('Error occurred while marking attendance:', error);
    res.status(500).json({ error: 'Unable to mark attendance. Please try again later.', details: error.message });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});




app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
