const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Create a Nodemailer transporter object using Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER_EMAIL,
    pass: process.env.USER_PASSWORD, // Your App Password
  },
  secure: true, // Use TLS
  port: 465, // SMTP port for TLS
});

// Email options
const mailOptions = {
  from: process.env.EMAIL_USER,
  to: 'yajaman2000@gmail.com', // Replace with recipient's email
  subject: 'Test Email from Nodemailer',
  text: 'This is a test email sent using Nodemailer!',
  html: '<p>This is a <strong>test</strong> email sent using Nodemailer!</p>',
};

// Send email
transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.log('Error sending email:', error);
  }
  console.log('Email sent successfully:', info.response);
});
