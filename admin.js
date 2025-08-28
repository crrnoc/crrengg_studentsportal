// admin.js
const express = require('express');
const multer = require('multer');
const path = require('path');
const ExcelJS = require("exceljs");
const fs = require('fs');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const router = express.Router();
const db = require("./db"); // ✅ adjust path as per your setup

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

// Simple file upload & log in DB
router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const { originalname, mimetype, size, filename } = req.file;
    await db.query(
      "INSERT INTO uploaded_files (filename, originalname, mimetype, size) VALUES (?, ?, ?, ?)",
      [filename, originalname, mimetype, size]
    );

    res.json({ message: "File uploaded and saved to database!" });
  } catch (err) {
    console.error("Upload failed:", err);
    res.status(500).json({ message: "Upload failed!" });
  }
});

// File parsing & inserting student data
router.post('/admin/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('No file uploaded.');

  const ext = path.extname(file.originalname).toLowerCase();

  try {
    let records = [];

    // Excel or CSV
    if (ext === '.xlsx' || ext === '.xls' || ext === '.csv') {
      const workbook = new ExcelJS.Workbook();
      if (ext === '.csv') {
        await workbook.csv.readFile(file.path);
      } else {
        await workbook.xlsx.readFile(file.path);
      }
      const worksheet = workbook.worksheets[0];
      worksheet.eachRow((row, rowNumber) => {
        if (rowNumber === 1) return; // skip header
        records.push({
          userId: row.getCell(1).value,
          name: row.getCell(2).value,
          dob: row.getCell(3).value,
          reg_no: row.getCell(4).value,
          unique_id: row.getCell(5).value,
          year: row.getCell(6).value,
          course: row.getCell(7).value,
          semester: row.getCell(8).value,
          aadhar_no: row.getCell(9).value,
          mobile_no: row.getCell(10).value,
          email: row.getCell(11).value,
        });
      });
    }
    // PDF
    else if (ext === '.pdf') {
      const dataBuffer = fs.readFileSync(file.path);
      const data = await pdfParse(dataBuffer);
      records = extractFromText(data.text);
    }
    // DOCX
    else if (ext === '.docx') {
      const data = await mammoth.extractRawText({ path: file.path });
      records = extractFromText(data.value);
    }
    else {
      return res.status(400).send('Unsupported file format.');
    }

    // Insert into DB
    for (const record of records) {
      await db.query(
        `INSERT INTO noc.students 
        (userId, name, dob, reg_no, unique_id, year, course, semester, aadhar_no, mobile_no, email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          record.userId, record.name, record.dob, record.reg_no, record.unique_id,
          record.year, record.course, record.semester, record.aadhar_no, record.mobile_no, record.email
        ]
      );
    }

    res.json({ message: 'Data inserted successfully.' });

  } catch (err) {
    console.error(err);
    res.status(500).send('Error processing file.');
  } finally {
    fs.unlinkSync(file.path); // Cleanup
  }
});

// Helper: parse plain text into student records
function extractFromText(text) {
  const lines = text.split('\n').filter(Boolean);
  const records = [];

  for (let line of lines) {
    const parts = line.split(','); // assuming comma-separated
    if (parts.length >= 11) {
      records.push({
        userId: parts[0]?.trim(),
        name: parts[1]?.trim(),
        dob: parts[2]?.trim(),
        reg_no: parts[3]?.trim(),
        unique_id: parts[4]?.trim(),
        year: parts[5]?.trim(),
        course: parts[6]?.trim(),
        semester: parts[7]?.trim(),
        aadhar_no: parts[8]?.trim(),
        mobile_no: parts[9]?.trim(),
        email: parts[10]?.trim(),
      });
    }
  }
  return records;
}

// Login route
router.post("/login", async (req, res) => {
  const { userId, password, role } = req.body;

  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE userId = ? AND role = ?",
      [userId, role]
    );

    if (rows.length === 0) {
      return res.json({ success: false, message: "User not found or role mismatch." });
    }

    const user = rows[0];

    // Direct password comparison
    if (user.password !== password) {
      return res.json({ success: false, message: "Invalid password." });
    }

    res.json({ success: true, userId: user.userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;
