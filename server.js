require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const cors = require('cors');
const path = require("path");
const bcrypt = require('bcrypt');
const fs = require('fs');
const multer = require('multer');
const adminRoutes = require("./admin");

const app = express();

// ✅ PORT (Cloud Run)
const PORT = process.env.PORT || 8080;

// =============================
// MIDDLEWARES
// =============================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Serve static frontend (HTML, CSS, JS, images) from public/
app.use(express.static(path.join(__dirname, "public")));

// ✅ Favicon handler → avoid 500 error
app.get('/favicon.ico', (req, res) => res.status(204).end());

// =============================
// SESSION + MYSQL STORE + POOL
// =============================
// Base DB config
let dbConfig = {
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// 🔹 Use Cloud SQL Unix socket if deployed on Google Cloud
if (process.env.CLOUD_SQL_CONNECTION && process.env.CLOUD_SQL_CONNECTION !== "") {
  dbConfig.socketPath = `/cloudsql/${process.env.CLOUD_SQL_CONNECTION}`;
} else {
  // 🔹 Fallback to TCP (local / Render / other)
  dbConfig.host = process.env.MYSQLHOST;
  dbConfig.port = process.env.MYSQLPORT;
}

// ✅ Create Pool
const pool = mysql.createPool(dbConfig);

// ✅ Session Store (connects via pool)
const sessionStore = new MySQLStore({}, pool);

app.use(session({
  key: 'noc_sid',
  secret: 'sircrrengg@123',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 15 * 60 * 1000 }, // 15 min
  rolling: true
}));

// ✅ Test DB connection
pool.getConnection((err, conn) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Connected to MySQL database');
    conn.release();
  }
});

// ✅ Export pool for use in routes
module.exports = pool;


// =============================
// FILE UPLOADS
// =============================
const upload = multer({ dest: 'uploads/' });
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir));

// =============================
// ROUTES
// =============================

// Root → serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 🔐 Admin API routes
app.use("/admin", adminRoutes);

// Middleware to protect admin pages
function requireAdminSession(req, res, next) {
  if (req.session.userId && ['admin','exam','accounts','hod','student','staff'].includes(req.session.role)) return next();
  res.redirect('/index.html');
}

// ✅ Check session
app.get('/check-session', (req, res) => {
  if (req.session.userId && ['admin','exam','accounts','hod','student','staff'].includes(req.session.role)) {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});

// ✅ Admin HTML routes
const adminPages = {
  "/adminpanel": "adminpanel.html",
  "/uploadresults": "uploadresultsAd.html",
  "/uploadsbi": "upload-sbi.html",
  "/dumatch": "du-match-status.html",
  "/uploadattendance": "uploadattendanceAd.html",
  "/nocstatus": "noc-status.html",
  "/removestudents": "removestudents.html",
  "/createnoc": "createnocAd.html",
  "/uploadstudents": "uploadstudents.html",
  "/uploadmidmarks": "uploadmid-marks.html",
  "/addmycounselling": "addmycounselling.html",
  "/examcell": "examcell.html",
  "/studentsfeesearch": "studentsfeesearch.html",
  "/staffallocation": "staffallocation.html",
  "/downloadattendance": "downloadattendance.html",
  "/editattendance": "editattendance.html",
  "/sendsms": "sendsms.html"
};
for (let route in adminPages) {
  app.get(route, requireAdminSession, (req,res) => {
    res.sendFile(path.join(__dirname,"public",adminPages[route]));
  });
}

// ✅ Login
// =============================
// LOGIN ROUTE
// =============================
app.post('/login', (req, res) => {
  let response = {
    success: false,
    message: "",
    userId: null,
    role: null,
    redirectTo: null
  };

  try {
    const { userId, password, role } = req.body;

    if (!userId || !password || !role) {
      response.message = "Missing credentials";
      return res.status(400).json(response);
    }

    pool.query(
      'SELECT * FROM users WHERE userId = ? AND role = ?',
      [userId, role],
      (err, results) => {
        if (err) {
          console.error("❌ DB Query Error:", err);
          response.message = "Database error";
          return res.status(500).json(response);
        }

        if (results.length === 0) {
          response.message = 'Invalid credentials or role mismatch';
          return res.status(401).json(response);
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err2, isMatch) => {
          if (err2) {
            console.error("❌ Bcrypt Error:", err2);
            response.message = "Password check error";
            return res.status(500).json(response);
          }

          if (!isMatch) {
            response.message = 'Incorrect password';
            return res.status(401).json(response);
          }

          // ✅ Save session
          req.session.userId = userId;
          req.session.role = role;

          // ✅ Role-based redirect
          switch (role) {
            case "student": response.redirectTo = `/student/${userId}`; break;
            case "staff": response.redirectTo = `/staff/${userId}`; break;
            case "admin": response.redirectTo = `/adminpanel`; break;
            case "hod": response.redirectTo = `/hodpanel.html`; break;
            case "exam": response.redirectTo = `/examcell`; break;
            case "accounts": response.redirectTo = `/accounts.html`; break;
          }

          // ✅ Success response
          response.success = true;
          response.message = 'Login successful';
          response.userId = userId;
          response.role = role;

          return res.status(200).json(response);
        });
      }
    );
  } catch (error) {
    console.error("🔥 Login route error:", error);
    response.message = "Server error";
    return res.status(500).json(response);
  }
});


// =============================
// ERROR HANDLERS (always JSON)
// =============================
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Page not found" });
});

app.use((err, req, res, next) => {
  console.error("🔥 Server error:", err.stack);
  if (!res.headersSent) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// =============================
// START SERVER
// =============================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});


//email otp
// Store OTPs temporarily in memory (for demo purpose only)
const otpMap = new Map();

// 1️⃣ Send OTP
app.post('/send-otp', (req, res) => {
  const { userId, email } = req.body;

  // First try from students
  connection.query('SELECT email FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err) return res.json({ success: false, message: "Server error" });

    if (results.length > 0 && results[0].email === email) {
      return sendOtpToEmail(userId, email, res); // student match
    }

    // Try from staff
    connection.query('SELECT staff_email FROM staff WHERE staff_id = ?', [userId], (err2, results2) => {
      if (err2 || results2.length === 0 || results2[0].staff_email !== email) {
        return res.json({ success: false, message: "User ID and email don't match." });
      }

      // staff match
      return sendOtpToEmail(userId, email, res);
    });
  });
});

function sendOtpToEmail(userId, email, res) {
  const otp = Math.floor(100000 + Math.random() * 900000);
  otpMap.set(userId, otp.toString());

  const mailOptions = {
    from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
    to: email,
    subject: "Your OTP for Password Reset",
    text: `Your OTP is ${otp}. It will expire in 10 minutes.`,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) return res.json({ success: false, message: "Failed to send email." });

    setTimeout(() => otpMap.delete(userId), 10 * 60 * 1000); // expire OTP after 10 minutes
    res.json({ success: true });
  });
}


// 2️⃣ Verify OTP
app.post('/verify-otp', (req, res) => {
  const { userId, otp } = req.body;
  const storedOtp = otpMap.get(userId);
  if (storedOtp && storedOtp === otp) {
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});


// 3️⃣ Reset Password with hashing
app.post('/reset-password', async (req, res) => {
  const { userId, newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    connection.query(
      'UPDATE users SET password = ? WHERE userId = ?',
      [hashedPassword, userId],
      (err, result) => {
        if (err || result.affectedRows === 0) {
          return res.json({ success: false, message: "User not found or update failed." });
        }

        otpMap.delete(userId);
        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Hashing error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// 👤 Get student details
app.get('/student/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT * FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    res.json(results[0]);
  });
});

// ✏️ Update student profile
app.post("/editprofile", upload.single("photo"), async (req, res) => {
  const {
    userId,
    name,
    dob,
    reg_no,
    uniqueId,
    year,
    course,
    dept_code,
    semester,
    aadhar_no,
    mobile_no,
    email,
    father_name,
    father_mobile,
    admission_type,
    section,
    counsellor_name,
    counsellor_mobile
  } = req.body;

  const file = req.file;
  console.log("📥 Edit Profile Req:", req.body);

  try {
    let photo_url = null;
    let public_id = null;

    if (file) {
      const result = await cloudinary.uploader.upload(file.path, {
        public_id: `students/${reg_no}`,
        overwrite: true,
        resource_type: "image"
      });
      photo_url = result.secure_url;
      public_id = result.public_id;
      fs.unlinkSync(file.path);
    }

    const updateFields = [
      name,
      dob || null,
      reg_no,
      uniqueId,
      year,
      course,
      dept_code,
      semester,
      aadhar_no,
      mobile_no,
      email,
      father_name,
      father_mobile,
      admission_type,
      section,
      counsellor_name,
      counsellor_mobile
    ];

    let sql = `
      UPDATE students SET
        name=?,
        dob=?,
        reg_no=?,
        uniqueId=?,
        year=?,
        course=?,
        dept_code=?,
        semester=?,
        aadhar_no=?,
        mobile_no=?,
        email=?,
        father_name=?,
        father_mobile=?,
        admission_type=?,
        section=?,
        counsellor_name=?,
        counsellor_mobile=?`;

    if (photo_url) {
      sql += `, photo_url=?, photo_public_id=?`;
      updateFields.push(photo_url, public_id);
    }

    sql += ` WHERE userId=?`;
    updateFields.push(userId);

    connection.query(sql, updateFields, (err, result) => {
      if (err) {
        console.error("❌ SQL Error:", err);
        return res.status(500).json({ message: "Profile update failed" });
      }
      console.log("✅ Profile updated for:", userId);
      return res.status(200).json({ message: "Profile updated successfully!" });
    });

  } catch (err) {
    console.error("❌ Error:", err);
    if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    return res.status(500).json({ message: "Server error" });
  }
});


// 🚀 Start server (only once!)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


//message route for staff

app.post('/send-bulk-notification', async (req, res) => {
  let { userIds, message } = req.body;

  console.log("🔥 HIT /send-bulk-notification");
  console.log("👉 Request Body:", req.body);

  if (typeof userIds === 'string') userIds = [userIds];
  if (!Array.isArray(userIds) || userIds.length === 0 || !message) {
    console.log("❌ Invalid input");
    return res.status(400).json({ success: false, message: "Invalid input" });
  }

  let sent = 0;
  let failed = 0;

  for (const userId of userIds) {
    console.log("📦 Processing userId:", userId);
    await new Promise(resolve => {
      const query = 'SELECT email, name FROM students WHERE userId = ?';
      connection.query(query, [userId], (err, results) => {
        if (err || results.length === 0) {
          console.log("❌ Student not found or DB error for:", userId, err);
          failed++;
          return resolve();
        }

        const student = results[0];
        console.log("✅ Found student:", student.name, "📧", student.email);

        const mailOptions = {
          from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
          to: student.email,
          subject: "📢 Important Notification from CRR NOC Team",
          html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
              <h2 style="color: #003366;">Sir C R Reddy College of Engineering</h2>
              <p>Dear <strong>${student.name}</strong>,</p>
              <p>${message}</p>
              <br>
              <p style="color: #555;">Best regards,<br><strong>CRR NOC Team</strong></p>
            </div>
          `
        };

        transporter.sendMail(mailOptions, (err2) => {
          if (err2) {
            console.log("❌ Email sending failed to:", student.email, "Error:", err2.message);
          } else {
            console.log("📧 Email sent to:", student.email);
          }

          connection.query(
            'INSERT INTO notifications (userId, message) VALUES (?, ?)',
            [userId, message],
            (err3) => {
              if (err3) {
                console.log("❌ Notification insert failed for:", userId, err3.message);
                failed++;
              } else {
                console.log("✅ Notification saved for:", userId);
                sent++;
              }
              resolve();
            }
          );
        });
      });
    });
  }

  console.log("✅ Summary: Sent =", sent, "Failed =", failed);
  res.json({ success: true, sent, failed });
});

// Get notifications for a specific user
// GET: Notifications with staff name included
app.get('/notifications/:userId', (req, res) => {
  const { userId } = req.params;

  const query = `
    SELECT n.message, n.date_sent, s.staff_name
    FROM notifications n
    LEFT JOIN staff s ON n.staffId = s.staff_id
    WHERE n.userId = ?
    ORDER BY n.date_sent DESC
  `;

  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching notifications:", err);
      return res.status(500).json({ success: false, message: "Error retrieving notifications" });
    }

    res.json({ success: true, notifications: results });
  });
});

//fine impose
// POST: Impose Fine and send notification
app.post('/impose-fine', (req, res) => {
  const { userId, amount, reason, staffId, academic_year } = req.body;

  if (!userId || !reason || !amount || !staffId || !academic_year) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  const fineQuery = `
    INSERT INTO fines (userId, amount, reason, staffId, academic_year)
    VALUES (?, ?, ?, ?, ?)
  `;
  const fineValues = [userId, amount, reason, staffId, academic_year];

  connection.query(fineQuery, fineValues, (err, result) => {
    if (err) {
      console.error("❌ Error inserting fine:", err);
      return res.status(500).json({ success: false, message: "Failed to insert fine" });
    }

    const message = `💸 Fine of ₹${amount} for Year ${academic_year}. Reason: ${reason}`;
    const notifyQuery = `
      INSERT INTO notifications (userId, message, staffId)
      VALUES (?, ?, ?)
    `;
    connection.query(notifyQuery, [userId, message, staffId], (err2) => {
      if (err2) {
        console.error("❌ Notification insert error:", err2);
        return res.status(500).json({ success: false, message: "Fine added, but notification failed" });
      }

      res.json({ success: true, message: "Fine imposed and student notified!" });
    });
  });
});


//total fine there exist before
app.get('/total-fine/:userId', (req, res) => {
  const { userId } = req.params;
  connection.query('SELECT SUM(amount) AS totalFine FROM fines WHERE userId = ?', [userId], (err, results) => {
    if (err) {
      console.error("Error fetching fine:", err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, totalFine: results[0].totalFine || 0 });
  });
});

//fee detuction dynamically
// Get remaining fee for a student
app.get('/remaining-fee/:reg_no', async (req, res) => {
  const regNo = req.params.reg_no;

  try {
    // 1. Get original fee structure
    const [structureRows] = await connection.promise().query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ?',
      [regNo]
    );

    if (structureRows.length === 0) {
      return res.json({ success: false, message: "Fee structure not found." });
    }

    const structure = structureRows[0];

    // 2. Get total paid per category
    const [paidRows] = await connection.promise().query(
      'SELECT fee_type, SUM(amount) AS paid FROM student_fee_payment WHERE reg_no = ? GROUP BY fee_type',
      [regNo]
    );

    const paidMap = {};
    paidRows.forEach(row => {
      paidMap[row.fee_type] = parseFloat(row.paid);
    });

    // 3. Calculate remaining fee
    const remaining = {
      tuition: (structure.tuition || 0) - (paidMap.tuition || 0),
      hostel: (structure.hostel || 0) - (paidMap.hostel || 0),
      bus: (structure.bus || 0) - (paidMap.bus || 0),
      university: (structure.university || 0) - (paidMap.university || 0),
      semester: (structure.semester || 0) - (paidMap.semester || 0),
      library: (structure.library || 0) - (paidMap.library || 0),
      fines: (structure.fines || 0) - (paidMap.fines || 0),
    };

    res.json({ success: true, data: remaining });
  } catch (error) {
    console.error("🔥 Remaining fee error:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

//paid amounts
app.get('/paid-amounts/:userId', (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT fee_type, SUM(amount_paid) AS paid 
    FROM student_fee_payments 
    WHERE userId = ? AND matched = 1 
    GROUP BY fee_type
  `;

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Paid amounts fetch error:", err);
      return res.status(500).json([]);
    }

    res.json(results);
  });
});

//reference number submission
app.post("/submit-du", (req, res) => {
  const { userId, payments, academic_year } = req.body;

  if (!userId || !Array.isArray(payments) || !academic_year) {
    return res.status(400).json({ success: false, message: "Invalid data" });
  }

  // 🧠 Step 1: Get unique_id from students table
  connection.query(
    "SELECT uniqueId FROM students WHERE userId = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("❌ Error fetching unique_id:", err);
        return res.status(500).json({ success: false, message: "Server error" });
      }

      if (!results.length || !results[0].uniqueId) {
        return res.status(400).json({
          success: false,
          message: "❌ Unique ID missing. Please update your profile first."
        });
      }

      const unique_id = results[0].uniqueId;
      const values = [];
      const checkMatches = [];
      const duChecks = [];

      // 📦 Loop through payments
      for (const p of payments) {
        const du = p.du?.trim();
        const amt = parseFloat(p.amount);
        const feeType = p.type;

        if (!du || isNaN(amt) || !feeType) continue;

        // ✅ Prepare values for matching
        values.push([userId, unique_id, feeType, du, amt, academic_year, 0]);

        // 🧠 Check if DU + amount exists in SBI uploaded table
        checkMatches.push(
          new Promise(resolve => {
            connection.query(
              "SELECT * FROM sbi_uploaded_references WHERE sbi_ref_no = ? AND amount = ? AND unique_id = ?",
              [du, amt, unique_id],
              (err, results) => {
                if (err) return resolve([du, false]);
                resolve([du, results.length > 0]);
              }
            );
          })
        );

        // 🧠 Check if DU already exists anywhere in student_fee_payments
        duChecks.push(
          new Promise((resolve, reject) => {
            connection.query(
              `SELECT userId, unique_id, academic_year, fee_type 
               FROM student_fee_payments 
               WHERE sbi_ref_no = ?`,
              [du],
              (err, results) => {
                if (err) return reject(err);
                if (results.length > 0) {
                  return reject({
                    message: `❌ Reference Number ${du} already exists for User: ${results[0].userId}, UniqueId: ${results[0].unique_id}, Year: ${results[0].academic_year}, Fee: ${results[0].fee_type}`
                  });
                }
                resolve();
              }
            );
          })
        );
      }

      // 🔁 First check duplicates
      Promise.all(duChecks)
        .then(() => {
          // 🔁 After all matches
          Promise.all(checkMatches).then(matchResults => {
            const matchMap = Object.fromEntries(matchResults);

            // 🔄 Build final values with matched = 1 or 0
            const finalValues = values.map(([userId, unique_id, type, du, amt, year, matched]) => {
              const isMatched = matchMap[du] ? 1 : 0;
              return [userId, unique_id, type, du, amt, year, isMatched];
            });

            const sql = `
              INSERT INTO student_fee_payments (
                userId, unique_id, fee_type, sbi_ref_no, amount_paid, academic_year, matched
              )
              VALUES ?
              ON DUPLICATE KEY UPDATE
                sbi_ref_no = VALUES(sbi_ref_no),
                amount_paid = VALUES(amount_paid),
                matched = VALUES(matched),
                academic_year = VALUES(academic_year),
                unique_id = VALUES(unique_id),
                matched_on = IF(matched = 0 AND VALUES(matched) = 1, NOW(), matched_on)
            `;

            connection.query(sql, [finalValues], (err2) => {
              if (err2) {
                console.error("❌ Insert error:", err2);
                return res.status(500).json({ success: false, message: "DB error" });
              }

              res.json({
                success: true,
                message: "✅ DU entries submitted and matched successfully."
              });
            });
          });
        })
        .catch(err => {
          return res.status(400).json({
            success: false,
            message: err.message || "❌ Duplicate Reference Number found."
          });
        });
    }
  );
});

//fee structure
app.get("/fee-structure/:reg_no", (req, res) => {
  const reg_no = req.params.reg_no;

  const sql = `
    SELECT * FROM student_fee_structure 
    WHERE reg_no = ? 
    ORDER BY updated_at DESC 
    LIMIT 1
  `;

  connection.query(sql, [reg_no], (err, results) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "No fee structure found." });
    }
    res.json({ success: true, data: results[0] });
  });
});

app.get('/noc-eligibility/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(500).json({ success: false });
    }

    const reg_no = studentRows[0].reg_no;

    // 1. Get latest fee structure
    connection.query(`
      SELECT * FROM student_fee_structure 
      WHERE reg_no = ? 
      ORDER BY updated_at DESC 
      LIMIT 1
    `, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) {
        return res.status(400).json({ success: false, message: 'Fee structure not found' });
      }

      const feeStructure = feeRows[0];

      // 2. Get paid amounts from student_fee_payment
      connection.query(`
        SELECT fee_type, SUM(amount) AS paid 
        FROM student_fee_payment 
        WHERE reg_no = ? 
        GROUP BY fee_type
      `, [reg_no], (err3, paidRows) => {
        if (err3) return res.status(500).json({ success: false });

        const paidMap = {};
        paidRows.forEach(row => {
          paidMap[row.fee_type] = parseFloat(row.paid);
        });

        // 3. Final check: compare each component
        const expected = {
          tuition: parseFloat(feeStructure.tuition) || 0,
          hostel: parseFloat(feeStructure.hostel) || 0,
          bus: parseFloat(feeStructure.bus) || 0,
          university: parseFloat(feeStructure.university) || 0,
          semester: parseFloat(feeStructure.semester) || 0,
          library: parseFloat(feeStructure.library) || 0,
          fines: parseFloat(feeStructure.fines) || 0
        };

        for (const key in expected) {
          const paid = paidMap[key] || 0;
          const remaining = expected[key] - paid;
          if (remaining > 0) {
            return res.json({ success: true, eligible: false });
          }
        }

        // ✅ All paid
        res.json({ success: true, eligible: true });
      });
    });
  });
});


app.post('/admin/upload-sbi', upload.single('sbiFile'), (req, res) => {
  const filePath = path.join(__dirname, req.file.path);
  const csv = require('csv-parser');
  const results = [];

  fs.createReadStream(filePath)
    .pipe(csv())
    .on('data', (row) => {
      const du = row["Bank Reference No"]?.trim();
      const amt = parseFloat(row["Amount"]);
      const status = row["Status"]?.toLowerCase();
      const uniqueId = row["UNIQUE NO"]?.trim();

      if (
        du && amt && uniqueId &&
        status && status.includes("completed successfully")
      ) {
        results.push([du, amt, uniqueId]);
      }
    })
    .on('end', () => {
      if (results.length === 0) {
        return res.status(400).json({ success: false, message: '❌ No valid COMPLETED entries found.' });
      }

      // STEP 1: Insert or update (if already exists) — prevents duplicate insert crash
      const insertQuery = `
        INSERT INTO sbi_uploaded_references (sbi_ref_no, amount, unique_id)
        VALUES ?
        ON DUPLICATE KEY UPDATE amount = VALUES(amount), unique_id = VALUES(unique_id)
      `;

      connection.query(insertQuery, [results], (err) => {
        if (err) {
          console.error('❌ Upload error:', err);
          return res.status(500).json({ success: false, message: 'Upload failed.' });
        }

        // STEP 2: Match both new & existing SBI entries with student_fee_payments
        const matchQuery = `
          UPDATE student_fee_payments p
          JOIN students s ON p.userId = s.userId
          JOIN sbi_uploaded_references r 
            ON p.sbi_ref_no = r.sbi_ref_no 
            AND p.amount_paid = r.amount 
            AND s.uniqueId = r.unique_id
          SET p.matched = 1, p.matched_on = NOW()
          WHERE p.matched = 0
        `;

        connection.query(matchQuery, (err2, result) => {
          if (err2) {
            console.error('❌ Match error:', err2);
            return res.status(500).json({ success: false, message: 'Matching failed.' });
          }

          res.json({ success: true, message: `✅ SBI file uploaded. ${result.affectedRows} entries matched.` });
        });
      });
    });
});



app.get('/admin/matches', (req, res) => {
  const sql = `
    SELECT 
      s.name,
      s.reg_no AS userId,
      f.academic_year,
      f.fee_type,
      f.amount_paid,
      f.sbi_ref_no,
      f.matched,
      DATE_FORMAT(f.matched_on, '%d-%m-%Y') AS matched_on
    FROM student_fee_payments f
    JOIN students s ON f.userId = s.reg_no
    ORDER BY f.matched_on DESC
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching matches:', err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});



app.post('/admin/search-noc-status', (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ success: false, message: "No query provided" });

  const searchTerm = `%${query}%`;
  const sql = `SELECT userId, reg_no, name FROM students WHERE userId LIKE ? OR name LIKE ?`;

  connection.query(sql, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error("❌ Search error:", err);
      return res.status(500).json({ success: false });
    }

    const checks = results.map(student => {
      const { userId, reg_no, name } = student;

      return new Promise(resolve => {
        connection.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, name, eligible: false });

            const fees = feeRows[0];

            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 
               GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, name, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));

                connection.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };

                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, name, eligible: false });
                    }

                    resolve({ userId, name, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });

    Promise.all(checks).then(data => {
      res.json({ success: true, data });
    });
  });
});

app.get('/admin/noc-status', (req, res) => {
  connection.query('SELECT userId, reg_no FROM students', (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no } = student;

      return new Promise(resolve => {
        // 1️⃣ Get latest fee structure
        connection.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, eligible: false });

            const fees = feeRows[0];
            // 2️⃣ Get verified paid fees
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 
               GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));
                // 3️⃣ Get fines
                connection.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };
                    // Check remaining
                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, eligible: false });
                    }
                    resolve({ userId, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });
    Promise.all(checks).then(data => res.json(data));
  });
});

//logic for the fee status for qr code

app.get("/fee-status/:userId", (req, res) => {
  const { userId } = req.params;

  // Map DB fee_type → frontend keys
  const typeMap = {
    "tuition fee": "tuition",
    "hostel fee": "hostel",
    "bus fee": "bus",
    "university fee": "university",
    "semester fee": "semester",
    "library dues": "library"
  };

  // Step 1: Get reg_no from students table
  const getRegNoQuery = `SELECT reg_no FROM students WHERE userId = ?`;

  connection.query(getRegNoQuery, [userId], (err, studentRows) => {
    if (err) return res.status(500).json({ success: false, message: "DB error (reg_no)" });
    if (studentRows.length === 0) return res.status(404).json({ success: false, message: "Student not found" });

    const reg_no = studentRows[0].reg_no;

    // Step 2: Get fee structure
    const feeStructureQuery = `SELECT * FROM student_fee_structure WHERE reg_no = ?`;

    connection.query(feeStructureQuery, [reg_no], (err2, feeRows) => {
      if (err2) return res.status(500).json({ success: false, message: "DB error (structure)" });
      if (feeRows.length === 0) return res.status(404).json({ success: false, message: "No fee structure found" });

      // Step 3: Get payments
      const paymentsQuery = `
        SELECT academic_year, fee_type, SUM(amount_paid) AS paid
        FROM student_fee_payments
        WHERE userId = ? AND matched = 1
        GROUP BY academic_year, fee_type
      `;

      connection.query(paymentsQuery, [userId], (err3, paidRows) => {
        if (err3) return res.status(500).json({ success: false, message: "DB error (payments)" });

        const paidMap = {};
        paidRows.forEach(row => {
          const year = row.academic_year;
          const normalized = typeMap[row.fee_type.toLowerCase()];
          if (!paidMap[year]) paidMap[year] = {};
          if (normalized) paidMap[year][normalized] = parseFloat(row.paid);
        });

        // Step 4: Build yearly summary
        const years = {};
        feeRows.forEach(row => {
          const year = row.academic_year;
          const expected = {
            tuition: parseFloat(row.tuition) || 0,
            hostel: parseFloat(row.hostel) || 0,
            bus: parseFloat(row.bus) || 0,
            university: parseFloat(row.university) || 0,
            semester: parseFloat(row.semester) || 0,
            library: parseFloat(row.library) || 0,
            fines: parseFloat(row.fines) || 0
          };

          const paid = paidMap[year] || {};

          years[year] = { expected, paid };
        });

        return res.json({ success: true, reg_no, years });
      });
    });
  });
});


app.post("/add-student", async (req, res) => {
  const {
    userId, name, dob, reg_no, unique_id,
    year, course, semester, aadhar_no, mobile_no,
    email = "", password, section,
    father_name, father_mobile_no,
    counsellor_name, counsellor_mobile,
    admission_type 
  } = req.body;

  // Required fields for validation
  const must = {
    userId, reg_no, unique_id, year, course,
    semester, section, password,
    counsellor_name, counsellor_mobile
  };

  for (const k in must) {
    if (!must[k] && must[k] !== "") {
      return res.status(400).json({ success: false, message: `Missing: ${k}` });
    }
  }

  try {
    //  Capitalize helper
    const capitalize = (s) =>
      (s || "").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());

    const studentName = capitalize(name);
    const fatherName = capitalize(father_name);
    const counsellorName = capitalize(counsellor_name);
    const sectionUpper = (section || "").toUpperCase();

    // Check if user already exists
    connection.query("SELECT 1 FROM users WHERE userid = ?", [userId], async (e, r) => {
      if (e) return res.status(500).json({ success: false });
      if (r.length) return res.status(400).json({ success: false, message: "User exists" });

      const hashed = await bcrypt.hash(password, 10);

      //  Insert into users table
      connection.query(
        "INSERT INTO users (userid, password, role) VALUES (?, ?, 'student')",
        [userId, hashed],
        (e1) => {
          if (e1) return res.status(500).json({ success: false, message: "User insert failed" });

          //  Insert into students table with admission_type
          const studentSql = `
            INSERT INTO students
              (userId, reg_no, uniqueId, year, course, semester, section,
               counsellor_name, counsellor_mobile,
               name, dob, aadhar_no, mobile_no, email,
               father_name, father_mobile, admission_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          `;

          const vals = [
            userId, reg_no, unique_id, year, course, semester, sectionUpper,
            counsellorName, counsellor_mobile,
            studentName || null, dob || null, aadhar_no || null, mobile_no || null, email,
            fatherName || null, father_mobile_no || null,
            admission_type || null
          ];

          connection.query(studentSql, vals, (e2) => {
            if (e2) {
              console.error("Student insert error:", e2);
              return res.status(500).json({ success: false });
            }
            res.json({ success: true });
          });
        }
      );
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

//logic for the fee upadate by staff
//Staff updates fee structure for a student by reg_no
app.post('/update-fee-structure', (req, res) => {
  const {
    reg_no, academic_year, tuition, hostel, bus,
    university, semester, library, fines
  } = req.body;

  if (!reg_no || !academic_year) {
    return res.status(400).json({ success: false, message: "Reg No and Year required" });
  }

  const queryCheck = `
    SELECT * FROM student_fee_structure 
    WHERE reg_no = ? AND academic_year = ?
  `;

  connection.query(queryCheck, [reg_no, academic_year], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "DB error" });

  const sql = result.length > 0
  ? `UPDATE student_fee_structure SET
      tuition=?, hostel=?, bus=?, university=?, semester=?, \`library\`=?, fines=?, updated_at=NOW()
     WHERE reg_no=? AND academic_year=?`
  : `INSERT INTO student_fee_structure 
     (reg_no, academic_year, tuition, hostel, bus, university, semester, \`library\`, fines, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`;


    const values = result.length > 0
      ? [tuition, hostel, bus, university, semester, library, fines, reg_no, academic_year]
      : [reg_no, academic_year, tuition, hostel, bus, university, semester, library, fines];

   connection.query(sql, values, (err2) => {
  if (err2) {
    console.error("❌ Fee update query failed:", err2.message); // this logs the actual MySQL error
    return res.status(500).json({ success: false, message: "Query failed", error: err2.message });
  }

  res.json({ success: true, message: "✅ Year-wise fee updated successfully!" });
});

  });
});
//noc code
// ... all previous code remains unchanged

//Updated Generate NOC PDF logic (fixed hanging issue)
app.get('/generate-noc/:userId', (req, res) => {
  const { userId } = req.params;
  const academicYear = parseInt(req.query.year); // 👈 Get year from query param

  if (!academicYear || academicYear < 1 || academicYear > 4) {
    return res.status(400).json({ success: false, message: 'Invalid or missing year' });
  }

  connection.query('SELECT name, course, reg_no FROM students WHERE userId = ?', [userId], (err, studentResults) => {
    if (err || studentResults.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const student = studentResults[0];
    const reg_no = student.reg_no;

    connection.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? AND academic_year = ?',
      [reg_no, academicYear],
      (err2, feeRows) => {
        if (err2 || feeRows.length === 0) {
          return res.status(400).json({ success: false, message: 'Fee structure not found for that year' });
        }

        const feeStructure = feeRows[0];

        connection.query(
          `SELECT fee_type, SUM(amount_paid) AS paid 
           FROM student_fee_payments 
           WHERE userId = ? AND matched = 1 AND academic_year = ?
           GROUP BY fee_type`,
          [userId, academicYear],
          (err3, paidRows) => {
            if (err3) return res.status(500).json({ success: false });

            const paidMap = {};
            paidRows.forEach(row => {
              paidMap[row.fee_type] = parseFloat(row.paid);
            });

            connection.query(
              'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
              [userId, academicYear],
              (err4, fineRes) => {
                if (err4) return res.status(500).json({ success: false });

                const fineAmount = parseFloat(fineRes[0].fine) || 0;

                const expected = {
                  tuition: parseFloat(feeStructure.tuition || 0),
                  hostel: parseFloat(feeStructure.hostel || 0),
                  bus: parseFloat(feeStructure.bus || 0),
                  university: parseFloat(feeStructure.university || 0),
                  semester: parseFloat(feeStructure.semester || 0),
                  library: parseFloat(feeStructure.library || 0),
                  fines: fineAmount
                };

                const readableMap = {
                  tuition: "TUTION FEE",
                  hostel: "HOSTEL FEE",
                  bus: "BUS FEE",
                  university: "UNIVERSITY FEE",
                  semester: "EXAMINATION CELL",
                  library: "LIBRARY DUE",
                  fines: "FINE"
                };

                const status = {};
                for (const key in expected) {
                  const paid = paidMap[key] || 0;
                  const remaining = expected[key] - paid;
                  status[readableMap[key]] = remaining <= 0 ? "PAID ✅" : "NOT PAID ❌";
                }

                const fileName = `noc_${userId}_year${academicYear}.pdf`;
                const filePath = path.join(__dirname, 'uploads', fileName);
                const doc = new PDFDocument({ margin: 50 });
                const stream = fs.createWriteStream(filePath);
                doc.pipe(stream);

                // Header
                const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
                if (fs.existsSync(headerPath)) {
                  doc.image(headerPath, { fit: [500, 150], align: 'center' });
                  doc.moveDown(3);
                }

                // Title
                doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE', {
                  align: 'center',
                  underline: true,
                });
                doc.moveDown(1.5);

                // Certificate body
                doc.font('Times-Bold').fontSize(12).text(
                  `This is to certify that Mr./Ms. ${student.name} (Roll No: ${student.reg_no}),`,
                  { align: 'justify' }
                );
                doc.moveDown(0.5);
                doc.font('Times-Roman').text(
                  `A bonafide student of ${student.course}, has the following fee details (paid/unpaid) towards the institution for   **Year ${academicYear}**.`,
                  { align: 'justify' }
                );
                doc.moveDown(1);
                doc.text(
                  `He/She has no objection from the college to appear for <exam purpose / leave purpose / higher studies / internships>`,
                  { align: 'justify' }
                );
                doc.moveDown();

                // Fee Details
                doc.font('Times-Bold').fontSize(13).text("FEE DETAILS", { align: 'center', underline: true });
                doc.moveDown();
                doc.font('Times-Roman').fontSize(12);

                const tableLeftX = 70;
                const tableRightX = 380;
                const rowHeight = 20;
                let y = doc.y;

                Object.keys(status).forEach(feeType => {
                  doc.text(feeType, tableLeftX, y);
                  doc.text(status[feeType], tableRightX, y);
                  y += rowHeight;
                });

                doc.moveDown();
                doc.text(
                  `This is a system-generated certificate and does not require a manual signature.`,
                  { align: 'center' }
                );
                doc.moveDown(1);
                doc.font('Times-Bold').text("COLLEGE STAMP", { align: 'center' });

 // QR code
const qrLink = `https://crr-noc.onrender.com/verifybyqr.html?userId=${userId}&year=${academicYear}`;

QRCode.toDataURL(qrLink, (err, qrUrl) => {
  if (err) {
    console.error("QR code generation failed", err);
    doc.end();
    return;
  }

  const qrSize = 50;
  const qrX = 150;
  const qrY = doc.page.height - qrSize - 150;

  doc.image(qrUrl, qrX, qrY, { width: qrSize });
  doc.font('Times-Roman')
    .fontSize(10)
    .text('Scan to verify the NOC', qrX - 10, qrY + qrSize + 5, {
      width: qrSize + 30,
      align: 'center'
    });

  // Add footer image if exists
  const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
  if (fs.existsSync(footerPath)) {
    const footerWidth = 500;
    const footerX = (doc.page.width - footerWidth) / 2;
    const footerY = doc.page.height - 100;

    doc.image(footerPath, footerX, footerY, {
      width: footerWidth,
      align: 'center'
    });
  }

  doc.end();

  stream.on("finish", () => {
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Content-Type", "application/pdf");

    const readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
  });
});
});
});
});
});
});

//logic for combined-noc
app.get('/generate-combined-noc/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT name, course, reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    const student = studentRows[0];
    const reg_no = student.reg_no;

    connection.query(`SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC`, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) {
        return res.status(400).json({ success: false, message: 'No fee structure found' });
      }

      const promises = feeRows.map(fee => {
        const year = fee.academic_year;

        return new Promise(resolve => {
          connection.query(
            `SELECT fee_type, SUM(amount_paid) AS paid 
             FROM student_fee_payments 
             WHERE userId = ? AND matched = 1 AND academic_year = ?
             GROUP BY fee_type`,
            [userId, year],
            (err3, paidRows) => {
              const paidMap = {};
              paidRows?.forEach(row => paidMap[row.fee_type] = parseFloat(row.paid));

              connection.query(
                'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
                [userId, year],
                (err4, fineRes) => {
                  const fineAmount = parseFloat(fineRes[0]?.fine || 0);

                  const expected = {
                    tuition: parseFloat(fee.tuition || 0),
                    hostel: parseFloat(fee.hostel || 0),
                    bus: parseFloat(fee.bus || 0),
                    university: parseFloat(fee.university || 0),
                    semester: parseFloat(fee.semester || 0),
                    library: parseFloat(fee.library || 0),
                    fines: fineAmount
                  };

                  let allPaid = true;
                  for (const key in expected) {
                    const paid = paidMap[key] || 0;
                    const remaining = expected[key] - paid;
                    if (remaining > 0) {
                      allPaid = false;
                      break;
                    }
                  }

                  resolve({ year, status: allPaid ? "✅ Paid" : "❌ Not Paid" });
                }
              );
            }
          );
        });
      });

      Promise.all(promises).then(yearStatuses => {
        const fileName = `combined_noc_${userId}.pdf`;
        const filePath = path.join(__dirname, 'uploads', fileName);
        const doc = new PDFDocument({ margin: 50 });
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        // Header
        const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
        if (fs.existsSync(headerPath)) {
          doc.image(headerPath, { fit: [500, 150], align: 'center' });
          doc.moveDown(2);
        }

        // Title
        doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE – FEE STATUS (ALL YEARS)', {
          align: 'center',
          underline: true
        });
        doc.moveDown();

        // Professional body
        doc.font('Times-Roman').fontSize(12).text(
          `This is to formally certify that Mr./Ms. ${student.name} (Reg. No: ${reg_no}), currently enrolled in the ${student.course} program at our institution, has completed the prescribed fee payments as per the academic requirements. The year-wise fee payment status is verified from official records and is provided below:`,
          { align: 'justify' }
        );
        doc.moveDown();

        doc.font('Times-Roman').fontSize(12).text(
          `This certificate is being issued upon the request of the student for the purpose of submission to external academic institutions, internship providers, employers, or any other authorities where official confirmation of fee clearance is required.`,
          { align: 'justify' }
        );
        doc.moveDown();

        // Year-wise status list
        yearStatuses.forEach(({ year, status }) => {
          doc.font('Times-Bold').fontSize(13).text(`${year} Year: ${status}`);
        });

        doc.moveDown(2);
        doc.font('Times-Italic').fontSize(11).text(
          "This certificate has been digitally generated and does not require a physical signature. It is valid for all official and academic purposes.",
          { align: 'center' }
        );

        doc.moveDown();
        doc.font('Times-Roman').fontSize(11).text(
          `This certificate remains valid unless found altered or tampered with. Verification can be performed using the QR code provided below.`,
          { align: 'center' }
        );

        doc.moveDown(2);
        doc.font('Times-Roman').text("Authorized By", { align: 'right' });
        doc.font('Times-Italic').text("Head of Accounts Department", { align: 'right' });

        // QR Code
        const qrLink = `https://crr-noc.onrender.com/verifybyqr.html?userId=${userId}&combined=true`;

        QRCode.toDataURL(qrLink, (err, qrUrl) => {
          if (!err && qrUrl) {
            doc.image(qrUrl, 250, doc.y + 10, { width: 60 });
          }

          // Footer
          const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
          if (fs.existsSync(footerPath)) {
            doc.image(footerPath, (doc.page.width - 500) / 2, doc.page.height - 100, { width: 500 });
          }

          doc.end();
          stream.on("finish", () => {
            res.download(filePath, fileName);
          });
        });
      });
    });
  });
});

// logic for the combined noc verification by qr

app.get('/verify-combined-noc/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, result) => {
    if (err || result.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const reg_no = result[0].reg_no;

    connection.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no],
      async (err2, feeRows) => {
        if (err2 || feeRows.length === 0) {
          return res.json({ success: false, message: "No fee structure found" });
        }

        const yearStatuses = await Promise.all(feeRows.map(fee => {
          const year = fee.academic_year;
          return new Promise(resolve => {
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS paid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 AND academic_year = ?
               GROUP BY fee_type`,
              [userId, year],
              (err3, paidRows) => {
                const paidMap = {};
                paidRows?.forEach(row => {
                  paidMap[row.fee_type.toLowerCase()] = parseFloat(row.paid);
                });

                connection.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
                  [userId, year],
                  (err4, fineRes) => {
                    const fineAmount = parseFloat(fineRes?.[0]?.fine || 0);

                    const expected = {
                      tuition: fee.tuition || 0,
                      hostel: fee.hostel || 0,
                      bus: fee.bus || 0,
                      university: fee.university || 0,
                      semester: fee.semester || 0,
                      library: fee.library || 0,
                      fines: fineAmount
                    };

                    let allPaid = true;
                    for (const key in expected) {
                      const paid = paidMap[key] || 0;
                      if ((expected[key] - paid) > 0) {
                        allPaid = false;
                        break;
                      }
                    }

                    resolve({ year, status: allPaid ? "✅ Paid" : "❌ Not Paid" });
                  }
                );
              }
            );
          });
        }));

        return res.json({ success: true, reg_no, yearStatuses });
      }
    );
  });
});


app.post('/api/submit-feedback', (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  // HTML Email for User
  const userMailOptions = {
  from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
  to: email,
  subject: "🎓 Thank You for Your Feedback",
  html: `
    <div style="font-family: Arial; padding: 20px;">
      <h2 style="color:#003366; margin-top: 0;">Sir C R Reddy College of Engineering</h2>
      <p>Hi <strong>${name}</strong>,</p>
      <p>Thank you for reaching out. We have received your feedback and will review it shortly.</p>
      <p><strong>Your message:</strong></p>
      <blockquote style="color: #444; font-style: italic;">${message}</blockquote>
      <p>Best regards,<br><strong>CRR NOC Support Team</strong></p>
    </div>
  `
};
  // Email to Admin
  const adminMailOptions = {
  from: '"CRR NOC Bot" <crrenoccertificate@gmail.com>',
  to: 'crrenoccertificate@gmail.com',
  subject: `📬 Feedback Received from ${name}`,
  html: `
    <div style="font-family: Arial; padding: 20px;">
      <h2 style="color:#003366;">Sir C R Reddy College of Engineering</h2>
      <h3 style="color: #222;">New Feedback Received</h3>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Message:</strong><br>${message}</p>
      <p style="color: #888; font-size: 13px;">Timestamp: ${new Date().toLocaleString()}</p>
    </div>
  `
};
  // Send both emails
  transporter.sendMail(userMailOptions, (err1) => {
    if (err1) {
      console.error("User email error:", err1);
      return res.status(500).json({ success: false, message: "Failed to notify user." });
    }
    transporter.sendMail(adminMailOptions, (err2) => {
      if (err2) {
        console.error("Admin email error:", err2);
        return res.status(500).json({ success: false, message: "Failed to notify admin." });
      }
      res.status(200).json({ success: true, message: "Feedback submitted successfully!" });
    });
  });
});

app.get('/student-du-entries/:userId', (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT id, fee_type, sbi_ref_no, amount_paid, matched, created_at 
    FROM student_fee_payments 
    WHERE userId = ? 
    ORDER BY created_at DESC
  `;

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching DU entries:", err);
      return res.status(500).json([]);
    }

    res.json(results);
  });
});
// 🧾 Get all fee entries for a user
app.get("/my-fee-entries/:userId", (req, res) => {
  const { userId } = req.params;
const sql = `SELECT id, fee_type, amount_paid, sbi_ref_no, created_at, matched 
             FROM student_fee_payments 
             WHERE userId = ? 
             ORDER BY created_at DESC`;

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Fetch error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

//  Delete a specific fee entry
app.delete("/delete-fee-entry/:id", (req, res) => {
  const { id } = req.params;
  connection.query("DELETE FROM student_fee_payments WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ success: false, message: "Delete failed." });
    }
    res.json({ success: true, message: "Fee entry deleted successfully." });
  });
});

app.post('/admin/search-student-sbi', (req, res) => {
  const { query } = req.body;

  if (!query || query.trim() === "") {
    return res.status(400).json({ success: false, message: "Query is required" });
  }

  const likeQuery = `%${query.toLowerCase()}%`;
  
  const sql = `
    SELECT 
      s.reg_no AS userId,
      s.name AS studentName,
      f.fee_type,
      f.sbi_ref_no,
      f.amount_paid,
      f.matched AS fee_matched,
      f.matched_on AS fee_matched_on,
      f.academic_year
    FROM students s
    LEFT JOIN student_fee_payments f ON s.reg_no = f.userId
    WHERE LOWER(s.reg_no) LIKE ? OR LOWER(s.name) LIKE ?
    ORDER BY f.matched_on DESC
  `;

  connection.query(sql, [likeQuery, likeQuery], (err, results) => {
    if (err) {
      console.error("🔥 SQL Execution Error:", err.sqlMessage);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }

    res.json({ success: true, data: results });
  });
});


app.get('/admin/noc-status', (req, res) => {
  connection.query('SELECT userId, reg_no, name FROM students', (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no, name } = student;

      return new Promise(resolve => {
        // 1️ Get latest fee structure
        connection.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, name, eligible: false });

            const fees = feeRows[0];

            // 2️Get verified paid fees
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 
               GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, name, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));

                // Get fines
                connection.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };

                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, name, eligible: false });
                    }

                    resolve({ userId, name, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });

    Promise.all(checks).then(data => res.json(data));
  });
});
//year wise fee details
app.get('/yearwise-fee/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err1, regRes) => {
    if (err1 || regRes.length === 0) return res.status(500).json({ success: false });

    const reg_no = regRes[0].reg_no;

    connection.query(
      `SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC`,
      [reg_no],
      (err2, feeRows) => {
        if (err2) return res.status(500).json({ success: false });
        if (feeRows.length === 0) return res.status(404).json({ success: false, message: "No fee data" });

        const promises = feeRows.map(fee => new Promise(resolve => {
          const year = fee.academic_year;

          connection.query(
            `SELECT fee_type, SUM(amount_paid) AS paid 
             FROM student_fee_payments 
             WHERE userId = ? AND matched = 1 AND academic_year = ?
             GROUP BY fee_type`,
            [userId, year],
            (err3, paidRows) => {
              const paidMap = {};

              // Map DB fee_type to backend keys
              const typeMap = {
                "Tuition Fee": "tuition",
                "Hostel Fee": "hostel",
                "Bus Fee": "bus",
                "University Fee": "university",
                "Semester Fee": "semester",
                "Library Dues": "library"
              };

              paidRows?.forEach(row => {
                const key = typeMap[row.fee_type];
                if (key) paidMap[key] = parseFloat(row.paid);
              });

              connection.query(
                `SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?`,
                [userId, year],
                (err4, fineRes) => {
                  const fineAmount = parseFloat(fineRes[0]?.fine || 0);
                  resolve({
                    year,
                    structure: fee,
                    paid: paidMap,
                    fines: fineAmount
                  });
                }
              );
            }
          );
        }));

        Promise.all(promises).then(data => res.json({ success: true, data }));
      }
    );
  });
});

// view backlogs 
app.get("/total-backlogs", (req, res) => {
  const { regno } = req.query;
  if (!regno) return res.status(400).json({ message: "Regno is required" });

  const useRegularTable = ["20B8", "21B8", "22B8", "23B8"].some(prefix => regno.toUpperCase().startsWith(prefix));
  const tableName = useRegularTable ? "results" : "autonomous_results";

  const query = `SELECT semester, subcode, grade, subname FROM ${tableName} WHERE regno = ?`;
  connection.query(query, [regno], (err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching data", error: err });

    const isBacklog = g => ["F","ab", "AB", "ABSENT", "MP", "NOT CO", "NOTCOMPLETED"].includes((g || "").toUpperCase());
    const backlogData = results.filter(r => isBacklog(r.grade));

    res.json({ backlogData, count: backlogData.length });
  });
});
// get Student Details for Removal
app.post("/get-student-details", async (req, res) => {
  const { reg_no } = req.body;
  try {
    const [rows] = await connection.promise().query("SELECT * FROM students WHERE reg_no = ?", [reg_no]);
    if (rows.length === 0) {
      return res.json({ success: false, message: "Student not found" });
    }
    res.json({ success: true, student: rows[0] });
  } catch (err) {
    console.error("Fetch error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Delete Student with Photo Removal
// Delete a single student and all their data
app.post('/delete-student', (req, res) => {
  const { reg_no } = req.body;

  if (!reg_no) return res.status(400).json({ success: false, message: "Registration number required." });

  // Step 1: get the matching userId from students
  connection.query('SELECT userId FROM students WHERE reg_no = ?', [reg_no], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found." });
    }

    const userId = results[0].userId;

    // Step 2: delete from all relevant tables using correct keys
    const queries = [
      ['DELETE FROM students WHERE reg_no = ?', [reg_no]],
      ['DELETE FROM users WHERE userid = ?', [userId]], // ✅ fixed
      ['DELETE FROM student_fee_structure WHERE reg_no = ?', [reg_no]],
      ['DELETE FROM student_fee_payments WHERE userId = ?', [userId]],
      ['DELETE FROM notifications WHERE userId = ?', [userId]],
      ['DELETE FROM fines WHERE userId = ?', [userId]],
    ];

    let completed = 0;
    queries.forEach(([query, params]) => {
      connection.query(query, params, (err2) => {
        if (err2) console.error(`Error deleting from table: ${query}`, err2);
        completed++;
        if (completed === queries.length) {
          return res.json({ success: true, message: `Student ${reg_no} and all related data deleted.` });
        }
      });
    });
  });
});


// Filter Batch
app.post("/filter-batch", async (req, res) => {
  const { batchPrefix, branch } = req.body;
  try {
    const [students] = await connection.promise().query(
      "SELECT reg_no, name FROM students WHERE reg_no LIKE ? AND course = ?",
      [`${batchPrefix}%`, branch]
    );
    res.json({ success: true, students });
  } catch (err) {
    console.error("Batch filter error:", err);
    res.status(500).json({ success: false, students: [] });
  }
});

// Delete Batch
app.post('/delete-batch', (req, res) => {
  const { batchPrefix, branch } = req.body;

  if (!batchPrefix || !branch) {
    return res.status(400).json({ success: false, message: "Batch prefix and branch are required." });
  }

  const sql = `SELECT reg_no, userId FROM students WHERE reg_no LIKE ? AND branch = ?`;
  const likePrefix = `${batchPrefix}%`;

  connection.query(sql, [likePrefix, branch], (err, students) => {
    if (err || students.length === 0) {
      return res.status(404).json({ success: false, message: "No matching students found." });
    }

    let completed = 0;
    const total = students.length;

    students.forEach(({ reg_no, userId }) => {
      const queries = [
        ['DELETE FROM students WHERE reg_no = ?', [reg_no]],
        ['DELETE FROM users WHERE userid = ?', [userId]],
        ['DELETE FROM student_fee_structure WHERE reg_no = ?', [reg_no]],
        ['DELETE FROM student_fee_payments WHERE userId = ?', [userId]],
        ['DELETE FROM notifications WHERE userId = ?', [userId]],
        ['DELETE FROM fines WHERE userId = ?', [userId]],
      ];

      let subCompleted = 0;
      queries.forEach(([q, p]) => {
        connection.query(q, p, (err2) => {
          if (err2) console.error(`Error deleting: ${q}`, err2);
          subCompleted++;
          if (subCompleted === queries.length) {
            completed++;
            if (completed === total) {
              return res.json({ success: true, message: `Batch ${batchPrefix} - ${branch} students deleted.` });
            }
          }
        });
      });
    });
  });
});

// result pdf upload
// Admin uploads result PDF
app.post('/upload', upload.single('pdf'), (req, res) => {
  const semester = req.body.semester;
  const filePath = req.file?.path;

  console.log("📥 Semester:", semester);
  if (!semester || !filePath) {
    return res.status(400).json({ message: '❌ Semester or PDF missing.' });
  }

  console.log("📄 PDF File Path:", filePath);
  console.log("🐍 Running Python script...");

  const python = spawn('python3', ['extract_pdf.py', filePath, semester]);

  let output = '';
  let errorOutput = '';

  python.stdout.on('data', (data) => {
    output += data.toString();
  });

  python.stderr.on('data', (data) => {
    errorOutput += data.toString();
  });

  python.on('close', (code) => {
    console.log("🐍 Python exited with code:", code);
    if (errorOutput) console.error("🐍 stderr:\n", errorOutput);

    if (code !== 0) {
      return res.status(500).json({
        message: '❌ Upload failed: Python script error',
        error: errorOutput || 'Unknown error'
      });
    }

    let results;
    try {
      results = JSON.parse(output);
    } catch (jsonErr) {
      console.error("❌ JSON Parse Error:", jsonErr.message);
      console.error("📦 Raw output:\n", output);
      return res.status(500).json({
        message: '❌ Invalid JSON from Python',
        error: jsonErr.message
      });
    }

    if (!results.length) {
      return res.status(200).json({
        message: '✅ PDF processed but no records found.',
        total: 0
      });
    }

    // Insert all entries with UPSERT (ON DUPLICATE KEY UPDATE)
    let completed = 0;
    const total = results.length;

    results.forEach(({ regno, subcode, subname, grade, credits }) => {
      connection.query(
        `INSERT INTO results (regno, subcode, subname, grade, credits, semester)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           grade = VALUES(grade),
           credits = VALUES(credits),
           semester = VALUES(semester)`,
        [regno, subcode, subname, grade, credits, semester],
        (err) => {
          if (err) {
            console.error(`❌ Insert failed: ${regno} - ${subcode} ➜`, err.message);
          } else {
            console.log(`✅ Inserted/Updated: ${regno} - ${subcode}`);
          }

          completed++;
          if (completed === total) {
            res.status(200).json({
              message: '✅ PDF processed and records inserted/updated.',
              total,
              semester
            });
          }
        }
      );
    });
  });
});


//AUTONOMOUS results upload
// Route: Upload Autonomous Student Result PDF
// Autonomous PDF Upload Route
// Route: Upload Autonomous Student Result PDF
app.post("/admin/upload-autonomous-result-pdf", upload.single("pdf"), async (req, res) => {
  try {
    const { semester } = req.body;
    if (!req.file || !semester) {
      return res.status(400).json({ success: false, message: "❌ PDF and semester required." });
    }

    const buffer = fs.readFileSync(req.file.path);
    const data = await pdfParse(buffer);
    const lines = data.text.split("\n").map(line => line.trim()).filter(Boolean);

    //Save raw text to .txt file
    const baseName = path.basename(req.file.originalname, path.extname(req.file.originalname)).replace(/\s+/g, "_");
    const txtPath = path.join(__dirname, "uploads", `${baseName}.txt`);
    fs.writeFileSync(txtPath, data.text, "utf-8");

    const results = [];
    let currentSubjectCodes = [];
    const subjectMap = {}; // subcode → subname
    let inserted = 0;

    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i];

      // Update subject codes from SGPA line
      if (line.includes("SGPA")) {
        const subPart = line.split("SGPA")[0];
        const subcodes = subPart.match(/[A-Z0-9]{8}/g);
        if (subcodes && subcodes.length === 10) {
          currentSubjectCodes = subcodes;
        }
        continue;
      }

      // Update subject map when subnames appear again
      const match = line.match(/^\d+\)\s*([A-Z0-9]{8})-(.+)$/);
      if (match) {
        const subcode = match[1].trim();
        const subname = match[2].trim();
        subjectMap[subcode] = subname;
        continue;
      }

      // Process student result blocks
      const regno = lines[i];
      const resultLine = lines[i + 1];

      if (/^\d{2}B8[0-9A-Z]{6}$/.test(regno) && /^[A-FS]{10}[0-9.]+$/.test(resultLine)) {
        const grades = resultLine.slice(0, 10).split("");
        const sgpa = parseFloat(resultLine.slice(10)) || 0;

        for (let j = 0; j < 10; j++) {
          const subcode = currentSubjectCodes[j];
          const subname = subjectMap[subcode] || null;
          const grade = grades[j];

          results.push([regno, semester, subcode, subname, grade, sgpa]);

          const query = `
            INSERT INTO autonomous_results (regno, semester, subcode, subname, grade, sgpa)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE grade = VALUES(grade), subname = VALUES(subname), sgpa = VALUES(sgpa)
          `;
          connection.query(query, [regno, semester, subcode, subname, grade, sgpa], (err) => {
            if (err) console.error(`❌ DB Error [${regno} - ${subcode}]:`, err.message);
          });

          inserted++;
        }

        i++; // skip result line
      }
    }

    // Save .csv version
    const csvPath = path.join(__dirname, "uploads", `${baseName}.csv`);
    const csvHeader = "regno,semester,subcode,subname,grade,sgpa\n";
    const csvContent = csvHeader + results.map(r => r.join(",")).join("\n");
    fs.writeFileSync(csvPath, csvContent, "utf-8");

    // Clean up PDF
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      message: `✅ ${inserted} subject grades inserted successfully.`,
      csvFile: `/uploads/${baseName}.csv`,
      txtFile: `/uploads/${baseName}.txt`
    });

  } catch (err) {
    console.error("❌ Fatal Error:", err);
    res.status(500).json({ success: false, message: "❌ Server error during parsing." });
  }
});

// Route: Upload attendance PDF
// Attendance upload route
app.post("/upload-attendance", upload.single("pdf"), (req, res) => {
  const semester = req.body.semester;
  const filePath = req.file?.path;

  if (!semester || !filePath) {
    return res.status(400).json({ message: "❌ Semester or PDF missing." });
  }

  console.log("📄 Attendance PDF File Path:", filePath);
  console.log("🐍 Running Python attendance script...");

  const python = spawn("python", ["extract_attendance.py", filePath, semester]);

  let output = "";
  let errorOutput = "";

  python.stdout.on("data", (data) => output += data.toString());
  python.stderr.on("data", (data) => errorOutput += data.toString());

  python.on("close", (code) => {
    console.log("🐍 Python exited with code:", code);
    if (errorOutput) console.error("🐍 stderr:\n", errorOutput);

    if (code !== 0) {
      return res.status(500).json({
        message: "❌ Python error",
        error: errorOutput || "Unknown error"
      });
    }

    let records;
    try {
      records = JSON.parse(output);
    } catch (err) {
      return res.status(500).json({ message: "❌ Invalid JSON", error: err.message });
    }

    let inserted = 0;
    const insertPromises = records.map(([regno, sem, total, present, percent]) => {
      return new Promise((resolve) => {
        connection.query(
          `INSERT INTO attendance 
           (regno, semester, total_classes, attended_classes, percentage) 
           VALUES (?, ?, ?, ?, ?) 
           ON DUPLICATE KEY UPDATE 
           total_classes=?, attended_classes=?, percentage=?`,
          [regno, sem, total, present, percent, total, present, percent],
          (err) => {
            if (err) {
              console.error(`❌ DB Error for ${regno}:`, err.message);
            } else {
              inserted++;
            }
            resolve();
          }
        );
      });
    });

    Promise.all(insertPromises).then(() => {
      const csvFileName = path.basename(filePath).replace(".pdf", ".csv");
      res.status(200).json({
        message: "✅ Attendance extracted and stored.",
        total: inserted,
        csv_file: `/uploads/${csvFileName}`
      });
    });
  });
});

app.get("/student-attendance/:regno", (req, res) => {
  const regno = req.params.regno;

  connection.query(
    "SELECT semester, total_classes, attended_classes, percentage FROM attendance WHERE regno = ? ORDER BY semester",
    [regno],
    (err, results) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ success: false, message: "Database error." });
      }

      res.json({ success: true, data: results });
    }
  );
});

// Fetch student results by regno and semester
app.get('/student/results/:regno', async (req, res) => {
  const { regno } = req.params;
  const semester = req.query.semester;

  console.log("📥 Incoming Request:", { regno, semester });

  try {
    // 1. Fetch semester-wise results from BOTH tables
    connection.query(
      `
      SELECT subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [regno, semester, regno, semester],
      (err, semResults) => {
        if (err) {
          console.error("❌ Error fetching sem results:", err);
          return res.status(500).json({ error: "DB error (semResults)" });
        }

        // 2. Fetch all results from BOTH tables for CGPA calculation
        connection.query(
          `
          SELECT grade, credits 
          FROM results 
          WHERE regno = ?
          UNION ALL
          SELECT grade, NULL as credits 
          FROM autonomous_results 
          WHERE regno = ?
          `,
          [regno, regno],
          (err, allResults) => {
            if (err) {
              console.error("❌ Error fetching all results:", err);
              return res.status(500).json({ error: "DB error (allResults)" });
            }

            const gradePoints = {
              S: 10, A: 9, B: 8, C: 7, D: 6, E: 5, F: 0, Ab: 0,
              Completed: 10, Absent: 0
            };

            function calculateGPA(results) {
              let totalCredits = 0;
              let weightedSum = 0;

              for (const r of results) {
                const point = gradePoints[r.grade];
                if (point === undefined) continue;

                // ✅ If credits are missing (autonomous), assume 3 by default
                const credits = r.credits !== null ? r.credits : 3;

                weightedSum += point * credits;
                totalCredits += credits;
              }

              const gpa = totalCredits > 0 ? weightedSum / totalCredits : 0;
              return { gpa: gpa.toFixed(2), totalCredits };
            }

            const { gpa: sgpa } = calculateGPA(semResults);
            const { gpa: cgpa } = calculateGPA(allResults);
            const percentage = ((parseFloat(cgpa) - 0.5) * 10).toFixed(2);

            res.json({
              regno,
              semester,
              results: semResults,
              sgpa,
              cgpa,
              percentage,
            });
          }
        );
      }
    );
  } catch (err) {
    console.error("❌ Uncaught Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


const GRADE_POINTS = {
  S: 10,
  A: 9,
  B: 8,
  C: 7,
  D: 6,
  E: 5,
  F: 0,
  Ab: 0,
  Completed: 10
};

app.get("/student/overallResults/:regno", async (req, res) => {
  const { regno } = req.params;

  try {
    // 🟢 Fetch grades + credits from BOTH tables
    const [rows] = await connection.promise().query(
      `
      SELECT grade, credits 
      FROM results 
      WHERE regno = ?

      UNION ALL

      SELECT grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ?
      `,
      [regno, regno]
    );

    // 🟢 If no data found
    if (!rows.length) return res.json({ sgpa: "0.00", percentage: "0.00" });

    let totalGradePoints = 0;
    let totalCredits = 0;

    rows.forEach(({ grade, credits }) => {
      const gradePoint = GRADE_POINTS[grade] || 0;

      // ✅ If autonomous results have no credits, assume 3
      const subjectCredits = credits !== null ? credits : 3;

      totalGradePoints += gradePoint * subjectCredits;
      totalCredits += subjectCredits;
    });

    const sgpa = totalCredits > 0 ? (totalGradePoints / totalCredits).toFixed(2) : "0.00";
    const percentage = (sgpa * 9.5).toFixed(2); // approximate conversion

    res.json({ sgpa, percentage });

  } catch (err) {
    console.error("❌ Failed to fetch overall results:", err);
    res.status(500).json({ sgpa: "0.00", percentage: "0.00" });
  }
});

// result verification
// ✅ Verify result (includes both results + autonomous_results)
app.get("/api/verify-result", async (req, res) => {
  const { regno, sem } = req.query;
  if (!regno || !sem) return res.status(400).json({ error: "Missing regno or sem" });

  function queryAsync(sql, values) {
    return new Promise((resolve, reject) => {
      connection.query(sql, values, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }

  try {
    // 🟢 Fetch results from BOTH tables
    const results = await queryAsync(
      `
      SELECT subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [regno, sem, regno, sem]
    );

    // 🟢 Fetch student details
    const studentRows = await queryAsync(
      "SELECT name, reg_no, course, photo_url FROM students WHERE reg_no = ?",
      [regno]
    );
    const student = studentRows[0] || {};

    // 🟢 GPA Calculation
    const gradeMap = { S: 10, A: 9, B: 8, C: 7, D: 6, E: 5, F: 0, Ab: 0 };
    let totalCredits = 0, totalPoints = 0;

    results.forEach(r => {
      const gp = gradeMap[r.grade] ?? 0;

      // ✅ If autonomous results don't have credits, assume 3
      const credits = r.credits !== null ? r.credits : 3;

      totalCredits += credits;
      totalPoints += gp * credits;
    });

    const sgpa = totalCredits ? (totalPoints / totalCredits).toFixed(2) : "N/A";

    res.json({
      name: student.name || "N/A",
      regno: student.reg_no || regno,
      course: student.course || "N/A",
      semester: sem,
      photo_url: student.photo_url || null,
      sgpa,
      results
    });
  } catch (err) {
    console.error("❌ Verification error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// generate results certificate (supports results + autonomous_results)
app.get("/generate-certificate/:userId", async (req, res) => {
  const { userId } = req.params;
  const semester = req.query.semester;
  if (!semester) return res.status(400).send("Semester is required");

  const doc = new PDFDocument({ size: "A4", margin: 40 });
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=Result_${userId}_${semester}.pdf`);
  doc.pipe(res);

  function queryAsync(sql, values) {
    return new Promise((resolve, reject) => {
      connection.query(sql, values, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }

  const gradePointMap = {
    S: 10, A: 9, B: 8, C: 7, D: 6, E: 5, F: 0, Ab: 0, ABSENT: 0, Completed: 0
  };

  try {
    // 🟢 Fetch results from BOTH tables
    const results = await queryAsync(
      `
      SELECT regno, subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT regno, subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [userId, semester, userId, semester]
    );

    if (!results.length) {
      doc.fontSize(14).text("❌ No results found", 100, 100);
      doc.end();
      return;
    }

    // 🟢 Fetch student info
    const studentRows = await queryAsync(
      "SELECT name, reg_no, course, father_name, photo_url FROM students WHERE userId = ?",
      [userId]
    );
    const student = studentRows[0] || {};
    const reg = student.reg_no || "";

    // 🟢 Decide JNTUK vs Autonomous header
    const isJNTUK = /^([0-1][0-9]|23)B8/.test(reg);
    const isAutonomous = /^24B8/.test(reg);

    if (isJNTUK) {
      const logoPath = path.join(__dirname, "public", "jntuk_logo.png");
      if (fs.existsSync(logoPath)) {
        doc.image(logoPath, 40, 40, { width: 60 });
      }
      doc
        .font("Helvetica-Bold")
        .fillColor("#7A0C0C")
        .fontSize(14)
        .text("JAWAHARLAL NEHRU TECHNOLOGICAL UNIVERSITY KAKINADA", 110, 45)
        .text("KAKINADA - 533003, ANDHRA PRADESH, INDIA", 110, 65);

      doc.moveTo(40, 100).lineTo(555, 100).stroke("#000");
    } else if (isAutonomous) {
      const headerPath = path.join(__dirname, "public", "logo.png"); // autonomous logo/header
      if (fs.existsSync(headerPath)) {
        doc.image(headerPath, { fit: [520, 120], align: "center" });
      }
    }

    // 🟢 Student Info
    doc.moveDown(2);
    const startY = doc.y;
    let lineY = startY;
    const labelX = 40;
    const valueX = 180;

    doc.font("Helvetica").fillColor("black").fontSize(10);
    doc.text("STUDENT NAME    :", labelX, lineY);
    doc.text(student.name || "N/A", valueX, lineY); lineY += 26;
    doc.text("FATHER'S NAME   :", labelX, lineY);
    doc.text(student.father_name || "N/A", valueX, lineY); lineY += 26;
    doc.text("REGISTRATION NO :", labelX, lineY);
    doc.text(student.reg_no || "N/A", valueX, lineY); lineY += 26;
    doc.text("COURSE          :", labelX, lineY);
    doc.text(`B.TECH - ${student.course || "N/A"}`, valueX, lineY); lineY += 26;
    doc.text("YEAR - SEMESTER :", labelX, lineY);
    doc.text(semester.toUpperCase(), valueX, lineY);

    // 🟢 Student Photo
    const photo_url = student.photo_url;
    if (photo_url) {
      try {
        const photoRes = await axios.get(photo_url, {
          responseType: "arraybuffer",
          headers: { "User-Agent": "Mozilla/5.0" }
        });
        doc.image(photoRes.data, 400, startY, { fit: [100, 120] });
      } catch {
        doc.rect(400, startY, 100, 120).stroke();
      }
    } else {
      doc.rect(400, startY, 100, 120).stroke();
    }

    // 🟢 Results Table
    doc.y = lineY + 60;
    const tableTop = doc.y;
    const rowHeight = 30;
    const colX = [40, 80, 180, 400, 460];
    const colWidths = [40, 100, 220, 60, 60];

    // watermark
    const watermarkPath = path.join(__dirname, "public", "jntuk_logo.png");
    if (isJNTUK && fs.existsSync(watermarkPath)) {
      doc.opacity(0.1).image(watermarkPath, 160, tableTop + 60, { width: 250 });
      doc.opacity(1);
    }

    doc.font("Helvetica-Bold").fontSize(9);
    ["S.No", "Sub Code", "Subject Name", "Grade", "Credits"].forEach((text, i) => {
      doc.rect(colX[i], tableTop, colWidths[i], rowHeight).stroke();
      doc.text(text, colX[i] + 2, tableTop + 8, { width: colWidths[i] - 4, align: "center" });
    });

    doc.font("Helvetica").fontSize(9);
    let totalCredits = 0, weightedSum = 0;
    results.forEach((row, i) => {
      const y = tableTop + rowHeight * (i + 1);
      const gradePoint = gradePointMap[row.grade?.toUpperCase()?.trim()] ?? 0;

      // ✅ Autonomous subjects have NULL credits → assume 3
      const credits = row.credits !== null ? parseFloat(row.credits) : 3;

      weightedSum += gradePoint * credits;
      totalCredits += credits;

      const data = [i + 1, row.subcode, row.subname, row.grade, credits];
      data.forEach((text, j) => {
        doc.rect(colX[j], y, colWidths[j], rowHeight).stroke();
        doc.text(String(text), colX[j] + 2, y + 8, {
          width: colWidths[j] - 4,
          align: "center"
        });
      });
    });

    const calculatedSGPA = totalCredits > 0 ? (weightedSum / totalCredits).toFixed(2) : "N/A";
    const finalTableY = tableTop + rowHeight * (results.length + 1);
    doc.font("Helvetica-Bold").fontSize(10);
    doc.text(`SEMESTER GRADE POINT AVERAGE (SGPA): ${calculatedSGPA}`, 100, finalTableY + 25, {
      width: 250,
      align: "center"
    });

    // footer legend
    doc.font("Helvetica").fontSize(8).fillColor("black");
    doc.text("CP: COMPLETED   NCP: NOT-COMPLETED   MP: Malpractice   WH: Withheld   P: Pass   F: Fail   AB: Absent", 40, finalTableY + 50);

    // QR
    const qrText = `https://crr-noc.onrender.com/verifyresult.html?regno=${userId}&sem=${semester}`;
    const qrDataURL = await QRCode.toDataURL(qrText);
    const qrBuffer = Buffer.from(qrDataURL.split(",")[1], "base64");
    doc.image(qrBuffer, 440, 670, { width: 80 });

    // signatures
    doc.font("Helvetica").fontSize(10);
    doc.text("Controller of Examinations", 40, 740);
    doc.text("Principal", 320, 740);

    const date = new Date().toLocaleDateString("en-GB").replace(/\//g, "-");
    doc.fontSize(6).text(`ISSUED DATE: ${date}`, 440, 790, { align: "right", width: 100 });

    doc.end();
  } catch (err) {
    console.error("❌ PDF generation error:", err);
    doc.fontSize(12).text("Something went wrong while generating the result.");
    doc.end();
  }
});

//admin create noc 
app.post('/admin/manual-create-noc', (req, res) => {
  const { regno, year, feeStatus } = req.body;

  if (!regno || !year || !feeStatus) {
    return res.status(400).json({ success: false, message: "Missing required fields." });
  }

  const fileName = `manual_noc_${regno}_year${year}.pdf`;
  const filePath = path.join(__dirname, 'uploads', fileName);

  const doc = new PDFDocument({ margin: 50 });
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  // Header
  const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
  if (fs.existsSync(headerPath)) {
    doc.image(headerPath, { fit: [500, 150], align: 'center' });
    doc.moveDown(3);
  }

  doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE', {
    align: 'center',
    underline: true
  });
  doc.moveDown();

  doc.font('Times-Roman').fontSize(12).text(`Reg No: ${regno}`);
  doc.text(`Academic Year: ${year}`);
  doc.moveDown();
  doc.text(`This is to certify that the student has the following fee details:`);
  doc.moveDown();

  const readableMap = {
    tuition: "TUTION FEE",
    hostel: "HOSTEL FEE",
    bus: "BUS FEE",
    university: "UNIVERSITY FEE",
    semester: "EXAMINATION CELL",
    library: "LIBRARY FEE",
    fines: "FINE"
  };

  const leftX = 70, rightX = 350, rowHeight = 20;
  let y = doc.y;

  // Prepare plain string for QR
  let qrString = `Reg No: ${regno}\nYear: ${year}\n`;

  for (const key in feeStatus) {
    const label = readableMap[key] || key.toUpperCase();
    const status = feeStatus[key]?.status || "Not Specified";
    const amount = feeStatus[key]?.amount || "-";
    doc.text(label, leftX, y);
    doc.text(`${status.toUpperCase()} ${amount !== "-" ? `(₹${amount})` : ""}`, rightX, y);
    y += rowHeight;

    qrString += `${label}: ${status} ₹${amount}\n`;
  }

  doc.moveDown();
  doc.text(`This is a system-generated certificate and does not require a manual signature.`, {
    align: 'center'
  });
  doc.moveDown();
  doc.font('Times-Bold').text("COLLEGE STAMP", { align: 'center' });

  QRCode.toDataURL(qrString, (err, qrUrl) => {
    if (err) {
      console.error("QR code generation failed", err);
      doc.end();
      return res.status(500).json({ success: false, message: "QR generation failed." });
    }

    const qrSize = 50;
    doc.image(qrUrl, 150, doc.y, { width: qrSize });
    doc.fontSize(10).text("Scan to view details", 145, doc.y + qrSize + 5, {
      width: 100,
      align: 'center'
    });

    const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
    if (fs.existsSync(footerPath)) {
      doc.image(footerPath, (doc.page.width - 500) / 2, doc.page.height - 100, { width: 500 });
    }

    doc.end();

    stream.on("finish", () => {
      // 🔁 Send the PDF file as a download
      res.download(filePath, fileName, (err) => {
        if (err) {
          console.error("Download error:", err);
          res.status(500).json({ success: false, message: "Download failed." });
        }
      });
    });
  });
});
ENC_KEY=12345678901234567890123456789012
ENC_IV=1234567890123456
//verify manual noc by qr
// Manual NOC QR Verification Page
app.get("/verify-noc/manual", (req, res) => {
  const { regno, year, ...rest } = req.query;
  if (!regno || !year) return res.send("❌ Invalid QR code.");

  let html = `
    <h2>✅ Manual NOC Verified</h2>
    <p><strong>Reg No:</strong> ${regno}</p>
    <p><strong>Academic Year:</strong> ${year}</p>
    <h3>Fee Status:</h3>
    <ul>`;

  const feeTypes = ["tuition", "hostel", "bus", "university", "semester", "library", "fines"];
  feeTypes.forEach(type => {
    const status = rest[`${type}Status`] || "-";
    const amount = rest[`${type}Amount`] || "-";
    html += `<li>${type.toUpperCase()}: ${status} - ₹${amount}</li>`;
  });

  html += `</ul><p>This NOC is verified by the system.</p>`;
  res.send(html);
});

// add counselling students
app.post("/assign-counselling", async (req, res) => {
  const {
    fromReg,
    toReg,
    counsellorName,
    counsellorMobile,
    counsellorId
  } = req.body;

  if (!fromReg || !toReg || !counsellorName || !counsellorMobile || !counsellorId) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const query = `
    UPDATE students
    SET counsellor_name = ?, counsellor_mobile = ?, counsellor_id = ?
    WHERE reg_no BETWEEN ? AND ?;
  `;

  connection.query(
    query,
    [counsellorName, counsellorMobile, counsellorId, fromReg, toReg],
    (err, result) => {
      if (err) {
        console.error("❌ Error updating students:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      return res.status(200).json({
        message: `✅ Successfully assigned counsellor to ${result.affectedRows} students.`
      });
    }
  );
});

app.get("/my-counselling-students/:staffId", (req, res) => {
  const { staffId } = req.params;

  const query = `
    SELECT 
      name,
      reg_no,
      email,
      course,
      year,
      mobile_no,
      section,
      father_name,
      father_mobile
    FROM students
    WHERE counsellor_id = ?
  `;

  connection.query(query, [staffId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching counselling students:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    res.json({ success: true, students: results });
  });
});

//update father details
app.post("/update-father-details", (req, res) => {
  const { reg_no, father_name, father_mobile } = req.body;

  if (!reg_no || !father_name || !father_mobile) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  const query = `
    UPDATE students
    SET father_name = ?, father_mobile = ?
    WHERE reg_no = ?
  `;

  connection.query(query, [father_name, father_mobile, reg_no], (err, result) => {
    if (err) {
      console.error("❌ Error updating father details:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    res.json({ success: true, message: "Father details updated successfully" });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout failed:", err);
      return res.status(500).send("Logout failed");
    }
    res.clearCookie("noc_sid");
    res.redirect('/index.html');
  });
});
app.get('/check-session', (req, res) => {
  if (
    req.session.userId &&
    (req.session.role === 'admin' || req.session.role === 'exam' || req.session.role ==='accounts')
  ) {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});

app.post('/staff/update-student', (req, res) => {
  const {
    userId,
    name,
    dob,
    course,
    semester,
    section,
    year,
    father_name,
    father_mobile,
    mobile_no,
    email,
    admission_type,
    counsellor_name,
    counsellor_mobile
  } = req.body;

  if (!userId) {
    return res.status(400).json({ success: false, message: "Missing userId" });
  }

  const safe_admission_type = (admission_type && admission_type !== "null") ? admission_type : null;
  const safe_section = (section && section !== "null") ? section : null;

  const query = `
    UPDATE students SET
      name = ?, dob = ?, course = ?, semester = ?, section = ?, year = ?,
      father_name = ?, father_mobile = ?, mobile_no = ?, email = ?, admission_type = ?,
      counsellor_name = ?, counsellor_mobile = ?
    WHERE userId = ?
  `;

  const values = [
    name, dob, course, semester, safe_section, year,
    father_name, father_mobile, mobile_no, email, safe_admission_type,
    counsellor_name, counsellor_mobile,
    userId
  ];

  connection.query(query, values, (err, result) => {
    if (err) {
      console.error("❌ SQL error while updating student:", err);
      return res.status(500).json({ success: false, message: "Server error while updating student." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "No student found with the given userId." });
    }

    res.json({ success: true, message: "Student profile updated successfully." });
  });
});

// 🔹 Route: Get all students in HOD's department
app.get('/hod/students', (req, res) => {
  const { staffId } = req.query;

  console.log("📥 Incoming request to /hod/students with staffId:", staffId);

  if (!staffId || !staffId.toUpperCase().startsWith("HOD")) {
    console.warn("⚠️ Invalid or missing staffId");
    return res.status(400).json({ error: "Invalid or missing staffId" });
  }

  const deptCode = staffId.toUpperCase().replace("HOD", "");
  console.log("🧩 Extracted deptCode:", deptCode);

  // Use your existing MySQL connection (change `connection` to whatever you're using)
  connection.query(
    `SELECT name, reg_no, course, year, section, mobile_no, email, father_name, father_mobile
     FROM students WHERE dept_code = ?`,
    [deptCode],
    (err, results) => {
      if (err) {
        console.error("❌ Database error in /hod/students:", err.message);
        return res.status(500).json({ error: "Internal server error" });
      }

      console.log(`📊 Retrieved ${results.length} students for dept ${deptCode}`);

      return res.json({
        status: "success",
        total: results.length,
        students: results,
      });
    }
  );
});

app.get("/hod/pass-fail-stats", (req, res) => {
  const { staffId, year, course, section } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }

  const deptCode = staffId.replace("HOD", "");
  const filters = ["s.dept_code = ?"];
  const params = [deptCode];

  if (year) { filters.push("s.year = ?"); params.push(year); }
  if (course) { filters.push("s.course = ?"); params.push(course); }
  if (section) { filters.push("s.section = ?"); params.push(section); }

  const query = `
    SELECT s.year, s.course, s.section,
      COUNT(DISTINCT s.reg_no) AS total_students,
      SUM(CASE WHEN failed.failed_count > 0 THEN 1 ELSE 0 END) AS failed_students
    FROM students s
    LEFT JOIN (
      SELECT regno, COUNT(*) AS failed_count
      FROM results
      WHERE grade IN ('F','Ab','NOT_COMPLETED','MP')
      GROUP BY regno
    ) AS failed
    ON failed.regno = s.reg_no
    WHERE ${filters.join(" AND ")}
    GROUP BY s.year, s.course, s.section
    ORDER BY s.year, s.course, s.section
  `;

  connection.query(query, params, (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching pass/fail stats:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const stats = rows.map(row => {
      const pass = row.total_students - row.failed_students;
      return {
        year: row.year,
        course: row.course,
        section: row.section,
        pass_percent: row.total_students === 0 ? 0 : Math.round((pass / row.total_students) * 100),
        fail_percent: row.total_students === 0 ? 0 : Math.round((row.failed_students / row.total_students) * 100)
      };
    });

    res.json({ stats });
  });
});

app.get("/hod/courses", (req, res) => {
  const { staffId, year } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }
  if (!year) {
    return res.status(400).json({ error: "Year is required" });
  }

  const deptCode = staffId.replace("HOD", "");

  const query = `
    SELECT DISTINCT course FROM students
    WHERE dept_code = ? AND year = ?
    ORDER BY course
  `;

  connection.query(query, [deptCode, year], (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching courses:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(rows.map(r => r.course));
  });
});


app.get("/hod/sections", (req, res) => {
  const { staffId, year, course } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }
  if (!year || !course) {
    return res.status(400).json({ error: "Year and Course required" });
  }

  const deptCode = staffId.replace("HOD", "");

  const query = `
    SELECT DISTINCT section FROM students
    WHERE dept_code = ? AND year = ? AND course = ?
    ORDER BY section
  `;

  connection.query(query, [deptCode, year, course], (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching sections:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(rows.map(r => r.section));
  });
});


// Backlog Summary Route
app.get("/hod/backlog-summary", (req, res) => {
  const { staffId, year, course, section } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }

  const deptCode = staffId.replace("HOD", "");
  const filters = ["s.dept_code = ?"];
  const params = [deptCode];

  if (year) { filters.push("s.year = ?"); params.push(year); }
  if (course) { filters.push("s.course = ?"); params.push(course); }
  if (section) { filters.push("s.section = ?"); params.push(section); }

  const query = `
    SELECT s.reg_no,
      SUM(CASE WHEN r.grade IN ('F','Ab','NOT_COMPLETED','MP') THEN 1 ELSE 0 END) AS backlogs
    FROM students s
    LEFT JOIN results r ON r.regno = s.reg_no
    WHERE ${filters.join(" AND ")}
    GROUP BY s.reg_no
  `;

  connection.query(query, params, (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching backlog summary:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    let zero = 0, low = 0, high = 0;
    rows.forEach(r => {
      if (r.backlogs === 0) zero++;
      else if (r.backlogs <= 2) low++;
      else high++;
    });

    res.json({ zero, low, high });
  });
});

function cleanRow(row) {
  const cleaned = {};
  for (let key in row) {
    const cleanKey = key.replace(/\uFEFF/g, "").trim(); // Remove BOM + trim
    cleaned[cleanKey] = typeof row[key] === "string" ? row[key].trim() : row[key];
  }
  return cleaned;
}

app.post('/admin/upload-students', upload.single("studentfile"), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

  const fileExt = path.extname(req.file.originalname).toLowerCase();
  let results = [];

  const insertStudents = (rows) => {
    let insertCount = 0;
    let updateCount = 0;

    rows.forEach((rawRow) => {
      const student = cleanRow(rawRow);

      const userId = student.userId || student["﻿userId"];
      const reg_no = student.reg_no;
      const uniqueId = student.uniqueId;

      if (!userId || !reg_no || !uniqueId) {
        console.warn("❌ Skipping row due to missing critical fields:", student);
        return;
      }

      // Insert or update in users
      const userQuery = `
        INSERT INTO users (userid, password, role)
        VALUES (?, ?, 'student')
        ON DUPLICATE KEY UPDATE password = VALUES(password)
      `;

      connection.query(userQuery, [userId, userId], (userErr) => {
        if (userErr) {
          console.error("❌ User insert failed:", userErr);
          return;
        }

        const studentQuery = `
          INSERT INTO students (
            userId, name, dob, reg_no, uniqueId, year, course, dept_code, semester,
            aadhar_no, mobile_no, email, father_name, father_mobile,
            admission_type, photo_url, photo_public_id, section,
            counsellor_name, counsellor_mobile, counsellor_id
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            name = VALUES(name), dob = VALUES(dob), year = VALUES(year),
            course = VALUES(course), dept_code = VALUES(dept_code), semester = VALUES(semester),
            aadhar_no = VALUES(aadhar_no), mobile_no = VALUES(mobile_no), email = VALUES(email),
            father_name = VALUES(father_name), father_mobile = VALUES(father_mobile),
            admission_type = VALUES(admission_type), photo_url = VALUES(photo_url),
            photo_public_id = VALUES(photo_public_id), section = VALUES(section),
            counsellor_name = VALUES(counsellor_name), counsellor_mobile = VALUES(counsellor_mobile),
            counsellor_id = VALUES(counsellor_id)
        `;

        const values = [
          userId,
          student.name || null,
          student.dob || null,
          reg_no,
          uniqueId,
          student.year || null,
          student.course || null,
          student.dept_code || null,
          student.semester || null,
          student.aadhar_no || null,
          student.mobile_no || null,
          student.email || null,
          student.father_name || null,
          student.father_mobile || null,
          student.admission_type || null,
          student.photo_url || null,
          student.photo_public_id || null,
          student.section || null,
          student.counsellor_name || null,
          student.counsellor_mobile || null,
          student.counsellor_id || null
        ];

        connection.query(studentQuery, values, (studentErr, result) => {
          if (studentErr) {
            console.error("❌ Student insert/update failed:", studentErr);
          } else {
            if (result.affectedRows === 1) insertCount++;
            else if (result.affectedRows === 2) updateCount++;
          }
        });
      });
    });

    fs.unlinkSync(req.file.path);

    setTimeout(() => {
      res.json({
        success: true,
        message: `✅ Upload complete! ${insertCount} inserted, ${updateCount} updated.`,
      });
    }, 1500);
  };

  // Handle file
  if (fileExt === ".csv") {
    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on("data", (row) => results.push(cleanRow(row)))
      .on("end", () => insertStudents(results));
  } else if (fileExt === ".xlsx") {
    const workbook = xlsx.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    results = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
    results = results.map(cleanRow);
    insertStudents(results);
  } else {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ success: false, message: "Unsupported file format." });
  }
});

app.post("/upload-midmarks", upload.single("file"), (req, res) => {
  const filePath = req.file.path;
  const results = [];

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => {
      results.push([
        row["CC"],
        row["HALLTICKET"],
        row["SUB CODE"],
        row["MID-1 (15M)"],
        row["A-1(5M)"],
        row["Q-1(20M)"],
        row["MID-2(15M)"],
        row["A-2(5M)"],
        row["Q-2(20M)"],
        row["LDS(30)/STATUS"],
        row["REG"],
        row["YEAR"],
        row["SEM"],
      ]);
    })
    .on("end", () => {
      const sql = `
        INSERT INTO mid_internal_marks
        (cc, hallticket, sub_code, mid1, a1, q1, mid2, a2, q2, lds_or_status, regulation, year, semester)
        VALUES ?
      `;
      connection.query(sql, [results], (err) => {
        fs.unlinkSync(filePath);
        if (err) return res.status(500).json({ error: err });
        res.json({ message: "✅ CSV Data inserted", count: results.length });
      });
    });
});
// get mid marks
app.get("/student/midmarks/:regno", (req, res) => {
  const { regno } = req.params;
  const { year, semester } = req.query;

  console.log("📥 Incoming Mid Marks Request:", { regno, year, semester });

const sql = `
  SELECT sub_code, mid1, a1, q1, mid2, a2, q2, lds_or_status 
  FROM mid_internal_marks 
  WHERE hallticket = ? AND TRIM(year) = ? AND TRIM(semester) = ?
`;


  connection.query(sql, [regno, year, semester], (err, rows) => {
    if (err) {
      console.error("❌ Error fetching mid marks:", err);
      return res.status(500).json({ error: "DB error while fetching mid marks" });
    }

    if (rows.length === 0) {
      console.warn("⚠️ No mid marks found for:", { regno, year, semester });
      return res.json({ regno, year, semester, midmarks: [] });
    }

    res.json({
      regno,
      year,
      semester,
      midmarks: rows,
    });
  });
});
//hod mid marks 
app.get("/api/midmarks/search", (req, res) => {
  const { regno, year, semester } = req.query;

  if (!regno || !year || !semester) {
    return res.status(400).json({ error: "Missing required query parameters" });
  }

  console.log("🔍 Mid Marks Search:", { regno, year, semester });

  const sql = `
    SELECT 
      hallticket AS regno,
      sub_code AS subcode,
      mid1, a1, q1,
      mid2, a2, q2,
      lds_or_status
    FROM mid_internal_marks
    WHERE 
      hallticket = ?
      AND TRIM(year) = ?
      AND TRIM(semester) = ?
  `;

  connection.query(sql, [regno, year, semester], (err, results) => {
    if (err) {
      console.error("❌ DB Error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(results);
  });
});

//  HOD send notification route
app.post('/api/notifications/send', (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message || !userId.startsWith("HOD")) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }

  const sql = 'INSERT INTO notifications (staffId, message) VALUES (?, ?)';
  const values = [userId, message];

  connection.query(sql, values, (err, results) => {
    if (err) {
      console.error('❌ DB Error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    res.json({ success: true, message: 'Notification sent' });
  });
});

//get dept wise notifications
app.get('/student/notifications/:userId', (req, res) => {
  const userId = req.params.userId;

  const getDeptQuery = `SELECT dept_code FROM students WHERE userId = ?`;

  connection.query(getDeptQuery, [userId], (err, deptResult) => {
    if (err) {
      console.error('❌ Error fetching department:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (deptResult.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const deptCode = deptResult[0].dept_code;

    // HOD notification format: HODCSE, HODIT, etc.
    const deptHOD = 'HOD' + deptCode;

    const getNotificationsQuery = `
      SELECT * FROM notifications
      WHERE staffId = ? OR staffId = 'ALL'
      ORDER BY date_sent DESC
    `;

    connection.query(getNotificationsQuery, [deptHOD], (err, notificationsResult) => {
      if (err) {
        console.error('❌ Error fetching notifications:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json(notificationsResult);
    });
  });
});


app.get('/api/departments', (req, res) => {
  const sql = 'SELECT DISTINCT dept_code FROM students';
  connection.query(sql, (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch departments' });
    res.json(result);
  });
});


app.get('/api/years/:dept_code', (req, res) => {
  const dept_code = req.params.dept_code;
  const sql = 'SELECT DISTINCT year FROM students WHERE dept_code = ?';
  connection.query(sql, [dept_code], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch years' });
    res.json(result);
  });
});

app.get('/api/courses-by-year', (req, res) => {
  const { dept_code, year } = req.query;
  const sql = 'SELECT DISTINCT course FROM students WHERE dept_code = ? AND year = ?';
  connection.query(sql, [dept_code, year], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch courses' });
    res.json(result);
  });
});

app.get('/api/sections', (req, res) => {
  const { dept_code, year, course } = req.query;
  const sql = `
    SELECT DISTINCT section FROM students 
    WHERE dept_code = ? AND year = ? AND course = ?
  `;
  connection.query(sql, [dept_code, year, course], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch sections' });
    res.json(result);
  });
});

app.get('/api/staff/:id', (req, res) => {
  const staffId = req.params.id;
  const sql = 'SELECT staff_name FROM staff WHERE staff_id = ?';
  connection.query(sql, [staffId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch staff' });
    if (result.length === 0) return res.status(404).json({ error: 'Staff not found' });
    res.json(result[0]);
  });
});

app.post("/api/allocate", (req, res) => {
  const {
    staff_id, year, course, dept_code,
    section, semester, day,
    period1, period2, period3, period4, period5, period6, period7
  } = req.body;

  if (!staff_id || !day || !semester) {
    return res.status(400).json({ success: false, error: "Missing required fields" });
  }

  // First, check for conflicts on the same day and periods for this staff
  const checkSql = `
    SELECT * FROM staff_period_allocation
    WHERE staff_id = ? AND day = ?
  `;

  connection.query(checkSql, [staff_id, day], (err, rows) => {
    if (err) {
      console.error("❌ Error checking for conflicts:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    // Check each period value for conflict
    const periods = [period1, period2, period3, period4, period5, period6, period7];
    const existingPeriods = [];

    rows.forEach(row => {
      for (let i = 1; i <= 7; i++) {
        if (row[`period${i}`]) existingPeriods.push(`period${i}`);
      }
    });

    const conflictPeriods = [];
    for (let i = 0; i < periods.length; i++) {
      if (periods[i] && existingPeriods.includes(`period${i + 1}`)) {
        conflictPeriods.push(`Period ${i + 1}`);
      }
    }

    if (conflictPeriods.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Conflict: Staff already allocated for ${conflictPeriods.join(", ")} on ${day}`
      });
    }

    // No conflicts – proceed with allocation
    const insertSql = `
      INSERT INTO staff_period_allocation (
        staff_id, year, course, dept_code, section,
        semester, day, period1, period2, period3,
        period4, period5, period6, period7
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
      staff_id, year, course, dept_code, section,
      semester, day, period1, period2, period3,
      period4, period5, period6, period7
    ];

    connection.query(insertSql, values, (err, result) => {
      if (err) {
        console.error("❌ Allocation insert error:", err);
        return res.status(500).json({ success: false, error: "Database error" });
      }

      res.json({ success: true, message: "Period allocation saved successfully!" });
    });
  });
});

// 🔹 Get Allocated Periods by Staff (Original + Adjustments)
app.get("/api/staff-allocation", (req, res) => {
  const { staff_id, date } = req.query;

  if (!staff_id) return res.status(400).json({ error: "Missing staff_id" });

  const sql = `
    (
      SELECT year, course, semester, section, dept_code, day,
        period1, period2, period3, period4, period5, period6, period7
      FROM staff_period_allocation
      WHERE TRIM(staff_id) = TRIM(?)
    )
    UNION
    (
      SELECT year, course, semester, section, NULL AS dept_code, day,
        CASE period_no WHEN 1 THEN subject END AS period1,
        CASE period_no WHEN 2 THEN subject END AS period2,
        CASE period_no WHEN 3 THEN subject END AS period3,
        CASE period_no WHEN 4 THEN subject END AS period4,
        CASE period_no WHEN 5 THEN subject END AS period5,
        CASE period_no WHEN 6 THEN subject END AS period6,
        CASE period_no WHEN 7 THEN subject END AS period7
      FROM staff_period_adjustments
      WHERE TRIM(to_staff_id) = TRIM(?) AND date = ?
    )
  `;

  connection.query(sql, [staff_id, staff_id, date], (err, result) => {
    if (err) {
      console.error("❌ Error fetching allocations:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
    res.json(result);
  });
});

// Get Students by Year, Semester, Course & Section
app.get("/api/students-by-course-section", (req, res) => {
  const { year, semester, course, section } = req.query;

  if (!year || !semester || !course || !section) {
    return res.status(400).json({ error: "Missing year, semester, course, or section" });
  }

  const sql = `
    SELECT reg_no, name, joining_date
    FROM students
    WHERE year = ? AND semester = ? AND course = ? AND section = ?
    ORDER BY reg_no
  `;

  connection.query(sql, [year, semester, course, section], (err, result) => {
    if (err) {
      console.error("❌ Error fetching students:", err);
      return res.status(500).json({ error: "Failed to fetch students" });
    }
    res.json(result);
  });
});

// 🔹 Submit Attendance
app.post('/api/submit-attendance', (req, res) => {
  const { entries } = req.body;

  if (!Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ success: false, message: "No attendance entries submitted" });
  }

  const values = entries.map(e => [
    e.reg_no,
    e.date,
    e.staff_id,
    e.course,
    e.year,
    e.semester,
    e.section,
    e.subject,
    e.status
  ]);

  const sql = `
    INSERT INTO daily_attendance 
    (reg_no, date, staff_id, course, year, semester, section, subject, status)
    VALUES ?
  `;

  connection.query(sql, [values], (err, result) => {
    if (err) {
      console.error("❌ Attendance insert failed:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    res.json({ success: true, inserted: result.affectedRows });
  });
});

// ✅ Get Period Info Route
app.get("/api/get-period-info", (req, res) => {
  const { staff_id, subject } = req.query;

  if (!staff_id || !subject) {
    return res.status(400).json({ error: "Missing staff_id or subject" });
  }

  const sql = `
    SELECT year, semester, day, 
      CASE 
        WHEN period1 = ? THEN '1'
        WHEN period2 = ? THEN '2'
        WHEN period3 = ? THEN '3'
        WHEN period4 = ? THEN '4'
        WHEN period5 = ? THEN '5'
        WHEN period6 = ? THEN '6'
        WHEN period7 = ? THEN '7'
        ELSE null 
      END AS period
    FROM staff_period_allocation
    WHERE staff_id = ? AND (
      period1 = ? OR period2 = ? OR period3 = ? OR
      period4 = ? OR period5 = ? OR period6 = ? OR period7 = ?
    )
    LIMIT 1
  `;

  const params = [
    subject, subject, subject, subject, subject, subject, subject, subject,
    staff_id,
    subject, subject, subject, subject, subject, subject
  ];

  connection.query(sql, params, (err, result) => {
    if (err) {
      console.error("Error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: "No matching period found" });
    }

    res.json(result[0]);
  });
});



// 🔹 Get Students by Section
app.get("/api/students-by-course-section", (req, res) => {
  const { year, semester, course, section } = req.query;

  if (!year || !semester || !course || !section) {
    return res.status(400).json({ error: "Missing year, semester, course, or section" });
  }

  const sql = `
    SELECT reg_no, name, joining_date
    FROM students
    WHERE year = ? AND semester = ? AND course = ? AND section = ?
    ORDER BY reg_no
  `;

  connection.query(sql, [year, semester, course, section], (err, result) => {
    if (err) {
      console.error("❌ Error fetching students:", err);
      return res.status(500).json({ error: "Failed to fetch students" });
    }
    res.json(result);
  });
});

app.get('/api/staff/semesters/:staffId', (req, res) => {
  const staffId = req.params.staffId;

  const sql = `
    SELECT DISTINCT semester 
    FROM staff_period_allocation 
    WHERE staff_id = ?
    ORDER BY 
      FIELD(semester, '1-1', '1-2', '2-1', '2-2', '3-1', '3-2', '4-1', '4-2')
  `;

  connection.query(sql, [staffId], (err, results) => {
    if (err) {
      console.error("Error fetching semesters:", err);
      return res.status(500).json({ error: "Database error" });
    }
    const semesters = results.map(row => row.semester);
    res.json({ semesters });
  });
});

// 📄 Download selected-subject attendance PDF (with lateral separation & TOTAL classes filled)
app.get("/api/download-attendance-pdf", (req, res) => {
  const { year, semester, course, section, subject, from_date, to_date } = req.query;

  if (!year || !semester || !course || !section || !subject || !from_date || !to_date) {
    return res.status(400).send("Missing required query parameters.");
  }

  const subjects = subject.split(",").map(s => s.split(":")[1]);
  const placeholders = subjects.map(() => "?").join(",");

  const query = `
    SELECT 
      a.reg_no,
      a.subject,
      COUNT(*) AS total_classes,
      SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS attended,
      s.joining_date,
      s.admission_type
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? AND a.semester = ? AND a.course = ? AND a.section = ?
      AND a.subject IN (${placeholders})
      AND a.date BETWEEN ? AND ?
    GROUP BY a.reg_no, a.subject, s.joining_date, s.admission_type
    ORDER BY a.reg_no, a.subject
  `;

  connection.query(
    query,
    [year, semester, course, section, ...subjects, from_date, to_date],
    (err, results) => {
      if (err) {
        console.error("❌ DB error:", err);
        return res.status(500).send("Database error.");
      }
      if (!results.length) {
        return res.status(404).send("No attendance records found.");
      }

      const allSubjects = Array.from(new Set(results.map(r => r.subject))).sort();
      const studentMap = {};

      results.forEach(r => {
        const reg = r.reg_no;
        const attended = parseInt(r.attended || 0, 10);
        const total_classes = parseInt(r.total_classes || 0, 10);
        const joinDate = r.joining_date ? new Date(r.joining_date) : null;
        const admissionType = r.admission_type || "regular";

        if (!studentMap[reg]) {
          studentMap[reg] = {
            regno: reg,
            subjects: {},
            total_attended: 0,
            subjectTotals: {},
            joining_date: joinDate,
            admission_type: admissionType
          };
        }
        studentMap[reg].subjects[r.subject] = attended;
        studentMap[reg].total_attended += attended;
        studentMap[reg].subjectTotals[r.subject] = total_classes;
      });

      const PDFDocument = require("pdfkit");
      const fs = require("fs");
      const path = require("path");

      const doc = new PDFDocument({ margin: 40, size: "A4", layout: "landscape" });
      const fileName = `AttendanceReport-${Date.now()}.pdf`;

      res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
      res.setHeader("Content-Type", "application/pdf");
      doc.pipe(res);

      const pageWidth = doc.page.width;
      const pageHeight = doc.page.height;
      const leftMargin = doc.page.margins.left;
      const rightMargin = doc.page.margins.right;
      const usableWidth = pageWidth - leftMargin - rightMargin;
      const signatureHeight = 70;
      const cellFontSize = 8;
      let regColWidth = 80;
      const otherColsCount = allSubjects.length + 2; // subjects + TOTAL + PERCENT
      const minColWidth = 45;
      let remainingWidth = usableWidth - regColWidth;
      let colWidth = Math.floor(remainingWidth / otherColsCount);
      if (colWidth < minColWidth) {
        colWidth = minColWidth;
        const totalNeeded = regColWidth + (colWidth * otherColsCount);
        if (totalNeeded > usableWidth) {
          regColWidth = Math.max(50, regColWidth - (totalNeeded - usableWidth));
        }
      }

      function renderPageHeader(headerText = "STATEMENT OF ATTENDANCE REPORT", totalsRowSource = null) {
        const logoPath = path.join(__dirname, "public", "crrengglogo.png");
        try {
          if (fs.existsSync(logoPath)) doc.image(logoPath, leftMargin, doc.page.margins.top, { width: 50 });
        } catch (e) {}
        const titleX = leftMargin + 60;
        const titleW = usableWidth - 60;
        doc.fontSize(14).font("Helvetica-Bold")
          .text("SIR C.R.REDDY COLLEGE OF ENGINEERING (Autonomous)", titleX, doc.page.margins.top - 2, { width: titleW, align: "center" });
        doc.fontSize(10).font("Helvetica")
          .text(`B.Tech Year - ${year}   Sem - ${semester}   Branch - ${course}   Section - ${section}`, { align: "center" });
        doc.fontSize(10).text(headerText, { align: "center" });
        doc.fontSize(8).text("Vatluru, Eluru - 534007, Eluru Dist. A.P.", { align: "center" });
        doc.fontSize(8).text(`From: ${from_date}  To: ${to_date}`, { align: "center" });
        doc.moveDown(0.5);

        let y = doc.y + 6;
        doc.moveTo(leftMargin, y).lineTo(pageWidth - rightMargin, y).stroke();
        y += 6;

        const headers = ["Regd.No", ...allSubjects, "TOTAL", "PERCENT"];
        let x = leftMargin;
        doc.fontSize(cellFontSize).font("Helvetica-Bold");
        headers.forEach((h, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          doc.save();
          doc.rect(x, y, w, 20).fillAndStroke("#007acc", "black");
          doc.fillColor("white").text(h.length > 18 ? h.substring(0, 18) + "..." : h, x + 3, y + 4, { width: w - 6, align: "center" });
          doc.restore();
          x += w;
        });
        y += 20;

        x = leftMargin;
        doc.fontSize(cellFontSize).font("Helvetica-Bold").fillColor("black");
        doc.rect(x, y, regColWidth, 20).stroke();
        doc.text("Total Classes", x + 3, y + 4, { width: regColWidth - 6, align: "center" });
        x += regColWidth;

        allSubjects.forEach(sub => {
          const totalForSubject = totalsRowSource ? totalsRowSource.subjectTotals[sub] || 0 : 0;
          doc.rect(x, y, colWidth, 20).stroke();
          doc.text(String(totalForSubject), x + 3, y + 4, { width: colWidth - 6, align: "center" });
          x += colWidth;
        });

        // TOTAL column
        const totalClassesSum = totalsRowSource
          ? allSubjects.reduce((sum, sub) => sum + (totalsRowSource.subjectTotals[sub] || 0), 0)
          : 0;
        doc.rect(x, y, colWidth, 20).stroke();
        doc.text(String(totalClassesSum), x + 3, y + 4, { width: colWidth - 6, align: "center" });
        x += colWidth;

        // PERCENT column (leave empty)
        doc.rect(x, y, colWidth, 20).stroke();
        x += colWidth;

        y += 20;
        return y;
      }

      // Regular students
      const regs = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() !== "lateral");
      let y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regs[0]);
      regs.forEach(std => {
        let possibleClasses = allSubjects.reduce((sum, sub) => sum + (std.subjectTotals[sub] || 0), 0);
        const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
        const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
        const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

        const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
        if (y + 20 > bottomLimit) {
          doc.addPage();
          y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regs[0]);
        }

        let x = leftMargin;
        rowCells.forEach((cell, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          if (i === rowCells.length - 1) {
            doc.fillColor(parseFloat(cell) < 75 ? "red" : "black");
          } else {
            doc.fillColor("black");
          }
          doc.rect(x, y, w, 20).stroke();
          doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
          x += w;
        });
        y += 20;
      });

      // Lateral students
      const laterals = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() === "lateral");
      if (laterals.length > 0) {
        doc.addPage();
        y = renderPageHeader("Lateral Entry Students", laterals[0]);
        laterals.forEach(std => {
          let possibleClasses = allSubjects.reduce((sum, sub) => sum + (std.subjectTotals[sub] || 0), 0);
          const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
          const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
          const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

          const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
          if (y + 20 > bottomLimit) {
            doc.addPage();
            y = renderPageHeader("Lateral Entry Students", laterals[0]);
          }

          let x = leftMargin;
          rowCells.forEach((cell, i) => {
            const w = (i === 0) ? regColWidth : colWidth;
            if (i === rowCells.length - 1) {
              doc.fillColor(parseFloat(cell) < 75 ? "red" : "black");
            } else {
              doc.fillColor("black");
            }
            doc.rect(x, y, w, 20).stroke();
            doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
            x += w;
          });
          y += 20;
        });
      }

      let lastY = doc.y || doc.page.margins.top;
      if ((pageHeight - doc.page.margins.bottom - lastY) < 80) {
        doc.addPage();
        lastY = doc.page.margins.top;
      }
      doc.fontSize(10).fillColor("black");
      doc.text("Faculty Signature", leftMargin + 10, lastY + 40);
      doc.text("HOD Signature", pageWidth - rightMargin - 160, lastY + 40);

      doc.end();
    }
  );
});


//fetch course and section by dept_code
app.get("/api/fetch-courses-sections", (req, res) => {
  const { dept_code, year } = req.query;

  if (!dept_code || !year) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const sql = `
    SELECT DISTINCT course, section 
    FROM students 
    WHERE dept_code = ? AND year = ?
  `;

  connection.query(sql, [dept_code, year], (err, results) => {
    if (err) {
      console.error("❌ DB error:", err);
      return res.status(500).json({ error: "DB error" });
    }

    res.json(results);
  });
});

// download section wise attendance with joining_date-based percentage + Lateral list at end
// download section wise attendance with joining_date-based percentage + Lateral list at end
app.get("/api/download-all-subjects-attendance", (req, res) => {
  const { year, course, section, semester, from_date, to_date } = req.query;
  if (!year || !course || !section || !from_date || !to_date || !semester) {
    return res.status(400).json({ error: "Missing query parameters." });
  }

  const query = `
    SELECT 
      a.reg_no,
      a.subject,
      COUNT(*) AS total_classes,
      SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS attended,
      s.joining_date,
      s.admission_type
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? 
      AND a.course = ? 
      AND a.section = ? 
      AND a.semester = ?
      AND a.date BETWEEN ? AND ?
      AND (
        s.admission_type != 'lateral' 
        OR a.date >= s.joining_date
      )
    GROUP BY a.reg_no, a.subject, s.joining_date, s.admission_type
    ORDER BY a.reg_no, a.subject
  `;

  connection.query(query, [year, course, section, semester, from_date, to_date], (err, results) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!results.length) return res.status(404).json({ error: "No data found" });

    const allSubjects = Array.from(new Set(results.map(r => r.subject))).sort();

    const studentMap = {};
    results.forEach(r => {
      const reg = r.reg_no;
      const attended = parseInt(r.attended || 0, 10);
      const total_classes = parseInt(r.total_classes || 0, 10);
      const joinDate = r.joining_date ? new Date(r.joining_date) : null;
      const admissionType = r.admission_type || "regular";

      if (!studentMap[reg]) {
        studentMap[reg] = {
          regno: reg,
          subjects: {},
          total_attended: 0,
          subjectTotals: {},
          joining_date: joinDate,
          admission_type: admissionType
        };
      }
      studentMap[reg].subjects[r.subject] = attended;
      studentMap[reg].total_attended += attended;
      studentMap[reg].subjectTotals[r.subject] = total_classes;
    });

    const PDFDocument = require("pdfkit");
    const fs = require("fs");
    const path = require("path");

    const doc = new PDFDocument({ margin: 40, size: "A4", layout: "landscape" });
    const fileName = `AttendanceReport-${Date.now()}.pdf`;
    const filePath = path.join(__dirname, "uploads", fileName);
    const writeStream = fs.createWriteStream(filePath);
    doc.pipe(writeStream);

    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const leftMargin = doc.page.margins.left;
    const rightMargin = doc.page.margins.right;
    const usableWidth = pageWidth - leftMargin - rightMargin;
    const signatureHeight = 70;
    const cellFontSize = 8;
    let regColWidth = 80;
    const otherColsCount = allSubjects.length + 2; // subjects + TOTAL + PERCENT
    const minColWidth = 45;
    let remainingWidth = usableWidth - regColWidth;
    let colWidth = Math.floor(remainingWidth / otherColsCount);
    if (colWidth < minColWidth) {
      colWidth = minColWidth;
      const totalNeeded = regColWidth + (colWidth * otherColsCount);
      if (totalNeeded > usableWidth) {
        regColWidth = Math.max(50, regColWidth - (totalNeeded - usableWidth));
      }
    }

    function renderPageHeader(headerText = "STATEMENT OF ATTENDANCE REPORT", totalsSourceStudent = null) {
      const logoPath = path.join(__dirname, "public", "crrengglogo.png");
      const topY = doc.page.margins.top;
      try {
        if (fs.existsSync(logoPath)) doc.image(logoPath, leftMargin, topY, { width: 50 });
      } catch (e) {}
      const titleX = leftMargin + 60;
      const titleW = usableWidth - 60;
      doc.fontSize(14).font("Helvetica-Bold").text("SIR C.R.REDDY COLLEGE OF ENGINEERING (Autonomous)", titleX, topY - 2, { width: titleW, align: "center" });
      doc.moveDown(0.2);
      doc.fontSize(10).font("Helvetica").text(`B.Tech Year - ${year}   Sem - ${semester}   Branch - ${course}   Section - ${section}`, { align: "center" });
      doc.fontSize(10).text(headerText, { align: "center" });
      doc.fontSize(8).text("Vatluru, Eluru - 534007, Eluru Dist. A.P.", { align: "center" });
      doc.fontSize(8).text(`From: ${from_date}  To: ${to_date}`, { align: "center" });
      doc.moveDown(0.5);

      let y = doc.y + 6;
      doc.moveTo(leftMargin, y).lineTo(pageWidth - rightMargin, y).stroke();
      y += 6;

      const headers = ["Regd.No", ...allSubjects, "TOTAL", "PERCENT"];
      let x = leftMargin;
      doc.fontSize(cellFontSize).font("Helvetica-Bold");
      headers.forEach((h, i) => {
        const w = (i === 0) ? regColWidth : colWidth;
        doc.save();
        doc.rect(x, y, w, 20).fillAndStroke("#007acc", "black");
        doc.fillColor("white").text(h.length > 18 ? h.substring(0, 18) + "..." : h, x + 3, y + 4, { width: w - 6, align: "center" });
        doc.restore();
        x += w;
      });
      y += 20;

      // Total Classes Row
      x = leftMargin;
      doc.fontSize(cellFontSize).font("Helvetica-Bold").fillColor("black");
      doc.rect(x, y, regColWidth, 20).stroke();
      doc.text("Total Classes", x + 3, y + 4, { width: regColWidth - 6, align: "center" });
      x += regColWidth;

      let totalClassesSum = 0;
      allSubjects.forEach(sub => {
        const totalForSubject = totalsSourceStudent ? (totalsSourceStudent.subjectTotals[sub] || 0) : 0;
        totalClassesSum += totalForSubject;
        doc.rect(x, y, colWidth, 20).stroke();
        doc.text(String(totalForSubject), x + 3, y + 4, { width: colWidth - 6, align: "center" });
        x += colWidth;
      });

      // Fill TOTAL column
      doc.rect(x, y, colWidth, 20).stroke();
      doc.text(String(totalClassesSum), x + 3, y + 4, { width: colWidth - 6, align: "center" });
      x += colWidth;

      // PERCENT column empty
      doc.rect(x, y, colWidth, 20).stroke();
      x += colWidth;

      y += 20;
      return y;
    }

    const regulars = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() !== "lateral");
    const laterals = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() === "lateral");

    // REGULAR STUDENTS PAGE
    let y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regulars[0] || null);
    regulars.forEach(std => {
      let possibleClasses = 0;
      allSubjects.forEach(sub => {
        possibleClasses += std.subjectTotals[sub] || 0;
      });
      const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
      const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
      const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

      const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
      if (y + 20 > bottomLimit) {
        doc.addPage();
        y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regulars[0] || null);
      }

      let x = leftMargin;
      rowCells.forEach((cell, i) => {
        const w = (i === 0) ? regColWidth : colWidth;
        if (i === rowCells.length - 1) {
          const p = parseFloat(cell) || 0;
          doc.fillColor(p < 75 ? "red" : "black");
        } else {
          doc.fillColor("black");
        }
        doc.rect(x, y, w, 20).stroke();
        doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
        x += w;
      });
      y += 20;
    });

    // LATERAL STUDENTS PAGE
    if (laterals.length > 0) {
      doc.addPage();
      y = renderPageHeader("Lateral Entry Students", laterals[0] || null);

      laterals.forEach(std => {
        let possibleClasses = 0;
        allSubjects.forEach(sub => {
          possibleClasses += std.subjectTotals[sub] || 0;
        });
        const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
        const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
        const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

        const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
        if (y + 20 > bottomLimit) {
          doc.addPage();
          y = renderPageHeader("Lateral Entry Students", laterals[0] || null);
        }

        let x = leftMargin;
        rowCells.forEach((cell, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          if (i === rowCells.length - 1) {
            const p = parseFloat(cell) || 0;
            doc.fillColor(p < 75 ? "red" : "black");
          } else {
            doc.fillColor("black");
          }
          doc.rect(x, y, w, 20).stroke();
          doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
          x += w;
        });
        y += 20;
      });
    }

    // SIGNATURES
    let lastY = doc.y || doc.page.margins.top;
    const minSpaceBelow = 80;
    const spaceBelow = pageHeight - doc.page.margins.bottom - lastY;
    if (spaceBelow < minSpaceBelow) {
      doc.addPage();
      lastY = doc.page.margins.top;
    }
    const signatureY = lastY + 40;
    doc.fontSize(10).fillColor("black");
    doc.text("Faculty Signature", leftMargin + 10, signatureY);
    doc.text("HOD Signature", pageWidth - rightMargin - 160, signatureY);

    doc.end();

    writeStream.on("finish", () => {
      res.download(filePath, fileName, err => {
        if (err) {
          console.error("Download error:", err);
          return res.status(500).json({ error: "File download error" });
        }
        fs.unlink(filePath, () => {});
      });
    });

    writeStream.on("error", err => {
      console.error("PDF write error:", err);
      return res.status(500).json({ error: "PDF write error" });
    });
  });
});



// 1) Get courses & sections for dept + year
app.get("/api/fetch-courses-sections", (req, res) => {
  const { dept_code, year } = req.query;
  if (!dept_code || !year) return res.status(400).json({ error: "Missing" });

  const query = `
    SELECT DISTINCT course, section
    FROM students
    WHERE dept_code = ? AND year = ?
    ORDER BY course, section
  `;
  connection.query(query, [dept_code, year], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    // return as array of { course, section }
    res.json(rows);
  });
});
// 2) Get absent students for a specific course/section/date
app.get("/api/get-absents", (req, res) => {
  const { year, course, section, date, semester } = req.query;
  if (!year || !course || !section || !date) return res.status(400).json({ error: "Missing" });

  const q = `
    SELECT a.id, a.reg_no, s.name, a.status, a.subject, a.date, a.semester
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? AND a.course = ? AND a.section = ? AND a.date = ?
      AND a.status = 'Absent'
    ORDER BY s.reg_no
  `;
  connection.query(q, [year, course, section, date], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows); // each row has attendance id (a.id) — important for updates
  });
});

// 3) Mark a student present (idempotent, atomic)
app.post("/api/mark-present", (req, res) => {
  const { attendance_id } = req.body;
  if (!attendance_id) return res.status(400).json({ error: "Missing attendance_id" });

  // make it safe: check current status, update only if Absent
  connection.beginTransaction(err => {
    if (err) return res.status(500).json({ error: "DB error" });

    const checkQ = `SELECT status FROM daily_attendance WHERE id = ? FOR UPDATE`;
    connection.query(checkQ, [attendance_id], (err, rows) => {
      if (err) return connection.rollback(() => res.status(500).json({ error: "DB error" }));
      if (!rows.length) return connection.rollback(() => res.status(404).json({ error: "Not found" }));
      if (rows[0].status === "Present") {
        return connection.rollback(() => res.json({ ok: true, updated: false, status: "already present" }));
      }

      const updQ = `UPDATE daily_attendance SET status = 'Present' WHERE id = ?`;
      connection.query(updQ, [attendance_id], (err, result) => {
        if (err) return connection.rollback(() => res.status(500).json({ error: "DB error" }));
        connection.commit(err => {
          if (err) return connection.rollback(() => res.status(500).json({ error: "DB error" }));
          res.json({ ok: true, updated: true });
        });
      });
    });
  });
});




// Route to insert/update full week staff allocation
app.post("/api/set-staff-allocation", (req, res) => {
  const { staff_id, year, course, semester, section, allocations } = req.body;

  if (!staff_id || !year || !course || !semester || !section || !allocations) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const queries = [];

  days.forEach((day) => {
    const dayAlloc = allocations[day];
    if (!dayAlloc) return; // Skip if no allocation for that day

    const { period1, period2, period3, period4, period5, period6, period7 } = dayAlloc;

    const sql = `
      INSERT INTO staff_period_allocation (
        staff_id, year, course, semester, section, day,
        period1, period2, period3, period4, period5, period6, period7
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        period1 = VALUES(period1),
        period2 = VALUES(period2),
        period3 = VALUES(period3),
        period4 = VALUES(period4),
        period5 = VALUES(period5),
        period6 = VALUES(period6),
        period7 = VALUES(period7)
    `;

    const values = [
      staff_id,
      year,
      course,
      semester,
      section,
      day,
      period1,
      period2,
      period3,
      period4,
      period5,
      period6,
      period7,
    ];

    queries.push({ sql, values });
  });

  let completed = 0;
  let hasError = false;

  queries.forEach(({ sql, values }) => {
    connection.query(sql, values, (err) => {
      if (err) {
        console.error("❌ Error inserting/updating allocation:", err);
        hasError = true;
      }

      completed++;
      if (completed === queries.length) {
        if (hasError) {
          return res.status(500).json({ error: "Some allocations failed" });
        } else {
          return res.json({ success: true, message: "All allocations saved successfully" });
        }
      }
    });
  });
});
// allocate time table and class work starting
app.post("/api/allocate/multi", (req, res) => {
  const { allocations } = req.body;

  console.log("Received Allocations:", allocations);

  if (!Array.isArray(allocations) || allocations.length === 0) {
    return res.status(400).json({ error: "Invalid or empty allocation data" });
  }

  const sql = `
    INSERT INTO staff_period_allocation (
      staff_id, year, course, dept_code, section, day,
      period1, period2, period3, period4, period5, period6, period7, semester
    ) VALUES ?
  `;

  const values = allocations.map((row) => [
    row.staff_id,
    row.year,
    row.course,
    row.dept_code,
    row.section,
    row.day,
    row.period1,
    row.period2,
    row.period3,
    row.period4,
    row.period5,
    row.period6,
    row.period7,
    row.semester,
  ]);

  // ✅ Extract joining date logic
  const first = allocations[0];
  let dateQueries = [];
  let dateValuesList = [];

  if (first.year === "2") {
    if (first.commence_regular) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ? AND (admission_type IS NULL OR admission_type != 'Lateral')
      `);
      dateValuesList.push([
        first.commence_regular,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }

    if (first.commence_lateral) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ? AND admission_type = 'Lateral'
      `);
      dateValuesList.push([
        first.commence_lateral,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }
  } else if (["1", "3", "4"].includes(first.year)) {
    if (first.commence_common) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ?
      `);
      dateValuesList.push([
        first.commence_common,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }
  }

  // ✅ Insert staff_period_allocation rows
  connection.query(sql, [values], async (err, result) => {
    if (err) {
      console.error("❌ Error inserting multiple allocations:", err);
      return res.status(500).json({ error: "Failed to insert allocations" });
    }

    // ✅ Execute joining_date updates one by one
    try {
      for (let i = 0; i < dateQueries.length; i++) {
        const q = dateQueries[i];
        const values = dateValuesList[i];
        await new Promise((resolve, reject) => {
          connection.query(q, values, (err2, result2) => {
            if (err2) reject(err2);
            else resolve(result2);
          });
        });
      }

      console.log("✅ Allocations and joining dates updated successfully");
      return res.json({ success: true, message: "Allocations and joining dates inserted successfully" });

    } catch (err) {
      console.error("❌ Failed to update joining date:", err);
      return res.status(500).json({ error: "Joining date update failed" });
    }
  });
});

//students getting for sms
app.post('/api/get-students-for-sms', (req, res) => {
  const { dept_code, year, course, section, reg_from, reg_to } = req.body;
  let sql = `SELECT reg_no, name, father_mobile FROM students WHERE 1=1`;
  const params = [];

  if (dept_code) { sql += ` AND dept_code = ?`; params.push(dept_code); }
  if (year) { sql += ` AND year = ?`; params.push(year); }
  if (course) { sql += ` AND course = ?`; params.push(course); }
  if (section) { sql += ` AND section = ?`; params.push(section); }
  if (reg_from && reg_to) { sql += ` AND reg_no BETWEEN ? AND ?`; params.push(reg_from, reg_to); }

  connection.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
    res.json({ success: true, data: rows });
  });
});

//send sms
const SMS_USERNAME = process.env.SMS_PROVIDER_USERNAME;
const SMS_APIKEY = process.env.SMS_PROVIDER_APIKEY;

const TEMPLATE_ID_MAP = {
  attendance: "1207175447438252519",
  midmarks: "1207175447366458267",
  university_eng: "1207175447825658891",
  university_telugu: "1207175447660496054"
};

const TEMPLATE_TEXT = {
  attendance: `ప్రియమైన తల్లిదండ్రులకు, మీ కుమారుడు/కుమార్తె {#var#} (Reg.No: {#var#}) యొక్క {#var#} సెమిస్టర్ హాజరు శాతం: {#var#}%
దయచేసి మీ పిల్లల నిరంతర హాజరును ఖచ్చితంగా నిర్ధారించండి.
SIR RAMALINGA REDDY COLLEGE`,
  midmarks: `Dear Parent, Mid marks of Your Ward {#var#} bearing regno {#var#} for sem {#var#} midmarks: {#var#}
SIR RAMALINGA REDDY COLLEGE`,
  university_eng: `Dear Parent, Your Ward {#var#} bearing regno:{#var#} has Results of Semester {#var#} of Year {#var#}.
Subjects & Grades: {#var#} SGPA: {#var#}
SIR RAMALINGA REDDY COLLEGE`,
  university_telugu: `ప్రియమైన తల్లిదండ్రులకు, మీ కుమారుడు/కుమార్తె {#var#} (Reg.No: {#var#}) కు {#var#} సంవత్సరం {#var#} సెమిస్టర్ ఫలితాలు విడుదలయ్యాయి.
విషయాలు & గ్రేడ్‌లు: {#var#} SGPA: {#var#}
SIR RAMALINGA REDDY COLLEGE`
};

function formatMessage(templateKey, data) {
  let msg = TEMPLATE_TEXT[templateKey];
  const replacements = [];

  if (templateKey === "attendance") {
    replacements.push(data.name, data.reg_no, data.semester, data.percentage);
  } else if (templateKey === "midmarks") {
    replacements.push(data.name, data.reg_no, data.semester, data.total_marks);
  } else if (templateKey === "university_eng") {
   replacements.push(data.name, data.reg_no, data.semester, data.year, data.result_link, data.sgpa);
  } else if (templateKey === "university_telugu") {
    replacements.push(data.name, data.reg_no, data.year, data.semester, data.result_link, data.sgpa);
  }

  replacements.forEach(rep => {
    msg = msg.replace("{#var#}", rep ?? "");
  });

  return msg;
}

app.post("/api/send-sms", async (req, res) => {
  try {
    const { reg_nos, senderId, template } = req.body;

    if (!reg_nos?.length) {
      return res.status(400).json({ success: false, message: "No students selected" });
    }
    if (!TEMPLATE_ID_MAP[template]) {
      return res.status(400).json({ success: false, message: "Invalid template type" });
    }

    let sql;
    if (template === "attendance") {
      sql = `SELECT s.name, s.reg_no, a.semester, a.percentage, s.father_mobile
             FROM students s
             JOIN attendance a ON a.regno = s.reg_no
             WHERE s.reg_no IN (?)`;
   } else if (template === "midmarks") {
  sql = `SELECT s.name, s.reg_no, m.semester,
            (CAST(m.mid1 AS DECIMAL) + CAST(m.a1 AS DECIMAL) + CAST(m.q1 AS DECIMAL) +
             CAST(m.mid2 AS DECIMAL) + CAST(m.a2 AS DECIMAL) + CAST(m.q2 AS DECIMAL)) AS total_marks,
            s.father_mobile
         FROM students s
         JOIN railway.mid_internal_marks m ON m.hallticket = s.reg_no
         WHERE s.reg_no IN (?)`;
} else if (template === "university_eng" || template === "university_telugu") {
  sql = `SELECT 
           ANY_VALUE(s.name) AS name,
           s.reg_no,
           ANY_VALUE(s.year) AS year,
           r.semester,
           GROUP_CONCAT(CONCAT(r.subname, ' - ', r.grade) SEPARATOR ', ') AS subjects_grades,
           ANY_VALUE(r.sgpa) AS sgpa,
           ANY_VALUE(s.father_mobile) AS father_mobile
         FROM students s
         LEFT JOIN (
           SELECT regno, semester, subname, grade, sgpa FROM autonomous_results
           UNION ALL
           SELECT regno, semester, subname, grade, sgpa FROM results
         ) r ON r.regno = s.reg_no
         WHERE s.reg_no IN (?)
         GROUP BY s.reg_no, r.semester`;
}

    
    const rows = await new Promise((resolve, reject) => {
      connection.query(sql, [reg_nos], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    if (!rows.length) {
      return res.status(404).json({ success: false, message: "No data found for selected students" });
    }

    // Send SMS for each student
    const sendResults = [];
    for (const s of rows) {
      const cleanMobile = (s.father_mobile || "").replace(/\D/g, "").slice(-10);
      if (!cleanMobile) continue;

      const dataObj =
        template === "attendance"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, percentage: s.percentage }
          : template === "midmarks"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, total_marks: s.total_marks }
          : template === "university_eng"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, year: s.year, result_link: `https://crr-noc.onrender.com/verifyresult.html?regno=${s.reg_no}&sem=${s.semester}`, sgpa: s.sgpa }
          : { name: s.name, reg_no: s.reg_no, year: s.year, semester: s.semester, result_link: `https://crr-noc.onrender.com/verifyresult.html?regno=${s.reg_no}&sem=${s.semester}`, sgpa: s.sgpa };

      const message = encodeURIComponent(formatMessage(template, dataObj));

      const url = `https://smslogin.co/v3/api.php?username=${SMS_USERNAME}&apikey=${SMS_APIKEY}&senderid=${senderId}&mobile=${cleanMobile}&message=${message}&templateid=${TEMPLATE_ID_MAP[template]}`;

      try {
        const apiResp = await axios.get(url, { timeout: 20000 });
        sendResults.push({ reg_no: s.reg_no, mobile: cleanMobile, status: apiResp.data });
      } catch (error) {
        sendResults.push({ reg_no: s.reg_no, mobile: cleanMobile, error: error.message });
      }
    }

    res.json({ success: true, results: sendResults });
  } catch (err) {
    console.error("Error in /api/send-sms:", err);
    res.status(500).json({ success: false, message: "Internal server error", error: err.message });
  }
});

module.exports = app;

app.post("/api/adjust-period", (req, res) => {
  const {
    from_staff_id, to_staff_id, course, year,
    section, semester, day, date, period_no, subject
  } = req.body;

  // 1️⃣ Check if Staff B is free at that time
  const checkSql = `
    SELECT 
      CASE ? 
        WHEN 1 THEN period1 
        WHEN 2 THEN period2 
        WHEN 3 THEN period3 
        WHEN 4 THEN period4 
        WHEN 5 THEN period5 
        WHEN 6 THEN period6 
        WHEN 7 THEN period7 
      END AS subject
    FROM staff_period_allocation
    WHERE staff_id=? AND day=? AND course=? AND year=? AND semester=? AND section=?
    LIMIT 1
  `;

  connection.query(
    checkSql,
    [period_no, to_staff_id, day, course, year, semester, section],
    (err, result) => {
      if (err) return res.status(500).json({ error: "DB error" });

      // Staff B is busy → Reject adjustment
      if (result.length && result[0].subject) {
        return res.status(400).json({
          error: "❌ Staff already has a class in this period."
        });
      }

      // 2️⃣ Insert adjustment record
      const insertSql = `
        INSERT INTO staff_period_adjustments
        (from_staff_id, to_staff_id, course, year, section, semester, day, date, period_no, subject)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      connection.query(
        insertSql,
        [from_staff_id, to_staff_id, course, year, section, semester, day, date, period_no, subject],
        (insertErr) => {
          if (insertErr) return res.status(500).json({ error: "Insert failed" });
          res.json({ success: true, message: "✅ Adjustment successful." });
        }
      );
    }
  );
});


// 🔹 Get Staff List in Section
app.get("/api/staff-in-section", (req, res) => {
  const { course, year, semester, section } = req.query;
  const sql = `
    SELECT DISTINCT s.staff_id, s.staff_name
    FROM staff_period_allocation spa
    JOIN staff s ON s.staff_id = spa.staff_id
    WHERE spa.course=? AND spa.year=? AND spa.semester=? AND spa.section=?;
  `;
  connection.query(sql, [course, year, semester, section], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get("/api/staff-subjects", (req, res) => {
  const { staff_id, course, year, semester, section } = req.query;

  if (!staff_id || !course || !year || !semester || !section) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const sql = `
    SELECT DISTINCT 
      period1 AS subject FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period1 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period2 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period2 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period3 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period3 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period4 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period4 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period5 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period5 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period6 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period6 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period7 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period7 IS NOT NULL
  `;

  const params = [
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section
  ];

  connection.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});
















