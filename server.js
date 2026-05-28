
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

const db = new sqlite3.Database("./database.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    whatsapp TEXT,
    password TEXT
)
`);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: "albahrawi-secret",
    resave: false,
    saveUninitialized: true
}));

app.post("/signup", async (req, res) => {
    const username = req.body["RegistrationForm[login]"];
    const email = req.body["RegistrationForm[email]"];
    const whatsapp = req.body["RegistrationForm[whatsapp]"];
    const password = req.body["RegistrationForm[password]"];
    const passwordAgain = req.body["RegistrationForm[password_again]"];

    if (password !== passwordAgain) {
        return res.send("كلمتا المرور غير متطابقتين");
    }

    const hashed = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, email, whatsapp, password) VALUES (?, ?, ?, ?)",
        [username, email, whatsapp, hashed],
        function(err) {
            if (err) {
                return res.send("اسم المستخدم مستخدم بالفعل");
            }

            res.redirect("/index.html");
        }
    );
});

app.post("/login", (req, res) => {
    const username = req.body["LoginForm[username]"];
    const password = req.body["LoginForm[password]"];

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err || !user) {
                return res.send("الحساب غير موجود");
            }

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.send("كلمة المرور غلط");
            }

            req.session.user = user.username;

            res.send(`
                <html dir="rtl">
                <head>
                    <title>تم تسجيل الدخول</title>
                    <style>
                        body{
                            font-family: Arial;
                            background:#111827;
                            color:white;
                            display:flex;
                            justify-content:center;
                            align-items:center;
                            height:100vh;
                        }
                        .box{
                            background:#1f2937;
                            padding:40px;
                            border-radius:20px;
                            text-align:center;
                        }
                    </style>
                </head>
                <body>
                    <div class="box">
                        <h1>اهلا ${user.username}</h1>
                        <p>تم تسجيل الدخول بنجاح ✅</p>
                        <a href="/services.html" style="color:#60a5fa;">الدخول للخدمات</a>
                    </div>
                </body>
                </html>
            `);
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
