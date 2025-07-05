// === Imports and Setup ===
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const csurf = require("csurf");
const { body, validationResult } = require("express-validator");
const winston = require("winston");
const { Resend } = require("resend");
const { PrismaClient, UserType } = require("@prisma/client");
const crypto = require("crypto");
const assistantRoutes = require("./routes/assistant.routes");
const voiceaiAssistantRoute = require("./routes/voiceai");
const knowledgeBaseRoute = require("./routes/knowledgebase.routes");
const voiceAIProxyRoute = require("./routes/voiceAIProxyRoute");
require("dotenv").config();

const prisma = new PrismaClient();
const app = express();
app.set("trust proxy", 1); // Trust first proxy

// === Logger Setup ===
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "audit.log" }),
    new winston.transports.Console(),
  ],
});

const auditLog = (email, action) => {
  logger.info({ email, action, timestamp: new Date().toISOString() });
};

// === Middleware Setup ===
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:8080",
  "https://voice.cognitiev.com",
  "https://youragency2.netlify.app",
  "https://propai.cognitiev.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// Force HTTPS in production
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// === CSRF Setup ===
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  },
  value: (req) => {
    // Try to read token from header (recommended for APIs)
    return req.headers["x-csrf-token"] || req.body._csrf || req.query._csrf;
  },
});

app.use(csrfProtection);

// === Rate Limiting ===
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many OTP attempts, please try again later.",
});

const resend = new Resend(process.env.RESEND_API_KEY);

const sendOtpEmail = async (email, otp) => {
  try {
    await resend.emails.send({
      from: "Your Agency <no-reply@mail.cognitiev.com>", // ✅ matches verified domain
      to: email,
      subject: "Your OTP Code",
      html: `<p>Your OTP code is: <strong>${otp}</strong>. It will expire in 5 minutes.</p>`,
    });
    logger.info(`OTP sent to ${email}`);
  } catch (error) {
    logger.error("Error sending OTP email:", error);
    console.error("Full error:", JSON.stringify(error, null, 2)); // Add this for debugging
  }
};

const isPasswordStrong = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(
    password
  );

const generateAccessToken = (email, type) =>
  jwt.sign({ email, type }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "2h",
  });

const generateRefreshToken = (email, type) =>
  jwt.sign({ email, type }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

const generateVerificationToken = () => crypto.randomBytes(32).toString("hex");

const failedOtpAttempts = {};
const MAX_OTP_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

// === Routes ===
//health check
app.get("/", (req, res) => {
  res.status(200).json({ message: "Backend is up and running 🚀" });
});

// Registration
app.post(
  "/auth/register",
  body("email").isEmail().normalizeEmail(),
  body("password").isString(),
  body("fullName")
    .isString()
    .isLength({ min: 3 })
    .withMessage("Full name must be at least 3 characters long"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, password, fullName } = req.body;

    if (!isPasswordStrong(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters, include uppercase, lowercase, number, and special character.",
      });
    }

    try {
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      await prisma.user.create({
        data: {
          email,
          passwordHash,
          fullName,
          type: UserType.NORMAL,
          consentGivenAt: new Date(),
        },
      });

      auditLog(email, "Registered");
      res.status(201).json({
        message: "Registered successfully",
        csrfToken: req.csrfToken(),
      });
    } catch (error) {
      logger.error("Register error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Login - Stage 1
app.post(
  "/auth/login",
  body("email").isEmail().normalizeEmail(),
  body("password").isString(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(404).json({ message: "User not found" });

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match)
        return res.status(401).json({ message: "Invalid credentials" });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpHash = await bcrypt.hash(otp, 10);
      const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
      logger.info(
        `Updating OTP for user: ${email} with hash: ${otpHash} expiry: ${otpExpiry}`
      );

      try {
        await prisma.user.update({
          where: { email },
          data: { otpHash, otpExpiry },
        });
        logger.info(`OTP saved successfully for ${email}`);
      } catch (error) {
        logger.error(`Failed to save OTP for ${email}: ${error}`);
      }

      await sendOtpEmail(email, otp);
      auditLog(email, "OTP sent");

      res.status(200).json({ message: "OTP sent", csrfToken: req.csrfToken() });
    } catch (error) {
      logger.error("Login error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Login - Stage 2 (Verify OTP)
app.post(
  "/auth/verify-otp",
  otpLimiter,
  body("email").isEmail().normalizeEmail(),
  body("otp").isLength({ min: 6, max: 6 }).isNumeric(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, otp } = req.body;

    const attemptData = failedOtpAttempts[email];
    if (
      attemptData &&
      attemptData.count >= MAX_OTP_ATTEMPTS &&
      Date.now() - attemptData.lastAttemptTime < LOCKOUT_DURATION
    ) {
      return res.status(429).json({
        message:
          "Account locked due to multiple failed OTP attempts. Try after some time.",
      });
    }

    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user || !user.otpHash)
        return res.status(401).json({ message: "OTP not generated" });

      if (new Date() > user.otpExpiry) {
        await prisma.user.update({
          where: { email },
          data: { otpHash: null, otpExpiry: null },
        });
        return res.status(401).json({ message: "OTP expired" });
      }

      const validOtp = await bcrypt.compare(otp, user.otpHash);
      if (!validOtp) {
        if (!failedOtpAttempts[email]) {
          failedOtpAttempts[email] = { count: 1, lastAttemptTime: Date.now() };
        } else {
          failedOtpAttempts[email].count++;
          failedOtpAttempts[email].lastAttemptTime = Date.now();
        }
        return res.status(401).json({ message: "Invalid OTP" });
      }

      delete failedOtpAttempts[email];

      const accessToken = generateAccessToken(user.email, user.type);
      const refreshToken = generateRefreshToken(user.email, user.type);

      await prisma.refreshToken.create({
        data: {
          token: refreshToken,
          userId: user.id,
        },
      });

      await prisma.user.update({
        where: { email },
        data: { otpHash: null, otpExpiry: null },
      });

      auditLog(email, "Logged in");

      res
        .cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          maxAge: 2 * 60 * 60 * 1000,
        })
        .cookie("refreshToken", refreshToken, {
          httpOnly: true,
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          secure: process.env.NODE_ENV === "production",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        .json({
          message: "Logged in successfully",
          csrfToken: req.csrfToken(),
        });
    } catch (error) {
      logger.error("Verify OTP error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Refresh Access Token
app.post("/auth/refresh-token", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const dbToken = await prisma.refreshToken.findUnique({ where: { token } });
    if (!dbToken) {
      await prisma.refreshToken.deleteMany({
        where: { userId: decoded.userId },
      });
      return res.sendStatus(403);
    }

    const user = await prisma.user.findUnique({
      where: { email: decoded.email },
    });
    if (!user) return res.sendStatus(403);

    const accessToken = generateAccessToken(user.email, user.type);
    auditLog(user.email, "Token refreshed");

    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 2 * 60 * 60 * 1000,
      })
      .json({ message: "Token refreshed" });
  } catch (error) {
    logger.error("Refresh token error:", error);
    res.sendStatus(403);
  }
});

// Logout
app.post("/auth/logout", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(200).json({ message: "Logged out" });

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    auditLog(decoded.email, "Logged out");

    await prisma.refreshToken.deleteMany({ where: { token } });

    res
      .clearCookie("accessToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      })
      .clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      })
      .status(200)
      .json({ message: "Logged out" });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// User Info
app.get("/auth/me", (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Not logged in" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    res.json({ email: decoded.email, type: decoded.type });
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
});

// Helper to generate a secure random token for password reset
const generateResetToken = () => crypto.randomBytes(32).toString("hex");

// Send password reset email
const sendResetPasswordEmail = async (email, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
  try {
    await resend.emails.send({
      from: "Your Agency <onboarding@resend.dev>",
      to: email,
      subject: "Password Reset Request",
      html: `<p>You requested a password reset. Click the link below to reset your password (valid for 1 hour):</p>
             <a href="${resetUrl}">${resetUrl}</a>
             <p>If you didn't request this, please ignore this email.</p>`,
    });
    logger.info(`Password reset email sent to ${email}`);
  } catch (error) {
    logger.error("Error sending password reset email:", error);
  }
};

// --- Forgot Password Request ---
app.post(
  "/auth/forgot-password",
  body("email").isEmail().normalizeEmail(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email } = req.body;
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        // To avoid user enumeration, respond with 200 anyway
        return res.status(200).json({
          message:
            "If an account with that email exists, a reset link has been sent.",
        });
      }

      // Generate token and expiry (1 hour)
      const token = generateResetToken();
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

      // Save token in PasswordResetToken table (replace any previous token for this user)
      await prisma.passwordResetToken.upsert({
        where: { userId: user.id },
        update: { token, expiresAt },
        create: { token, userId: user.id, expiresAt },
      });

      await sendResetPasswordEmail(email, token);
      auditLog(email, "Requested password reset");

      res.status(200).json({
        message:
          "If an account with that email exists, a reset link has been sent.",
      });
    } catch (error) {
      logger.error("Forgot password error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// --- Reset Password ---
app.post(
  "/auth/reset-password",
  body("email").isEmail().normalizeEmail(),
  body("token").isString(),
  body("newPassword").isString(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, token, newPassword } = req.body;

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters, include uppercase, lowercase, number, and special character.",
      });
    }

    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user)
        return res.status(404).json({ message: "Invalid token or email" });

      const resetRecord = await prisma.passwordResetToken.findUnique({
        where: { userId: user.id },
      });
      if (!resetRecord || resetRecord.token !== token) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }

      if (new Date() > resetRecord.expiresAt) {
        await prisma.passwordResetToken.delete({ where: { userId: user.id } });
        return res.status(400).json({ message: "Token expired" });
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      // Update password & delete reset token
      await prisma.user.update({
        where: { email },
        data: { passwordHash },
      });

      await prisma.passwordResetToken.delete({ where: { userId: user.id } });

      // Optional: Delete all refresh tokens to force logout everywhere
      await prisma.refreshToken.deleteMany({ where: { userId: user.id } });

      auditLog(email, "Password reset successful");

      res.status(200).json({ message: "Password has been reset successfully" });
    } catch (error) {
      logger.error("Reset password error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Delete User (Right to Erasure)
app.post("/auth/delete", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "User not found" });

    await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await prisma.user.delete({ where: { email } });

    auditLog(email, "User data deleted");

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(200).json({ message: "User data deleted" });
  } catch (error) {
    logger.error("Delete user error:", error);
    res.status(500).json({ message: "Server error" });
  }
});
app.get("/auth/profile", async (req, res) => {
  console.log("accessToken:", req.cookies.accessToken);
  const token = req.cookies.accessToken;
  console.log(token);
  if (!token) return res.status(401).json({ message: "Not logged in" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    console.log("decoded : " + decoded.email);
    const user = await prisma.user.findUnique({
      where: { email: decoded.email },
      select: { email: true, fullName: true, type: true },
    });
    console.log(user);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.status(200).json(user);
  } catch (error) {
    console.log(error);
    res.status(403).json({ message: "Invalid token" });
  }
});
app.put(
  "/auth/profile",
  body("fullName").optional().isString().isLength({ min: 3 }),
  body("type").optional().isIn(["NORMAL", "ADMIN"]), // validate only accepted types
  async (req, res) => {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ message: "Not logged in" });

    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      const { fullName, type } = req.body;

      const updateData = {};
      if (fullName) updateData.fullName = fullName;
      if (type) updateData.type = type;

      const updatedUser = await prisma.user.update({
        where: { email: decoded.email },
        data: updateData,
        select: { email: true, fullName: true, type: true },
      });

      auditLog(decoded.email, "Updated profile");
      res.status(200).json({ message: "Profile updated", user: updatedUser });
    } catch (error) {
      logger.error("Update profile error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// CSRF Token Endpoint
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Privacy Policy URL (GDPR)
app.get("/privacy-policy", (req, res) => {
  res.json({ url: "https://yourdomain.com/privacy-policy" });
});

// === Update Vapi Agent ===
app.patch("/api/vapi/agent/:id", async (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Not logged in" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const {
      agentName,
      prompt,
      voiceSpeed,
      firstMessage,
      recordingEnabled,
      callForwardingNumber,
    } = req.body;

    const vapiResponse = await axios.patch(
      `https://api.vapi.ai/assistant/${req.params.id}`,
      {
        name: agentName,
        model: {
          messages: [{ role: "system", content: prompt }],
        },
        voice: {
          speed: parseFloat(voiceSpeed),
        },
        firstMessage,
        recordingOptions: {
          enabled: recordingEnabled,
        },
        callForwarding: {
          number: callForwardingNumber,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
        },
      }
    );

    auditLog(decoded.email, `Updated Vapi agent ${req.params.id}`);
    res
      .status(200)
      .json({ message: "Agent updated successfully", data: vapiResponse.data });
  } catch (error) {
    logger.error("Vapi agent update failed:", error);
    res.status(500).json({ message: "Failed to update Vapi agent" });
  }
});

app.use("/api/assistants", assistantRoutes);
app.use("/voiceai", voiceaiAssistantRoute);
app.use("/api/knowledge-base", knowledgeBaseRoute);

app.use("/api/voiceai", voiceAIProxyRoute);

// Start Server
const PORT = process.env.PORT || 8787;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// app.listen(5000, () => logger.info("Auth server running on http://localhost:5000"));
