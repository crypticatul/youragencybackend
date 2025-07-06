import { Hono } from "hono";
import { neon } from "@neondatabase/serverless";
import { cors } from "hono/cors";
import * as jose from "jose";
import * as bcrypt from "bcryptjs";
import { Resend } from "resend";
import * as cookie from "cookie";
import profileRoutes from "./routes/profileRoutes.js";
const app = new Hono();

// Initialize database connection
const getDB = async (url) => {
  if (!url) {
    console.error("Database URL is not provided");
    throw new Error("Database URL is required");
  }

  try {
    console.log("Creating new database connection");
    const sql = neon(url);

    // Test the connection
    await sql`SELECT 1`;
    console.log("Database connection successful");
    return sql;
  } catch (err) {
    console.error("Database connection failed:", err);
    throw new Error(`Database connection failed: ${err.message}`);
  }
};

// Helper to check if route needs database
const requiresDatabase = (path) => {
  return path !== "/csrf-token" && !path.startsWith("/health");
};

// CSRF token generation
const generateCsrfToken = () => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

// Configure CORS
app.use(
  "*",
  cors({
    origin: (origin) => {
      console.log("Request origin:", origin);
      // Log origin details
      const isLocalhost =
        origin?.includes("localhost") || origin?.includes("127.0.0.1");

      console.log("CORS checking origin:", {
        origin,
        isLocalhost: isLocalhost,
        isDevelopment: process.env.NODE_ENV === "development",
      });

      // In development or localhost, be permissive
      if (!origin || origin.includes("localhost")) {
        console.log("Allowing localhost/development origin:", origin);
        return origin || "*";
      }

      // In production, be strict but include all variations
      const allowedOrigins = [
        "https://yourai.cognitiev.com",
        "http://yourai.cognitiev.com",
        "https://youragencybackend.atul-949.workers.dev",
        "https://cognitiev.com",
      ];
      // Check if origin is allowed or matches *.cognitiev.com
      const isAllowed =
        allowedOrigins.includes(origin) ||
        (origin && origin.endsWith(".cognitiev.com"));
      console.log(`Origin ${origin} allowed: ${isAllowed}`);
      return isAllowed ? origin : false;
    },
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowHeaders: [
      "Content-Type",
      "Authorization",
      "X-CSRF-Token",
      "x-voice-ai-key",
    ],
    credentials: true,
    exposeHeaders: ["Set-Cookie"],
    maxAge: 86400,
  })
);

// Health check endpoint
app.get("/health", async (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// CSRF token endpoint (before database middleware)
app.get("/csrf-token", async (c) => {
  try {
    console.log("Generating CSRF token");
    const csrfToken = generateCsrfToken();
    return c.json(
      { csrfToken },
      200,
      {
        "Cache-Control": "no-store"
      }
    );
  } catch (err) {
    console.error("CSRF token error:", err);
    return c.json({ message: "Error generating CSRF token" }, 500);
  }
});

// Request logging middleware
app.use("*", async (c, next) => {
  try {
    const headers = c.req.headers || new Headers();
    const origin = headers.get("origin") || "";
    const host = headers.get("host") || "";

    console.log("Request:", {
      method: c.req.method,
      path: c.req.path,
      origin,
      host,
      url: c.req.url,
      isCORS: origin !== host,
      headers: Object.fromEntries(headers.entries()),
    });

    const response = await next();
    if (response?.headers) {
      console.log("Response:", {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
      });
    }
    return response;
  } catch (err) {
    console.error("Request error:", err);
    return c.json(
      {
        status: "error",
        message: err.message,
        path: c.req.path,
        timestamp: new Date().toISOString(),
      },
      500
    );
  }
});

// Environment Middleware
app.use("*", async (c, next) => {
  try {
    const env = c.env || {};
    if (!env.DATABASE_URL && requiresDatabase(c.req.path)) {
      throw new Error("Database URL is not configured");
    }
    c.set("env", env);
    await next();
  } catch (err) {
    console.error("Environment error:", {
      error: err.message,
      stack: err.stack,
      path: c.req.path,
    });
    return c.json(
      {
        status: "error",
        message: "Configuration error",
        details:
          process.env.NODE_ENV === "development"
            ? err.message
            : "An unexpected error occurred",
        path: c.req.path,
        timestamp: new Date().toISOString(),
      },
      500
    );
  }
});

// VoiceAI proxy endpoint
app.all("/api/voiceai/*", async (c) => {
  try {
    const env = c.get("env");
    const VAPI_API_KEY = env.VAPI_API_KEY;

    if (!VAPI_API_KEY) {
      console.error("VoiceAI API key not configured");
      return c.json({ message: "VoiceAI API key not configured" }, 500);
    }

    const url = new URL(c.req.url);
    const apiPath = url.pathname.replace(/^\/api\/voiceai\/?/, "");
    const targetUrl = `https://api.vapi.ai/${apiPath}${url.search}`;

    console.log("Proxying request to:", targetUrl);

    const headers = new Headers();
    headers.set("Authorization", `Bearer ${VAPI_API_KEY}`);
    headers.set("Content-Type", "application/json");

    const response = await fetch(targetUrl, {
      method: c.req.method,
      headers: headers,
      body: ["GET", "HEAD"].includes(c.req.method) ? null : await c.req.text(),
    });

    const data = await response.json();
    return c.json(data, response.status);
  } catch (error) {
    console.error("VoiceAI proxy error:", error);
    return c.json(
      {
        message: "Failed to proxy request to VoiceAI",
        details: error.message,
      },
      500
    );
  }
});

// Auth routes
app.post("/auth/signup", async (c) => {
  try {
    const { email, password, fullName } = await c.req.json();

    // Validate required fields
    if (!email || !password || !fullName) {
      return c.json({ message: "All fields are required" }, 400);
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return c.json({ message: "Invalid email format" }, 400);
    }

    // Validate password strength
    if (password.length < 6) {
      return c.json(
        { message: "Password must be at least 6 characters long" },
        400
      );
    }

    const env = c.get("env");
    const sql = await getDB(env.DATABASE_URL);

    // Check if user already exists
    const [existingUser] = await sql`
      SELECT id FROM "User" WHERE email = ${email}
    `;

    if (existingUser) {
      return c.json({ message: "Email already registered" }, 400);
    }

    // Hash password and create user
    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    const [user] = await sql`
      INSERT INTO "User" (email, "passwordHash", "fullName", type)
      VALUES (${email}, ${passwordHash}, ${fullName}, 'NORMAL')
      RETURNING id, email, "fullName"
    `;

    // Generate token
    const secret = new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
    const token = await new jose.SignJWT({ email: user.email, userId: user.id })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("2h")
      .sign(secret);

    const headers = c.req.headers || new Headers();
    const origin = headers.get("origin") || "";
    const host = headers.get("host") || "";
    const isLocalhost =
  origin.includes("localhost") ||
  origin.includes("127.0.0.1") ||
  host.includes("localhost") ||
  host.includes("127.0.0.1") ||
  c.req.url.includes("localhost");

    const cookieOptions = isLocalhost
      ? `accessToken=${token}; Path=/; HttpOnly; SameSite=Lax`
      : `accessToken=${token}; Path=/; Domain=.cognitiev.com; HttpOnly; Secure; SameSite=Lax`;

    const response = c.json({ message: "Signup successful" });
    c.cookie("accessToken", token, {
      path: "/",
      httpOnly: true,
      secure: !isLocalhost,
      sameSite: "Lax",
      domain: isLocalhost ? undefined : ".cognitiev.com",
    });
    return c.json({ message: "Login successful" });
  } catch (err) {
    console.error("Signup error:", err);
    return c.json({ message: "Error creating account" }, 500);
  }
});

app.post("/auth/login", async (c) => {
  try {
    const headers = c.req.headers || new Headers();
    const origin = headers.get("origin") || "";
    const reqHost = headers.get("host") || "";

    // Default to production domain if headers are missing
    const effectiveHost = reqHost || "yourai.cognitiev.com";
    console.log("Login attempt started:", {
      origin,
      host: reqHost,
      effectiveHost,
    });

    // Get database connection
    const env = c.get("env");
    if (!env.DATABASE_URL) {
      throw new Error("Database configuration missing");
    }
    console.log("Getting database connection");
    const sql = await getDB(env.DATABASE_URL);

    // Parse request body
    let email, password;
    try {
      const body = await c.req.json();
      email = body.email;
      password = body.password;
    } catch (err) {
      console.error("Failed to parse request body:", err);
      return c.json({ message: "Invalid request format" }, 400);
    }

    if (!email || !password) {
      console.log("Login failed: Missing credentials");
      return c.json({ message: "Email and password are required" }, 400);
    }

    console.log("Finding user with email:", email);
    const [user] = await sql`
      SELECT id, email, "passwordHash", "fullName"
      FROM "User"
      WHERE email = ${email}
    `;

    if (!user) {
      console.log("Login failed: User not found");
      return c.json({ message: "Invalid credentials. Please try again." }, 401);
    }

    const validPassword = bcrypt.compareSync(password, user.passwordHash);
    if (!validPassword) {
      console.log("Login failed: Invalid password");
      return c.json({ message: "Invalid credentials. Please try again." }, 401);
    }

    // Generate and send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Check for Resend API key
    if (!env.RESEND_API_KEY) {
      throw new Error("Resend API key not configured");
    }

    const resend = new Resend(env.RESEND_API_KEY);
    try {
      const resendData = await resend.emails.send({
        from: "YourAI <no-reply@mail.cognitiev.com>",
        to: [email],
        subject: "Your Login OTP",
        html: `Your OTP for login is: <strong>${otp}</strong>`,
      });

      console.log("OTP email sent successfully:", {
        to: email,
        messageId: resendData.id,
      });
    } catch (error) {
      console.error("Resend API error:", error);
      throw new Error(`Failed to send OTP email: ${error.message}`);
    }

    // Hash OTP and store in User table
    const otpHash = bcrypt.hashSync(otp, 10);
    await sql`
      UPDATE "User"
      SET "otpHash" = ${otpHash},
          "otpExpiry" = NOW() + INTERVAL '5 minutes'
      WHERE email = ${email}
    `;

    return c.json({
      message: "OTP sent successfully",
      email: user.email,
      requiresOTP: true,
    });
  } catch (err) {
    console.error("Login error:", err);
    console.error("Login error details:", {
      error: err.message,
      stack: err.stack,
      url: c.req.url,
      headers: c.req.headers ? Object.fromEntries(c.req.headers.entries()) : {},
    });
    return c.json(
      {
        message: "Server error during login",
        details:
          process.env.NODE_ENV === "development"
            ? err.message
            : "An unexpected error occurred",
      },
      500
    );
  }
});

// Verify OTP endpoint
app.post("/auth/verify-otp", async (c) => {
  try {
    const { email, otp } = await c.req.json();

    if (!email || !otp) {
      return c.json({ message: "Email and OTP are required" }, 400);
    }

    const env = c.get("env");
    const sql = await getDB(env.DATABASE_URL);

    // Get user and verify OTP
    const [user] = await sql`
      SELECT id, email, "fullName", "otpHash", "otpExpiry"
      FROM "User"
      WHERE email = ${email}
      AND "otpExpiry" > NOW()
    `;

    if (!user) {
      return c.json({ message: "OTP has expired" }, 400);
    }

    const validOTP = bcrypt.compareSync(otp, user.otpHash);
    if (!validOTP) {
      return c.json({ message: "Invalid OTP" }, 400);
    }

    // Clear OTP after successful verification
    await sql`
      UPDATE "User"
      SET "otpHash" = NULL,
          "otpExpiry" = NULL
      WHERE email = ${email}
    `;

    // Generate JWT token
    const secret = new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
    const token = await new jose.SignJWT({ email: user.email, userId: user.id })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("2h")
      .sign(secret);

    // Determine if running on localhost
    const headers = c.req.headers || new Headers();
const origin = headers.get("origin") || "";
const host = headers.get("host") || "";

const isLocalhost =
  origin.includes("localhost") ||
  origin.includes("127.0.0.1") ||
  host.includes("localhost") ||
  host.includes("127.0.0.1") ||
  c.req.url.includes("localhost"); // final fallback

console.log("isLocalhost:", isLocalhost);

    const cookieValue =
      `accessToken=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${2 * 60 * 60}` +
      (isLocalhost ? "" : "; Secure; Domain=.cognitiev.com");
    const testCookie =
      `testCookie=hello; Path=/; HttpOnly; SameSite=Lax; Max-Age=${2 * 60 * 60}` +
      (isLocalhost ? "" : "; Secure; Domain=.cognitiev.com");
    // Set cookies in response header
    c.header("Set-Cookie", [cookieValue, testCookie]); // ✅ Correct way
    console.log("Logout request received. Clearing accessToken cookie.");
    console.log(c);
    // Return JSON response via Hono
    console.log;
    return c.json({ message: "Logged in" }, 200);
  } catch (err) {
    console.error("OTP verification error:", err);
    return c.json({ message: "Error verifying OTP" }, 500);
  }
});

app.post("/auth/logout", async (c) => {
  const headers = c.req.headers || new Headers();
  const origin = headers.get("origin") || "";
  const host = headers.get("host") || "";
  const isLocalhost =
  origin.includes("localhost") ||
  origin.includes("127.0.0.1") ||
  host.includes("localhost") ||
  host.includes("127.0.0.1") ||
  c.req.url.includes("localhost"); // final fallback


  const cookieString = isLocalhost
    ? `accessToken=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
    : `accessToken=; Path=/; Domain=.cognitiev.com; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

  const response = c.json({ message: "Logged out successfully" });

  response.headers.set("Set-Cookie", cookieString);
  return response;
});

// Middleware for authentication
const authenticate = async (c, next) => {
  // const headers = c.req.headers || new Headers();
  console.log("LOG C>REQ");
  // console.log(c.req)
  // const cookieHeader = headers.get("cookie") || "";
  const cookieHeader = c.req.header("cookie") || "";

  console.log("Raw cookie header:", cookieHeader);
  const cookies = cookie.parse(cookieHeader);
  const token = cookies.accessToken;
  console.log("Parsed token:", token);

  if (!token) return c.json({ message: "Not logged in" }, 401);

  try {
    const env = c.get("env");
    const secret = new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
    const { payload } = await jose.jwtVerify(token, secret);
    c.set("user", payload);
    console.log("inside Auth");
    console.log(c);
    await next();
  } catch (error) {
    return c.json({ message: "Invalid token" }, 403);
  }
};

// Routes
// GET /api/assistants → fetch assistant IDs
app.get("/api/assistants", authenticate, async (c) => {
  try {
    const env = c.get("env");
    console.log("Getting database connection for assistants");
    const sql = await getDB(env.DATABASE_URL);
    const user = c.get("user");

    const assistants = await sql`
      SELECT a.* FROM "AssistantID" a
      INNER JOIN "User" u ON a."userId" = u.id
      WHERE u.email = ${user.email}
      ORDER BY a."createdAt" DESC
    `;

    return c.json({ assistants });
  } catch (err) {
    console.error("Fetch assistants error:", err);
    return c.json({ message: "Error fetching assistants" }, 500);
  }
});

// Add /auth/me endpoint
app.get("/auth/me", authenticate, async (c) => {
  try {
    console.log("Fetching user details");
    const env = c.get("env");
    const sql = await getDB(env.DATABASE_URL);
    const user = c.get("user");

    const [userDetails] = await sql`
      SELECT id, email, "fullName", type
      FROM "User"
      WHERE email = ${user.email}
    `;

    if (!userDetails) {
      return c.json({ message: "User not found" }, 404);
    }

    return c.json({
      user: {
        email: userDetails.email,
        fullName: userDetails.fullName,
        type: userDetails.type,
      },
    });
  } catch (err) {
    console.error("Fetch user error:", err);
    return c.json({ message: "Error fetching user details" }, 500);
  }
});

// POST /api/assistants → create a new assistant ID
app.post("/api/assistants", authenticate, async (c) => {
  const { value, assistantName } = await c.req.json();

  if (!value || !assistantName) {
    return c.json({ message: "Assistant value and name are required" }, 400);
  }

  try {
    const env = c.get("env");
    console.log("Getting database connection for creating assistant");
    const sql = await getDB(env.DATABASE_URL);
    const user = c.get("user");

    // Get user ID
    const [userRecord] = await sql`
      SELECT id FROM "User" WHERE email = ${user.email}
    `;

    if (!userRecord) {
      return c.json({ message: "User not found" }, 404);
    }

    // Create assistant
    const [newAssistant] = await sql`
      INSERT INTO "AssistantID" (value, "assistantName", "userId")
      VALUES (${value}, ${assistantName}, ${userRecord.id})
      RETURNING *
    `;

    return c.json(
      { message: "Assistant created", assistant: newAssistant },
      201
    );
  } catch (err) {
    console.error("Create assistant error:", err);
    return c.json({ message: "Error creating assistant" }, 500);
  }
});

// PUT /api/assistants/:id → update assistant's name and/or value
app.put("/api/assistants/:id", authenticate, async (c) => {
  const assistantId = parseInt(c.param("id"));
  const { value, assistantName } = await c.req.json();

  if (isNaN(assistantId)) {
    return c.json({ message: "Invalid assistant ID" }, 400);
  }

  if (!value && !assistantName) {
    return c.json({ message: "Nothing to update" }, 400);
  }

  try {
    const env = c.get("env");
    console.log("Getting database connection for updating assistant");
    const sql = await getDB(env.DATABASE_URL);
    const user = c.get("user");

    // Verify ownership
    const [assistant] = await sql`
      SELECT a.id FROM "AssistantID" a
      INNER JOIN "User" u ON a."userId" = u.id
      WHERE a.id = ${assistantId} AND u.email = ${user.email}
    `;

    if (!assistant) {
      return c.json({ message: "Unauthorized or assistant not found" }, 403);
    }

    // Update assistant
    const [updatedAssistant] = await sql`
      UPDATE "AssistantID"
      SET ${value ? sql`value = ${value}` : sql``}
          ${value && assistantName ? sql`, ` : sql``}
          ${assistantName ? sql`"assistantName" = ${assistantName}` : sql``}
      WHERE id = ${assistantId}
      RETURNING *
    `;

    return c.json({
      message: "Assistant updated",
      assistant: updatedAssistant,
    });
  } catch (err) {
    console.error("Update assistant error:", err);
    return c.json({ message: "Error updating assistant" }, 500);
  }
});

// DELETE /api/assistants/:id → delete an assistant ID
app.delete("/api/assistants/:id", authenticate, async (c) => {
  const assistantId = parseInt(c.param("id"));

  if (isNaN(assistantId)) {
    return c.json({ message: "Invalid assistant ID" }, 400);
  }

  try {
    const env = c.get("env");
    console.log("Getting database connection for deleting assistant");
    const sql = await getDB(env.DATABASE_URL);
    const user = c.get("user");

    // Verify ownership and delete
    const [deleted] = await sql`
      WITH deleted AS (
        DELETE FROM "AssistantID" a
        USING "User" u
        WHERE a.id = ${assistantId} 
        AND a."userId" = u.id 
        AND u.email = ${user.email}
        RETURNING a.*
      )
      SELECT * FROM deleted
    `;

    if (!deleted) {
      return c.json({ message: "Unauthorized or not found" }, 403);
    }

    return c.json({ message: "Assistant deleted" });
  } catch (err) {
    console.error("Delete assistant error:", err);
    return c.json({ message: "Error deleting assistant" }, 500);
  }
});

// VoiceAI route
app.get("/voiceai/assistant/:id", authenticate, async (c) => {
  const { id } = c.req.param();
  const env = c.get("env");
  const VAPI_API_KEY = env.VAPI_API_KEY;

  if (!VAPI_API_KEY) {
    return c.json(
      { message: "VoiceAI API key not set in environment variables" },
      500
    );
  }

  try {
    const response = await fetch(`https://api.vapi.ai/assistant/${id}`, {
      headers: {
        Authorization: `Bearer ${VAPI_API_KEY}`,
      },
    });

    const data = await response.json();
    return c.json(data);
  } catch (error) {
    console.error("Error fetching assistant from Voiceai:", error);
    return c.json(
      {
        message: "Failed to fetch assistant from Voiceai",
        details: error.message,
      },
      error.response?.status || 500
    );
  }
});
app.route("/auth/profile", profileRoutes);

export default {
  fetch: app.fetch,
};
