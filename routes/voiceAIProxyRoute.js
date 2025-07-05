const express = require("express");
const axios = require("axios");
require("dotenv").config();
const router = express.Router();



const VOICE_AI_API_BASE_URL = "https://api.vapi.ai";
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:8080",
  "https://voice.cognitiev.com",
  "https://youragency2.netlify.app",
  "https://propai.cognitiev.com"
];

function getCorsHeaders(origin) {
  const isAllowed = allowedOrigins.includes(origin);
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : "", // ✅ must be a single string
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
router.use((req, res, next) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  // Apply CORS headers
  res.set(corsHeaders);

  // Manually handle OPTIONS requests for CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(204).end(); // Preflight success response
  }

  next(); // Continue to actual route
});


// Middleware to validate API key and build headers
function buildHeaders(req) {
  const voiceAIKey = process.env.VAPI_API_KEY;
  if (!voiceAIKey) {
    throw new Error("VOICEAIKEY is not set in environment variables.");
  }

  const headers = {
    Authorization: `Bearer ${voiceAIKey}`,
    "Content-Type": "application/json",
  };

  const allowedForwardHeaders = ["user-agent", "accept", "accept-language"];
  allowedForwardHeaders.forEach((key) => {
    if (req.headers[key]) headers[key] = req.headers[key];
  });

  return headers;
}

// Helper to forward request to VoiceAI API
async function proxyRequest(req, res, endpointPath, methodOverride = null) {
  const origin = req.headers.origin;
    const corsHeaders = getCorsHeaders(origin);
  try {

    const headers = buildHeaders(req);
    const targetUrl = `${VOICE_AI_API_BASE_URL}${endpointPath}${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`;
    const method = methodOverride || req.method;

    const response = await axios({
      url: targetUrl,
      method,
      headers,
      data: ["GET", "HEAD"].includes(method) ? undefined : req.body,
      responseType: "text",
      validateStatus: null,
    });

    res.set({
      ...corsHeaders,
      "Content-Type": response.headers["content-type"] || "application/json",
    });

    try {
      const jsonData = JSON.parse(response.data);
      res.status(response.status).json(jsonData);
    } catch {
      res.status(response.status).send(response.data);
    }
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: "Unknown proxy error" };
    res.set(corsHeaders).status(status).json({
      error: "Proxy Error",
      message: err.message,
      responseData: data,
    });
  }
}

// === Routes ===

// CALL
router.get("/call", async (req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  const {
    id,
    assistantId,
    phoneNumberId,
    limit,
    createdAtGt,
    createdAtLt,
    createdAtGe,
    createdAtLe,
    updatedAtGt,
    updatedAtLt,
    updatedAtGe,
    updatedAtLe,
  } = req.query;

  const queryParams = new URLSearchParams();
  if (id) queryParams.append("id", id);
  if (assistantId) queryParams.append("assistantId", assistantId);
  if (phoneNumberId) queryParams.append("phoneNumberId", phoneNumberId);

  // Use provided limit or default to 1000
  queryParams.append("limit", limit || "200");

  if (createdAtGt) queryParams.append("createdAtGt", createdAtGt);
  if (createdAtLt) queryParams.append("createdAtLt", createdAtLt);
  if (createdAtGe) queryParams.append("createdAtGe", createdAtGe);
  if (createdAtLe) queryParams.append("createdAtLe", createdAtLe);
  if (updatedAtGt) queryParams.append("updatedAtGt", updatedAtGt);
  if (updatedAtLt) queryParams.append("updatedAtLt", updatedAtLt);
  if (updatedAtGe) queryParams.append("updatedAtGe", updatedAtGe);
  if (updatedAtLe) queryParams.append("updatedAtLe", updatedAtLe);

  const proxiedUrl = queryParams.toString() ? `/call?${queryParams.toString()}` : "/call";

  await proxyRequest(req, res, proxiedUrl, "GET");
});


router.post("/call", (req, res) => proxyRequest(req, res, "/call"));

// ASSISTANT
router.get("/assistant", (req, res) => proxyRequest(req, res, "/assistant"));
router.post("/assistant", (req, res) => proxyRequest(req, res, "/assistant"));
router.patch("/assistant/:id", (req, res) =>
  proxyRequest(req, res, `/assistant/${req.params.id}`, "PATCH")
);

// KNOWLEDGE BASE
router.get("/knowledge-base", (req, res) => proxyRequest(req, res, "/knowledge-base"));
router.post("/knowledge-base", (req, res) => proxyRequest(req, res, "/knowledge-base"));

// CATCH OTHER ROUTES (OPTIONAL — add if you want dynamic flexibility)
router.use((req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  res.status(404).set(corsHeaders).json({
    error: "Route not found",
    message: `Route ${req.originalUrl} not defined in VoiceAI proxy.`,
  });
});


module.exports = router;
