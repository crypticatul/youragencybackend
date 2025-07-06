const express = require("express");
const { fetchCallsOptimized } = require("../services/voiceaiService");
const router = express.Router();

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
    "Access-Control-Allow-Origin": isAllowed ? origin : "",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

router.use((req, res, next) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);
  res.set(corsHeaders);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  next();
});

// Chart data endpoint - returns aggregated data for charts
router.get("/overview", async (req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);

  try {
    const {
      assistantId,
      days = "30", // Default to 30 days
      createdAtGt,
      createdAtLt,
    } = req.query;

    console.log(`Fetching chart data for ${days} days, assistant: ${assistantId}`);

    // Use optimized service to fetch calls data
    const result = await fetchCallsOptimized({
      assistantId,
      days,
      customStartDate: createdAtGt,
      customEndDate: createdAtLt,
    });

    // Return processed chart data instead of raw calls
    const response = {
      chartData: result.chartData,
      metadata: {
        totalCalls: result.totalCalls,
        dateRange: result.dateRange,
        limit: result.limit,
        timePeriod: days,
        assistantId,
      },
      performance: {
        optimizedLimit: result.limit,
        message: `Fetched ${result.totalCalls} calls with optimized limit of ${result.limit} for ${days} days`,
      }
    };

    res.set(corsHeaders);
    res.status(200).json(response);

  } catch (error) {
    console.error("Chart data fetch error:", error);
    res.set(corsHeaders);
    res.status(500).json({
      error: "Failed to fetch chart data",
      message: error.message,
      fallback: "Consider using raw /call endpoint with manual processing"
    });
  }
});

// Performance info endpoint
router.get("/performance-info", async (req, res) => {
  const origin = req.headers.origin;
  const corsHeaders = getCorsHeaders(origin);
  
  const { LIMIT_CONFIG } = require("../services/voiceaiService");

  res.set(corsHeaders);
  res.status(200).json({
    optimizationConfig: LIMIT_CONFIG,
    recommendations: {
      "7_days": "Fast loading - limit 100 calls",
      "30_days": "Good performance - limit 200 calls", 
      "60_days": "Moderate performance - limit 300 calls",
      "all_time": "May be slower - limit 500 calls, consider pagination"
    },
    usage: "Add ?days=7|30|60|all to your requests for optimized performance"
  });
});

module.exports = router;
