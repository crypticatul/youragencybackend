// routes/knowledgebase.routes.js
const express = require("express");
const jwt = require("jsonwebtoken");
const { createKnowledgeBase } = require("../services/voiceaiService");

const router = express.Router();

router.post("/", async (req, res) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
    const kbData = req.body; // should include name, provider, and optionally searchPlan, createPlan, id, orgId

    const result = await createKnowledgeBase(kbData);

    res.status(201).json({ message: "Knowledge base created", data: result });
  } catch (error) {
    console.error("Knowledge base creation error:", error);
    res.status(500).json({ message: error.message || "Server error" });
  }
});

module.exports = router;
