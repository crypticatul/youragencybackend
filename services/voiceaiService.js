// services/voiceaiService.js
const axios = require("axios");

const createKnowledgeBase = async (payload) => {
  try {
    const response = await axios.post(
      "https://api.vapi.ai/knowledge-base",
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    return response.data;
  } catch (error) {
    console.error("Vapi createKnowledgeBase error:", error.response?.data || error.message);
    throw new Error("Failed to create knowledge base");
  }
};

module.exports = {
  createKnowledgeBase,
};
