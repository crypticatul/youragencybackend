# Render Environment Variables Setup

## Required Environment Variables for Optimization

Based on the complete code analysis, here are the **exact environment variables** you need to set in your Render dashboard:

### ✅ **Already Set (Current Render Variables)**
1. **ACCESS_TOKEN_SECRET** - JWT token generation
2. **DATABASE_URL** - Prisma database connection  
3. **NODE_ENV** - Environment detection
4. **REFRESH_TOKEN_SECRET** - Refresh token generation
5. **RESEND_API_KEY** - Email functionality (OTP, password reset)
6. **VAPI_API_KEY** - **Critical for optimization** - Used by optimized calls service

### 🔧 **Optional but Recommended**
7. **FRONTEND_URL** - Used for password reset email links
   - Set to: `https://voice.cognitiev.com` (or your actual frontend domain)
   - If not set, password reset emails will use localhost links

## Final Render Environment Variables Configuration

When you deploy to Render, ensure these are set:

```
ACCESS_TOKEN_SECRET=your_existing_value
REFRESH_TOKEN_SECRET=your_existing_value  
DATABASE_URL=your_existing_value
VAPI_API_KEY=your_existing_value
RESEND_API_KEY=your_existing_value
NODE_ENV=production
FRONTEND_URL=https://voice.cognitiev.com
```

## Environment Variables Analysis by Feature

### Authentication & Security
- `ACCESS_TOKEN_SECRET` - JWT authentication
- `REFRESH_TOKEN_SECRET` - Token refresh  
- `NODE_ENV` - Production security settings

### Database
- `DATABASE_URL` - Prisma connection

### External APIs
- `VAPI_API_KEY` - **Required for optimization** - Calls VAPI API with smart limits
- `RESEND_API_KEY` - Email sending (OTP, password reset)

### Frontend Integration  
- `FRONTEND_URL` - Password reset links (optional)

## Critical Variables for Optimization

The optimization **will work** with your current variables because:

✅ **VAPI_API_KEY** is the key variable used by:
- `services/voiceaiService.js` - Smart call fetching
- `routes/voiceAIProxyRoute.js` - Optimized proxy requests
- Main `index.js` - Agent update functionality

## Summary

🎯 **Your current Render environment is 95% ready!**

**Required Action**: Just add `FRONTEND_URL=https://voice.cognitiev.com`

**The optimization will work immediately** because all critical variables (especially `VAPI_API_KEY`) are already configured.

## Testing the Optimization

After deployment, test these endpoints:
- `GET /api/voiceai/call?days=7` - Optimized calls (limit 100)
- `GET /api/voiceai/call?days=30` - Optimized calls (limit 200)
- `GET /api/charts/overview?days=30` - Pre-processed chart data

## Performance Expected

- **7 days**: 2x faster (100 vs 200+ calls)
- **30 days**: Same speed, more reliable  
- **60 days**: Better coverage (300 calls)
- **All time**: Much better coverage (500 calls)
