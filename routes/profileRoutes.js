import { Hono } from 'hono';
import * as jose from 'jose';
import * as cookie from 'cookie';
import { neon } from '@neondatabase/serverless';

const profileRoutes = new Hono();

const getDB = async (url) => {
  const sql = neon(url);
  await sql`SELECT 1`; // test connection
  return sql;
};

profileRoutes.get('/', async (c) => {
  const cookieHeader = c.req.header('cookie') || '';
  const cookies = cookie.parse(cookieHeader);
  const token = cookies.accessToken;

  if (!token) return c.json({ message: 'Not logged in' }, 401);

  try {
    const env = c.get('env');
    const secret = new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
    const { payload } = await jose.jwtVerify(token, secret);

    const sql = await getDB(env.DATABASE_URL);
    const [user] = await sql`
      SELECT email, "fullName", type
      FROM "User"
      WHERE email = ${payload.email}
    `;

    if (!user) return c.json({ message: 'User not found' }, 404);

    return c.json(user);
  } catch (error) {
    console.error('Token verification error:', error);
    return c.json({ message: 'Invalid token' }, 403);
  }
});

profileRoutes.put('/', async (c) => {
    const cookieHeader = c.req.header('cookie') || '';
    const cookies = cookie.parse(cookieHeader);
    const token = cookies.accessToken;
  
    if (!token) return c.json({ message: 'Not logged in' }, 401);
  
    try {
      const env = c.get('env');
      const secret = new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
      const { payload } = await jose.jwtVerify(token, secret);
      const { fullName, type } = await c.req.json();
  
      const sql = await getDB(env.DATABASE_URL);
  
      // Build dynamic query
      const updates = [];
      const values = [];
  
      if (fullName) {
        updates.push(`"fullName" = $${updates.length + 1}`);
        values.push(fullName);
      }
  
      if (type) {
        updates.push(`type = $${updates.length + 1}`);
        values.push(type);
      }
  
      if (updates.length === 0) {
        return c.json({ message: 'No fields to update' }, 400);
      }
  
      // Add email condition
      values.push(payload.email);
      const updateQuery = `
        UPDATE "User"
        SET ${updates.join(', ')}
        WHERE email = $${values.length}
        RETURNING email, "fullName", type
      `;
  
      const updatedUser = await sql(updateQuery, values);
  
      return c.json({ message: 'Profile updated', user: updatedUser[0] });
    } catch (error) {
      console.error('Profile update error:', error);
      return c.json({ message: 'Error updating profile' }, 500);
    }
  });
  

export default profileRoutes;
