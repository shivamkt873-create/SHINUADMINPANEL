const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const required = ["DATABASE_URL", "ADMIN_USERNAME", "ADMIN_PASSWORD_HASH", "JWT_SECRET"];
for (const k of required) if (!process.env[k]) {
  console.error(`Missing required environment variable: ${k}`); process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters."); process.exit(1);
}
const app = express();
const isProd = process.env.NODE_ENV === "production";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
});
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
    upgradeInsecureRequests: isProd ? [] : null
  }
}}));
app.use(express.json({limit:"20kb"}));
app.use(cookieParser());
app.use(express.static("public"));

app.get("/", (req, res) => res.sendFile(__dirname + "/index.html"));
app.get("/app.js", (req, res) => res.sendFile(__dirname + "/app.js"));
const loginLimiter = rateLimit({windowMs: 15*60*1000, max: 8, standardHeaders: true, legacyHeaders: false});
const apiLimiter = rateLimit({windowMs: 60*1000, max: 60, standardHeaders: true, legacyHeaders: false});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) UNIQUE NOT NULL,
      key_prefix VARCHAR(20) NOT NULL,
      label VARCHAR(120) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE INDEX IF NOT EXISTS licenses_created_at_idx ON licenses(created_at DESC);
  `);
}
function hashKey(key) { return crypto.createHash("sha256").update(key).digest("hex"); }
function makeKey() {
  const raw = crypto.randomBytes(20).toString("hex").toUpperCase();
  return "SHINU-" + raw.match(/.{1,5}/g).join("-");
}
function auth(req,res,next) {
  const token = req.cookies.shinu_admin;
  if (!token) return res.status(401).json({error:"Sign in required"});
  try {
    const p = jwt.verify(token, process.env.JWT_SECRET);
    if (p.sub !== process.env.ADMIN_USERNAME) throw new Error("bad subject");
    next();
  } catch { res.clearCookie("shinu_admin"); return res.status(401).json({error:"Session expired"}); }
}
app.get("/api/health", (req,res)=>res.json({ok:true,service:"SHINU ADMIN PANEL"}));
app.post("/api/admin/login", loginLimiter, async (req,res)=>{
  const {username,password} = req.body || {};
  if (typeof username !== "string" || typeof password !== "string" ||
      username.length > 100 || password.length > 200) return res.status(400).json({error:"Invalid input"});
  const okUser = crypto.timingSafeEqual(
    Buffer.from(username.padEnd(100,"\0").slice(0,100)),
    Buffer.from(process.env.ADMIN_USERNAME.padEnd(100,"\0").slice(0,100))
  );
  const okPass = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (!okUser || !okPass) return res.status(401).json({error:"Incorrect username or password"});
  const token = jwt.sign({sub:process.env.ADMIN_USERNAME}, process.env.JWT_SECRET, {expiresIn:"8h"});
  res.cookie("shinu_admin", token, {httpOnly:true, secure:isProd, sameSite:"strict", maxAge:8*60*60*1000, path:"/"});
  res.json({ok:true});
});
app.post("/api/admin/logout", auth, (req,res)=>{res.clearCookie("shinu_admin",{httpOnly:true,secure:isProd,sameSite:"strict",path:"/"});res.json({ok:true});});
app.get("/api/admin/me", auth, (req,res)=>res.json({username:process.env.ADMIN_USERNAME}));

app.get("/api/admin/licenses", auth, async (req,res)=>{
  const {rows}=await pool.query("SELECT id,key_prefix,label,created_at,expires_at,active,(expires_at > NOW()) AS unexpired FROM licenses ORDER BY created_at DESC LIMIT 500");
  res.json({licenses:rows});
});
app.post("/api/admin/licenses", auth, async (req,res)=>{
  const {label="",days,expiresAt}=req.body || {};
  if (typeof label !== "string" || label.length > 120) return res.status(400).json({error:"Label must be 120 characters or fewer"});
  let expiry;
  if (expiresAt) expiry = new Date(expiresAt);
  else if (Number.isInteger(days) && [1,7,30,90,365].includes(days)) expiry = new Date(Date.now()+days*86400000);
  else return res.status(400).json({error:"Choose 1, 7, 30, 90, 365 days or a valid custom expiry"});
  if (!Number.isFinite(expiry.getTime()) || expiry <= new Date() || expiry > new Date(Date.now()+10*365*86400000))
    return res.status(400).json({error:"Expiry must be in the future and within 10 years"});
  const key=makeKey();
  await pool.query("INSERT INTO licenses(key_hash,key_prefix,label,expires_at) VALUES($1,$2,$3,$4)",
    [hashKey(key),key.slice(0,11),label.trim(),expiry.toISOString()]);
  res.status(201).json({license:{key,label:label.trim(),expires_at:expiry.toISOString()}});
});
app.patch("/api/admin/licenses/:id", auth, async (req,res)=>{
  const id=Number(req.params.id), {active}=req.body || {};
  if (!Number.isSafeInteger(id) || typeof active !== "boolean") return res.status(400).json({error:"Invalid request"});
  const r=await pool.query("UPDATE licenses SET active=$1 WHERE id=$2 RETURNING id,active",[active,id]);
  if (!r.rowCount) return res.status(404).json({error:"License not found"});
  res.json({license:r.rows[0]});
});
// Public validation endpoint for software you own or are authorized to integrate.
// Never place the admin secret or database credentials in a browser extension.
app.post("/api/license/validate", apiLimiter, async (req,res)=>{
  const {key}=req.body || {};
  if (typeof key !== "string" || key.length < 10 || key.length > 100)
    return res.status(400).json({valid:false,error:"Invalid key format"});
  const {rows}=await pool.query("SELECT active,expires_at FROM licenses WHERE key_hash=$1",[hashKey(key.trim())]);
  if (!rows.length) return res.json({valid:false,reason:"not_found"});
  const item=rows[0];
  if (!item.active) return res.json({valid:false,reason:"deactivated"});
  if (new Date(item.expires_at) <= new Date()) return res.json({valid:false,reason:"expired"});
  res.json({valid:true,expiresAt:item.expires_at});
});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Internal server error"});});
const port=process.env.PORT || 3000;
initDb().then(()=>app.listen(port,()=>console.log(`SHINU ADMIN PANEL listening on ${port}`)))
  .catch(e=>{console.error("Database initialization failed",e);process.exit(1);});
