const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Load a local .env file without requiring an extra package.
// This keeps the project easy to run with `npm install` + `npm start`.
function loadDotEnv() {
  const envFile = path.join(__dirname, '.env');
  if (!fs.existsSync(envFile)) return;
  const lines = fs.readFileSync(envFile, 'utf8').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

loadDotEnv();

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = path.join(ROOT, 'server-data', 'students.json');
const ADMIN_DB_FILE = path.join(ROOT, 'server-data', 'admins.json');
const RESET_TTL = 10 * 60 * 1000;
const OTP_TTL = 10 * 60 * 1000;
const pendingRegistrations = new Map();
const otpSendTimes = new Map();

const COLLEGES = {
  GPV001: { name: 'Government Polytechnic Vaishali', prefix: 'GPV' },
  GPM001: { name: 'Government Polytechnic Muzaffarpur', prefix: 'GPM' },
  GPA001: { name: 'Government Polytechnic Aurangabad', prefix: 'GPA' }
};

function ensureDb(){
  fs.mkdirSync(path.dirname(DB_FILE), {recursive:true});
  if(!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
}
function readStudents(){ ensureDb(); try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8')||'[]')}catch{return []} }
function readAdmins(){ try{return JSON.parse(fs.readFileSync(ADMIN_DB_FILE,'utf8')||'[]')}catch{return []} }
function writeStudents(items){ ensureDb(); fs.writeFileSync(DB_FILE, JSON.stringify(items,null,2)); }
function normalize(v){ return String(v ?? '').trim(); }
function emailNorm(v){ return normalize(v).toLowerCase(); }
function college(code){ return COLLEGES[normalize(code).toUpperCase()] || null; }
function studentId(code, roll){ const c=college(code); if(!c) return ''; return c.prefix + normalize(roll).toUpperCase().replace(/[^A-Z0-9]/g,''); }
function passwordRules(p){return typeof p==='string' && p.length>=8 && /[A-Za-z]/.test(p) && /\d/.test(p);}
function hashPassword(password,salt){ return crypto.scryptSync(password,salt,64).toString('hex'); }
function safeStudent(s){ const x={...s}; delete x.passwordHash; delete x.passwordSalt; delete x.resetTokenHash; delete x.resetTokenExpires; delete x.resetTokenUsed; delete x.resetToken; delete x.resetOtpHash; delete x.resetOtpExpires; delete x.resetOtpAttempts; return x; }
function json(res,status,payload){ const body=JSON.stringify(payload); res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(body); }
function parseBody(req){return new Promise((resolve,reject)=>{let data='';req.on('data',c=>{data+=c;if(data.length>1000000) req.destroy();});req.on('end',()=>{try{resolve(data?JSON.parse(data):{})}catch(e){reject(e)}});req.on('error',reject);});}
function mailer(){
  if(!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({service:'gmail',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
}
function makeOtp(){ return String(crypto.randomInt(0,1000000)).padStart(6,'0'); }
function otpHash(code,email){ return crypto.createHash('sha256').update(`${emailNorm(email)}:${String(code)}:${process.env.OTP_PEPPER||'proexam-otp-v1'}`).digest('hex'); }
function safeEqualHex(a,b){ try { const x=Buffer.from(String(a),'hex'), y=Buffer.from(String(b),'hex'); return x.length===y.length && x.length>0 && crypto.timingSafeEqual(x,y); } catch { return false; } }
async function sendOtpEmail(email,name,code,purpose){
  const transporter=mailer(); if(!transporter) throw new Error('EMAIL_NOT_CONFIGURED');
  await transporter.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to:email,subject:`ProExam ${purpose} verification code`,text:`Hello ${name||'Student'},\n\nYour ProExam verification code is ${code}. It expires in 10 minutes. Do not share this code with anyone.\n\nIf you did not request this, you can ignore this email.\n\nProExam`,html:`<p>Hello ${escapeHtml(name||'Student')},</p><p>Your ProExam verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${code}</p><p>This code expires in 10 minutes. Do not share it with anyone.</p><p>If you did not request this, you can ignore this email.</p><p>ProExam</p>`});
}
function sendCooldownKey(purpose,email){ return `${purpose}:${emailNorm(email)}`; }
function checkSendCooldown(key){ const last=otpSendTimes.get(key)||0; return Date.now()-last>=60_000; }
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

async function api(req,res){
  let body={}; try{body=await parseBody(req)}catch{return json(res,400,{ok:false,message:'Invalid request.'})}
  if(req.method==='POST' && req.url==='/api/register'){
    const c=college(body.collegeCode); if(!c) return json(res,400,{ok:false,message:'Invalid college code.'});
    const name=normalize(body.name), email=emailNorm(body.email), roll=normalize(body.rollNumber), password=String(body.password||'');
    if(!name||!email||!roll||!password) return json(res,400,{ok:false,message:'Please fill all required details.'});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res,400,{ok:false,message:'Enter a valid email address.'});
    if(!passwordRules(password)) return json(res,400,{ok:false,message:'Password must be at least 8 characters and contain a letter and a number.'});
    const students=readStudents(), code=normalize(body.collegeCode).toUpperCase(), userId=studentId(code,roll);
    if(students.some(s=>s.collegeCode===code && normalize(s.rollNumber).toLowerCase()===roll.toLowerCase())) return json(res,409,{ok:false,message:'This college roll number is already registered.'});
    if(students.some(s=>emailNorm(s.email)===email)) return json(res,409,{ok:false,message:'This email is already registered.'});
    if(students.some(s=>String(s.userId||'').toLowerCase()===userId.toLowerCase())) return json(res,409,{ok:false,message:'This Student ID already exists. Please contact your college.'});
    const key=sendCooldownKey('register',email); if(!checkSendCooldown(key)) return json(res,429,{ok:false,message:'Please wait 60 seconds before requesting another OTP.'});
    const otp=makeOtp(), salt=crypto.randomBytes(16).toString('hex');
    const pending={id:crypto.randomUUID(),userId,name,email,rollNumber:roll,collegeCode:code,institute:c.name,branch:normalize(body.branch)||'Not specified',semester:normalize(body.semester)||'Not specified',phone:normalize(body.phone),passwordHash:hashPassword(password,salt),passwordSalt:salt,role:'student',verified:true,createdAt:new Date().toISOString(),otpHash:otpHash(otp,email),otpExpires:Date.now()+OTP_TTL,attempts:0};
    try { await sendOtpEmail(email,name,otp,'registration'); pendingRegistrations.set(email,pending); otpSendTimes.set(key,Date.now()); return json(res,200,{ok:true,message:'Verification OTP sent to your email. It expires in 10 minutes.'}); }
    catch(e){ console.error('REGISTRATION EMAIL ERROR:',e.message); if(e.message==='EMAIL_NOT_CONFIGURED') return json(res,503,{ok:false,message:'Email service is not configured. Add valid Gmail App Password to .env and restart.'}); return json(res,502,{ok:false,message:'Could not send OTP email. Check Gmail SMTP settings and try again.'}); }
  }
  if(req.method==='POST' && req.url==='/api/register/verify'){
    const email=emailNorm(body.email), pending=pendingRegistrations.get(email);
    if(!pending) return json(res,400,{ok:false,message:'No pending registration found. Request a new OTP.'});
    if(Date.now()>pending.otpExpires) { pendingRegistrations.delete(email); return json(res,400,{ok:false,message:'OTP expired. Please register again to get a new OTP.'}); }
    if(++pending.attempts>5) { pendingRegistrations.delete(email); return json(res,429,{ok:false,message:'Too many incorrect OTP attempts. Please register again.'}); }
    if(!safeEqualHex(pending.otpHash,otpHash(body.otp,email))) return json(res,400,{ok:false,message:'Incorrect OTP. Please check the code and try again.'});
    const students=readStudents();
    if(students.some(s=>emailNorm(s.email)===email || (s.collegeCode===pending.collegeCode && normalize(s.rollNumber).toLowerCase()===pending.rollNumber.toLowerCase()) || String(s.userId||'').toLowerCase()===pending.userId.toLowerCase())) { pendingRegistrations.delete(email); return json(res,409,{ok:false,message:'This email, roll number, or Student ID is already registered.'}); }
    const student={...pending}; delete student.otpHash; delete student.otpExpires; delete student.attempts;
    students.push(student); writeStudents(students); pendingRegistrations.delete(email);
    return json(res,200,{ok:true,student:safeStudent(student)});
  }
  if(req.method==='POST' && req.url==='/api/admin-login'){
    const c=college(body.collegeCode); if(!c) return json(res,400,{ok:false,message:'Invalid college code.'});
    const a=readAdmins().find(x=>x.collegeCode===normalize(body.collegeCode).toUpperCase() && x.userId.toLowerCase()===normalize(body.userId).toLowerCase());
    if(!a) return json(res,401,{ok:false,message:'Invalid ID or password for this college.'});
    const supplied=hashPassword(String(body.password||''),a.passwordSalt);
    if(!crypto.timingSafeEqual(Buffer.from(supplied,'hex'),Buffer.from(a.passwordHash,'hex'))) return json(res,401,{ok:false,message:'Invalid ID or password for this college.'});
    return json(res,200,{ok:true,admin:{userId:a.userId,name:a.name,collegeCode:a.collegeCode,role:a.role,collegeName:c.name}});
  }
  if(req.method==='POST' && req.url==='/api/login'){
    const c=college(body.collegeCode); if(!c) return json(res,400,{ok:false,message:'Invalid college code.'});
    const students=readStudents(); const s=students.find(x=>x.collegeCode===normalize(body.collegeCode).toUpperCase() && x.userId.toLowerCase()===normalize(body.userId).toLowerCase());
    if(!s) return json(res,401,{ok:false,message:'Invalid ID or password for this college.'});
    const supplied=hashPassword(String(body.password||''),s.passwordSalt);
    if(!crypto.timingSafeEqual(Buffer.from(supplied,'hex'),Buffer.from(s.passwordHash,'hex'))) return json(res,401,{ok:false,message:'Invalid ID or password for this college.'});
    return json(res,200,{ok:true,student:safeStudent(s)});
  }
  if(req.method==='POST' && req.url==='/api/forgot-password'){
    const generic={ok:true,message:'If the details match a registered account, a verification OTP has been sent to the registered email address.'};
    const c=college(body.collegeCode); if(!c) return json(res,200,generic);
    const students=readStudents(), s=students.find(x=>x.collegeCode===normalize(body.collegeCode).toUpperCase() && emailNorm(x.email)===emailNorm(body.email));
    if(!s) return json(res,200,generic);
    const email=emailNorm(s.email), key=sendCooldownKey('reset',email); if(!checkSendCooldown(key)) return json(res,429,{ok:false,message:'Please wait 60 seconds before requesting another OTP.'});
    const otp=makeOtp(); s.resetOtpHash=otpHash(otp,email); s.resetOtpExpires=Date.now()+OTP_TTL; s.resetOtpAttempts=0; delete s.resetTokenHash; delete s.resetTokenExpires; delete s.resetTokenUsed;
    writeStudents(students);
    try { await sendOtpEmail(email,s.name,otp,'password reset'); otpSendTimes.set(key,Date.now()); return json(res,200,generic); }
    catch(e){ console.error('RESET OTP EMAIL ERROR:',e.message); delete s.resetOtpHash; delete s.resetOtpExpires; delete s.resetOtpAttempts; writeStudents(students); if(e.message==='EMAIL_NOT_CONFIGURED') return json(res,503,{ok:false,message:'Email service is not configured. Add valid Gmail App Password to .env and restart.'}); return json(res,502,{ok:false,message:'Could not send OTP email. Check Gmail SMTP settings and try again.'}); }
  }
  if(req.method==='POST' && req.url==='/api/reset/verify'){
    const code=normalize(body.collegeCode).toUpperCase(); if(!college(code)) return json(res,400,{ok:false,message:'Invalid college code.'});
    const students=readStudents(), s=students.find(x=>x.collegeCode===code && emailNorm(x.email)===emailNorm(body.email));
    if(!s || !s.resetOtpHash || Date.now()>Number(s.resetOtpExpires||0)) return json(res,400,{ok:false,message:'OTP expired or invalid. Request a new OTP.'});
    s.resetOtpAttempts=Number(s.resetOtpAttempts||0)+1;
    if(s.resetOtpAttempts>5){delete s.resetOtpHash;delete s.resetOtpExpires;delete s.resetOtpAttempts;writeStudents(students);return json(res,429,{ok:false,message:'Too many incorrect OTP attempts. Request a new OTP.'});}
    if(!safeEqualHex(s.resetOtpHash,otpHash(body.otp,s.email))){writeStudents(students);return json(res,400,{ok:false,message:'Incorrect OTP. Please check the code and try again.'});}
    const resetToken=crypto.randomBytes(32).toString('hex'); s.resetTokenHash=crypto.createHash('sha256').update(resetToken).digest('hex'); s.resetTokenExpires=Date.now()+RESET_TTL; s.resetTokenUsed=false;
    delete s.resetOtpHash;delete s.resetOtpExpires;delete s.resetOtpAttempts;writeStudents(students);
    return json(res,200,{ok:true,token:resetToken,userId:s.userId});
  }
  if(req.method==='POST' && req.url==='/api/reset/password'){
    const c=college(body.collegeCode); if(!c) return json(res,400,{ok:false,message:'Reset session expired. Please request a new reset email.'});
    const password=String(body.newPassword||''); if(!passwordRules(password)) return json(res,400,{ok:false,message:'Password must be at least 8 characters and contain a letter and a number.'});
    const students=readStudents(); const s=students.find(x=>x.collegeCode===normalize(body.collegeCode).toUpperCase() && x.userId.toLowerCase()===normalize(body.userId).toLowerCase());
    const h=crypto.createHash('sha256').update(String(body.token||'')).digest('hex');
    if(!s||s.resetTokenUsed||Date.now()>Number(s.resetTokenExpires||0)||s.resetTokenHash!==h) return json(res,400,{ok:false,message:'Reset session expired. Please request a new reset email.'});
    const salt=crypto.randomBytes(16).toString('hex'); s.passwordSalt=salt;s.passwordHash=hashPassword(password,salt);s.resetTokenUsed=true;delete s.resetTokenHash;delete s.resetTokenExpires;delete s.resetToken;writeStudents(students);
    return json(res,200,{ok:true});
  }
  return json(res,404,{ok:false,message:'Not found'});
}

const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webmanifest':'application/manifest+json','.txt':'text/plain; charset=utf-8'};
function serve(req,res){
  let p=decodeURIComponent(req.url.split('?')[0]); if(p==='/'||p==='')p='/index.html';
  const file=path.normalize(path.join(ROOT,p)); if(!file.startsWith(ROOT))return res.writeHead(403).end('Forbidden');
  fs.stat(file,(err,st)=>{if(err||!st.isFile())return res.writeHead(404).end('Not found');res.writeHead(200,{'Content-Type':mime[path.extname(file).toLowerCase()]||'application/octet-stream'});fs.createReadStream(file).pipe(res);});
}
const server=http.createServer((req,res)=>{ if(req.url.startsWith('/api/')) api(req,res).catch(()=>json(res,500,{ok:false,message:'Server error.'})); else serve(req,res); });
server.listen(PORT,()=>{
  console.log(`ProExam running at http://localhost:${PORT}`);
  console.log(process.env.SMTP_USER && process.env.SMTP_PASS ? 'Gmail SMTP: CONFIGURED' : 'Gmail SMTP: NOT CONFIGURED');
});
