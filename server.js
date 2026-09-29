const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto');
const SECRET=process.env.JWT_SECRET||'change-me-in-production';
const db=new Database(process.env.DB_FILE||'school.db');db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,role TEXT NOT NULL,first TEXT,last TEXT,login TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,code TEXT UNIQUE NOT NULL,lang TEXT DEFAULT 'hy',theme TEXT DEFAULT 'light');
CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS members(class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,PRIMARY KEY(class_id,user_id));
CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY,class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,subject TEXT,weekday INTEGER,start TEXT,end TEXT);
CREATE TABLE IF NOT EXISTS grades(id INTEGER PRIMARY KEY,class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,teacher_id INTEGER,subject TEXT,date TEXT,grade INTEGER,UNIQUE(student_id,subject,date));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,text TEXT,ts INTEGER);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,scanner_id INTEGER,target_id INTEGER,ts INTEGER);`);
const q=(s,...a)=>db.prepare(s).all(...a),one=(s,...a)=>db.prepare(s).get(...a),run=(s,...a)=>db.prepare(s).run(...a);
const newCode=()=>crypto.randomBytes(5).toString('hex');
if(!one("SELECT 1 FROM users WHERE role='admin'"))run("INSERT INTO users(role,first,last,login,hash,code) VALUES('admin','Admin','',?,?,?)",'admin',bcrypt.hashSync(process.env.ADMIN_PASS||'admin123',10),newCode());

const app=express();app.use(express.json());app.use(express.static(path.join(__dirname,'public')));
const tok=u=>jwt.sign({id:u.id,v:u.hash.slice(-12)},SECRET,{expiresIn:'30d'});
const pub=u=>({id:u.id,role:u.role,first:u.first,last:u.last,login:u.login,code:u.code,lang:u.lang,theme:u.theme});
const wrap=f=>(a,b)=>{try{b.json(f(a)||{})}catch(e){b.status(String(e.code).includes('UNIQUE')?409:400).json({error:e.message})}};
app.post('/api/login',(a,b)=>{const u=one('SELECT * FROM users WHERE login=?',a.body.login);if(!u||!bcrypt.compareSync(a.body.password||'',u.hash))return b.sendStatus(401);b.json({token:tok(u),me:pub(u)})});

// every request re-reads the user from the DB: admin edits/deletes apply instantly
app.use('/api',(a,b,n)=>{try{const p=jwt.verify((a.headers.authorization||'').slice(7),SECRET),u=one('SELECT * FROM users WHERE id=?',p.id);if(!u||u.hash.slice(-12)!==p.v)throw 0;a.u=u;n()}catch{b.sendStatus(401)}});
const need=(...r)=>(a,b,n)=>r.includes(a.u.role)?n():b.sendStatus(403);
const staff=u=>['admin','director'].includes(u.role);
const inCls=(u,c)=>staff(u)||!!one('SELECT 1 FROM members WHERE class_id=? AND user_id=?',c,u.id);

app.get('/api/me',(a,b)=>b.json(pub(a.u)));
app.put('/api/me/prefs',wrap(a=>run('UPDATE users SET lang=?,theme=? WHERE id=?',a.body.lang,a.body.theme,a.u.id)));

app.get('/api/users',need('admin','director'),wrap(a=>q(`SELECT id,role,first,last,login,code FROM users ${a.u.role=='admin'?'':"WHERE role='teacher'"} ORDER BY role,last`)));
app.post('/api/users',need('admin'),wrap(a=>{const d=a.body;run('INSERT INTO users(role,first,last,login,hash,code) VALUES(?,?,?,?,?,?)',d.role,d.first,d.last,d.login,bcrypt.hashSync(d.password,10),d.code||newCode())}));
app.put('/api/users/:id',need('admin'),wrap(a=>{const d=a.body,id=a.params.id;run("UPDATE users SET role=?,first=?,last=?,login=?,code=COALESCE(NULLIF(?,''),code) WHERE id=?",d.role,d.first,d.last,d.login,d.code,id);if(d.password)run('UPDATE users SET hash=? WHERE id=?',bcrypt.hashSync(d.password,10),id)}));
app.delete('/api/users/:id',need('admin'),wrap(a=>{if(a.params.id==a.u.id)throw new Error('self');run('DELETE FROM users WHERE id=?',a.params.id)}));

app.get('/api/classes',wrap(a=>staff(a.u)?q('SELECT * FROM classes ORDER BY name'):q('SELECT c.* FROM classes c JOIN members m ON m.class_id=c.id WHERE m.user_id=? ORDER BY name',a.u.id)));
app.post('/api/classes',need('admin'),wrap(a=>run('INSERT INTO classes(name) VALUES(?)',a.body.name)));
app.delete('/api/classes/:id',need('admin'),wrap(a=>run('DELETE FROM classes WHERE id=?',a.params.id)));
app.get('/api/classes/:id/members',wrap(a=>{if(!inCls(a.u,a.params.id))throw new Error('no');return q('SELECT u.id,u.role,u.first,u.last FROM members m JOIN users u ON u.id=m.user_id WHERE m.class_id=? ORDER BY u.role DESC,u.last',a.params.id)}));
app.post('/api/classes/:id/members',need('admin'),wrap(a=>run('INSERT OR IGNORE INTO members VALUES(?,?)',a.params.id,a.body.user_id)));
app.delete('/api/classes/:id/members/:uid',need('admin'),wrap(a=>run('DELETE FROM members WHERE class_id=? AND user_id=?',a.params.id,a.params.uid)));

app.get('/api/lessons',need('admin','director','teacher','student'),wrap(a=>{
 const B="SELECT l.*,c.name cls,u.first||' '||u.last teacher FROM lessons l JOIN classes c ON c.id=l.class_id JOIN users u ON u.id=l.teacher_id";
 if(staff(a.u))return q(B+' ORDER BY weekday,start');
 if(a.u.role=='teacher')return q(B+' WHERE l.teacher_id=? ORDER BY weekday,start',a.u.id);
 return q(B+' WHERE l.class_id IN (SELECT class_id FROM members WHERE user_id=?) ORDER BY weekday,start',a.u.id)}));
app.post('/api/lessons',need('admin'),wrap(a=>{const d=a.body;run('INSERT INTO lessons(class_id,teacher_id,subject,weekday,start,end) VALUES(?,?,?,?,?,?)',d.class_id,d.teacher_id,d.subject,d.weekday,d.start,d.end)}));
app.delete('/api/lessons/:id',need('admin'),wrap(a=>run('DELETE FROM lessons WHERE id=?',a.params.id)));

app.get('/api/grades',need('admin','teacher','student'),wrap(a=>{const{class_id,subject,date}=a.query;
 if(a.u.role=='student')return q('SELECT * FROM grades WHERE student_id=? ORDER BY date DESC',a.u.id);
 if(!inCls(a.u,class_id))throw new Error('no');return q('SELECT * FROM grades WHERE class_id=? AND subject=? AND date=?',class_id,subject,date)}));
app.post('/api/grades',need('admin','teacher'),wrap(a=>{const d=a.body;if(!inCls(a.u,d.class_id))throw new Error('no');
 if(!d.grade)run('DELETE FROM grades WHERE student_id=? AND subject=? AND date=?',d.student_id,d.subject,d.date);
 else run('INSERT INTO grades(class_id,student_id,teacher_id,subject,date,grade) VALUES(?,?,?,?,?,?) ON CONFLICT(student_id,subject,date) DO UPDATE SET grade=excluded.grade,teacher_id=excluded.teacher_id',d.class_id,d.student_id,a.u.id,d.subject,d.date,d.grade)}));

app.get('/api/chat/:c',wrap(a=>{if(!inCls(a.u,a.params.c))throw new Error('no');return q('SELECT m.id,m.text,m.ts,u.first,u.last,u.role FROM messages m JOIN users u ON u.id=m.user_id WHERE m.class_id=? AND m.id>? ORDER BY m.id DESC LIMIT 100',a.params.c,a.query.after||0).reverse()}));
app.post('/api/chat/:c',wrap(a=>{if(!inCls(a.u,a.params.c)||!a.body.text)throw new Error('no');run('INSERT INTO messages(class_id,user_id,text,ts) VALUES(?,?,?,?)',a.params.c,a.u.id,String(a.body.text).slice(0,1000),Date.now())}));

app.post('/api/scan',need('scanner'),(a,b)=>{const u=one('SELECT id,first,last,role FROM users WHERE code=?',a.body.code);if(!u)return b.sendStatus(404);run('INSERT INTO scans(scanner_id,target_id,ts) VALUES(?,?,?)',a.u.id,u.id,Date.now());b.json(u)});
app.get('/api/scans',need('admin'),wrap(()=>q('SELECT s.ts,sc.login scanner,t.first,t.last FROM scans s LEFT JOIN users sc ON sc.id=s.scanner_id LEFT JOIN users t ON t.id=s.target_id ORDER BY s.id DESC LIMIT 200')));

app.listen(process.env.PORT||3000,()=>console.log('School app on :'+(process.env.PORT||3000)));
