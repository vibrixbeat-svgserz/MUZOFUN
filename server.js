const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_MUZOFUN_SECRET';
const DATA_DIR = process.env.DATA_DIR || '/data';
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const LOCAL_UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
const finalUploadDir = (() => { try { fs.mkdirSync(UPLOAD_DIR,{recursive:true}); fs.accessSync(UPLOAD_DIR,fs.constants.W_OK); return UPLOAD_DIR; } catch { fs.mkdirSync(LOCAL_UPLOAD_DIR,{recursive:true}); return LOCAL_UPLOAD_DIR; }})();
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(finalUploadDir,{recursive:true});

app.set('trust proxy', 1);
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true,limit:'1mb'}));

const pool = process.env.DATABASE_URL ? new Pool({connectionString:process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : {rejectUnauthorized:false}}) : null;
let dbReady = false;

async function initDb(){
  if(!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(80) NOT NULL,
      avatar_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tracks (
      id UUID PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(160) NOT NULL,
      artist VARCHAR(160) NOT NULL,
      genre VARCHAR(60) NOT NULL DEFAULT 'Other',
      description TEXT NOT NULL DEFAULT '',
      audio_url TEXT NOT NULL,
      cover_url TEXT,
      plays BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS likes (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      track_id UUID NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(user_id, track_id)
    );
    CREATE TABLE IF NOT EXISTS playlists (
      id UUID PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(120) NOT NULL,
      is_public BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS playlist_tracks (
      playlist_id UUID NOT NULL REFERENCES playlists(id) ON DELETE CASCADE,
      track_id UUID NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
      position INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(playlist_id, track_id)
    );
    CREATE INDEX IF NOT EXISTS tracks_created_idx ON tracks(created_at DESC);
    CREATE INDEX IF NOT EXISTS tracks_plays_idx ON tracks(plays DESC);
  `);
  dbReady = true;
}

function requireDb(req,res,next){ if(!dbReady) return res.status(503).json({error:'База данных не подключена. Добавь PostgreSQL в Railway.'}); next(); }
function tokenFor(user){ return jwt.sign({id:String(user.id),username:user.username}, JWT_SECRET, {expiresIn:'30d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const token=h.startsWith('Bearer ')?h.slice(7):null;
  if(!token) return res.status(401).json({error:'Требуется вход'});
  try { req.user=jwt.verify(token,JWT_SECRET); next(); } catch { return res.status(401).json({error:'Сессия истекла'}); }
}
function safeName(name){ return String(name||'file').replace(/[^a-zA-Z0-9._-]/g,'_').slice(-100); }
const audioExt = new Set(['.mp3','.m4a','.aac','.wav','.ogg','.oga','.flac','.webm']);
const imageExt = new Set(['.jpg','.jpeg','.png','.webp']);
const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,finalUploadDir),filename:(req,file,cb)=>cb(null,`${crypto.randomUUID()}-${safeName(file.originalname)}`)});
const upload=multer({storage,limits:{fileSize:100*1024*1024},fileFilter:(req,file,cb)=>{
  const ext=path.extname(file.originalname).toLowerCase();
  if(file.fieldname==='audio' && audioExt.has(ext)) return cb(null,true);
  if(file.fieldname==='cover' && imageExt.has(ext)) return cb(null,true);
  cb(new Error('Неподдерживаемый формат файла'));
}});

app.get('/api/health', async (req,res)=>res.json({ok:true,app:'MUZOFUN',version:'2.0.0-real',database:!!dbReady,storage:finalUploadDir}));
app.get('/api/me', requireDb, auth, async (req,res)=>{
  const {rows}=await pool.query('SELECT id,username,display_name,avatar_url,created_at FROM users WHERE id=$1',[req.user.id]);
  if(!rows[0]) return res.status(404).json({error:'Пользователь не найден'}); res.json({user:rows[0]});
});
app.post('/api/auth/register', requireDb, async(req,res)=>{
  const username=String(req.body.username||'').trim().toLowerCase(); const password=String(req.body.password||''); const displayName=String(req.body.displayName||username).trim().slice(0,80);
  if(!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({error:'Логин: 3–32 символа, только латиница, цифры и _'});
  if(password.length<8) return res.status(400).json({error:'Пароль минимум 8 символов'});
  try{const hash=await bcrypt.hash(password,12); const {rows}=await pool.query('INSERT INTO users(username,password_hash,display_name) VALUES($1,$2,$3) RETURNING id,username,display_name',[username,hash,displayName||username]); res.json({token:tokenFor(rows[0]),user:rows[0]});}
  catch(e){if(e.code==='23505') return res.status(409).json({error:'Такой пользователь уже существует'}); console.error(e); res.status(500).json({error:'Ошибка регистрации'});}
});
app.post('/api/auth/login', requireDb, async(req,res)=>{
  const username=String(req.body.username||'').trim().toLowerCase(); const password=String(req.body.password||'');
  const {rows}=await pool.query('SELECT id,username,display_name,password_hash,avatar_url FROM users WHERE username=$1',[username]); const u=rows[0];
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Неверный логин или пароль'});
  delete u.password_hash; res.json({token:tokenFor(u),user:u});
});
app.get('/api/tracks', async(req,res)=>{
  if(!dbReady) return res.json({tracks:[]});
  const q=String(req.query.q||'').trim(); const sort=String(req.query.sort||'new'); const userId=req.user?.id||null;
  const order=sort==='top'?'t.plays DESC, t.created_at DESC':sort==='likes'?'like_count DESC, t.created_at DESC':'t.created_at DESC';
  const params=[]; let where=''; if(q){params.push('%'+q+'%'); where=`WHERE t.title ILIKE $1 OR t.artist ILIKE $1 OR t.genre ILIKE $1 OR u.username ILIKE $1`;}
  const sql=`SELECT t.id,t.title,t.artist,t.genre,t.description,t.audio_url,t.cover_url,t.plays,t.created_at,u.username,u.display_name,
    COUNT(DISTINCT l.user_id)::int AS like_count ${userId?' ,EXISTS(SELECT 1 FROM likes ml WHERE ml.track_id=t.id AND ml.user_id=$'+(params.length+1)+') AS liked':''}
    FROM tracks t JOIN users u ON u.id=t.user_id LEFT JOIN likes l ON l.track_id=t.id ${where} GROUP BY t.id,u.id ORDER BY ${order} LIMIT 100`;
  if(userId) params.push(userId); const {rows}=await pool.query(sql,params); res.json({tracks:rows});
});
app.post('/api/tracks', requireDb, auth, upload.fields([{name:'audio',maxCount:1},{name:'cover',maxCount:1}]), async(req,res)=>{
  try{
    const audio=req.files?.audio?.[0]; const cover=req.files?.cover?.[0]; if(!audio) return res.status(400).json({error:'Добавь аудиофайл'});
    const ext=path.extname(audio.filename).toLowerCase(); const title=String(req.body.title||'').trim().slice(0,160); const artist=String(req.body.artist||'').trim().slice(0,160); const genre=String(req.body.genre||'Other').trim().slice(0,60); const description=String(req.body.description||'').trim().slice(0,2000);
    if(!title||!artist) return res.status(400).json({error:'Название и исполнитель обязательны'});
    const id=crypto.randomUUID(); const audioUrl='/uploads/'+encodeURIComponent(audio.filename); const coverUrl=cover?'/uploads/'+encodeURIComponent(cover.filename):null;
    const {rows}=await pool.query(`INSERT INTO tracks(id,user_id,title,artist,genre,description,audio_url,cover_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[id,req.user.id,title,artist,genre,description,audioUrl,coverUrl]); res.status(201).json({track:rows[0]});
  }catch(e){console.error(e); res.status(500).json({error:'Не удалось опубликовать трек'});}
});
app.post('/api/tracks/:id/play', async(req,res)=>{if(!dbReady) return res.status(503).json({error:'База данных не подключена'}); await pool.query('UPDATE tracks SET plays=plays+1 WHERE id=$1',[req.params.id]); res.json({ok:true});});
app.post('/api/tracks/:id/like', requireDb, auth, async(req,res)=>{try{const id=req.params.id; const ex=await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND track_id=$2',[req.user.id,id]); if(ex.rowCount) await pool.query('DELETE FROM likes WHERE user_id=$1 AND track_id=$2',[req.user.id,id]); else await pool.query('INSERT INTO likes(user_id,track_id) VALUES($1,$2)',[req.user.id,id]); const c=await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE track_id=$1',[id]); res.json({liked:!ex.rowCount,like_count:c.rows[0].count});}catch(e){res.status(400).json({error:'Не удалось изменить лайк'});}});
app.get('/api/library', requireDb, auth, async(req,res)=>{const [tracks,playlists]=await Promise.all([pool.query(`SELECT t.*,COUNT(l.user_id)::int like_count FROM tracks t LEFT JOIN likes l ON l.track_id=t.id WHERE t.user_id=$1 GROUP BY t.id ORDER BY t.created_at DESC`,[req.user.id]),pool.query('SELECT * FROM playlists WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id])]);res.json({tracks:tracks.rows,playlists:playlists.rows});});
app.post('/api/playlists', requireDb, auth, async(req,res)=>{const name=String(req.body.name||'').trim().slice(0,120);if(!name)return res.status(400).json({error:'Введите название'});const {rows}=await pool.query('INSERT INTO playlists(id,user_id,name) VALUES($1,$2,$3) RETURNING *',[crypto.randomUUID(),req.user.id,name]);res.json({playlist:rows[0]});});
app.post('/api/playlists/:id/tracks/:trackId', requireDb, auth, async(req,res)=>{const p=await pool.query('SELECT id FROM playlists WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);if(!p.rowCount)return res.status(404).json({error:'Плейлист не найден'});await pool.query('INSERT INTO playlist_tracks(playlist_id,track_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.params.id,req.params.trackId]);res.json({ok:true});});
app.get('/uploads/:file', (req,res)=>{const file=path.basename(req.params.file);const p=path.join(finalUploadDir,file);if(!p.startsWith(finalUploadDir+path.sep))return res.sendStatus(400);if(!fs.existsSync(p))return res.sendStatus(404);res.sendFile(p);});

app.use(express.static(PUBLIC_DIR,{extensions:['html']}));
app.get('*',(req,res)=>res.sendFile(path.join(PUBLIC_DIR,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||'Ошибка запроса'});});

initDb().then(()=>{if(pool) console.log('PostgreSQL: connected'); else console.log('PostgreSQL: not configured'); app.listen(PORT,HOST,()=>console.log(`MUZOFUN listening on ${HOST}:${PORT}`));}).catch(e=>{console.error('Database init failed:',e);app.listen(PORT,HOST,()=>console.log(`MUZOFUN listening on ${HOST}:${PORT} (DB unavailable)`));});
