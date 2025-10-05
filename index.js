
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { nanoid } = require('nanoid');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const fs = require('fs');

const app = express();
app.use(helmet());
app.use(bodyParser.json());
app.use(cors());

// rate limiter
app.use(rateLimit({ windowMs: 60*1000, max: 120 }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin_dev_token';
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';
if(!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// multer storage for uploads
const storage = multer.diskStorage({
  destination: (req,file,cb) => cb(null, UPLOAD_DIR),
  filename: (req,file,cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// MongoDB connect
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oosb_db';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('MongoDB connected'))
  .catch(e=>console.error('MongoDB connection error', e));

// Schemas
const UserSchema = new mongoose.Schema({ id:String, email:String, password:String, createdAt:{type:Date,default:Date.now} });
const BalanceSchema = new mongoose.Schema({ userId:String, balance:{ type:Number, default:0 } });
const OrderSchema = new mongoose.Schema({
  id:String, userId:String, link:String, platform:String, qty:Number, pricePer:Number, subtotal:Number,
  status:{ type:String, default:'pending' }, paid:{ type:Boolean, default:false }, createdAt:{type:Date,default:Date.now},
  approvedAt:Date, deliveredAt:Date, proofFiles:[String]
});
const PaymentProofSchema = new mongoose.Schema({ id:String, userId:String, amount:Number, files:[String], createdAt:{type:Date,default:Date.now}, verified:{type:Boolean,default:false} });

const User = mongoose.model('User', UserSchema);
const Balance = mongoose.model('Balance', BalanceSchema);
const Order = mongoose.model('Order', OrderSchema);
const PaymentProof = mongoose.model('PaymentProof', PaymentProofSchema);

// helpers
function authMiddleware(req,res,next){
  const auth = req.headers.authorization; if(!auth) return res.status(401).json({ error:'Missing token' });
  const parts = auth.split(' '); if(parts.length!==2) return res.status(401).json({ error:'Invalid auth header' });
  const token = parts[1];
  try{ const payload = jwt.verify(token, JWT_SECRET); req.user = payload; next(); } catch(e){ return res.status(401).json({ error:'Invalid token' }); }
}
function adminAuth(req,res,next){ const header = req.headers['x-admin-token'] || ''; if(header !== ADMIN_TOKEN) return res.status(403).json({ error:'Forbidden' }); next(); }

// root
app.get('/', (req,res) => res.json({ ok:true, msg:'OOSB SOCIALS backend' }));

// register
app.post('/api/register', [
  body('email').isEmail(), body('password').isLength({ min:6 })
], async (req,res)=>{
  const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error: errors.array() });
  const { email, password } = req.body;
  const exists = await User.findOne({ email });
  if(exists) return res.status(400).json({ error:'User exists' });
  const id = nanoid();
  const hash = bcrypt.hashSync(password, 8);
  await User.create({ id, email, password: hash });
  await Balance.create({ userId: id, balance: 0 });
  res.json({ ok:true });
});

// login
app.post('/api/login', [
  body('email').isEmail(), body('password').exists()
], async (req,res)=>{
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if(!user) return res.status(400).json({ error:'Invalid credentials' });
  if(!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// me
app.get('/api/me', authMiddleware, async (req,res)=>{
  const user = await User.findOne({ id: req.user.id });
  if(!user) return res.status(404).json({ error:'User not found' });
  const balance = await Balance.findOne({ userId: req.user.id });
  const orders = await Order.find({ userId: req.user.id }).sort({ createdAt:-1 });
  res.json({ email: user.email, id: user.id, balance: balance?balance.balance:0, orders });
});

// create order
app.post('/api/order', authMiddleware, [
  body('link').isLength({ min:3 }),
  body('platform').isIn(['instagram','facebook','twitter','tiktok','youtube']),
  body('qty').isInt({ min:10 }),
  body('price_per').isFloat({ min:1 })
], async (req,res)=>{
  const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error: errors.array() });
  const { link, platform, qty, price_per } = req.body;
  const id = nanoid();
  const subtotal = Number(qty) * Number(price_per);
  await Order.create({ id, userId: req.user.id, link, platform, qty, pricePer: price_per, subtotal, status:'pending' });
  res.json({ ok:true, id, subtotal, message:'Order created. Fund your account to process.' });
});

// paystack initialize (placeholder) - replace with real API call in production
app.post('/api/paystack/init', authMiddleware, [ body('amount').isInt({ min:100 }), body('email').isEmail() ], async (req,res)=>{
  const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';
  if(!PAYSTACK_SECRET) return res.status(500).json({ error:'Paystack not configured' });
  const reference = 'ps_' + nanoid();
  const authorization_url = 'https://paystack.com/pay/demo_' + reference;
  res.json({ reference, authorization_url, message:'Prototype: replace with live Paystack initialize call' });
});

// manual bank transfer: upload proof files
app.post('/api/fund/proof', authMiddleware, upload.array('files', 5), async (req,res)=>{
  const amount = Number(req.body.amount) || 0;
  const files = (req.files || []).map(f => f.filename);
  const id = nanoid();
  await PaymentProof.create({ id, userId: req.user.id, amount, files, verified:false });
  res.json({ ok:true, id, files, message:'Proof uploaded. Billing team will verify.' });
});

// admin: list proofs and verify (credits user)
app.get('/api/admin/proofs', adminAuth, async (req,res)=>{
  const proofs = await PaymentProof.find().sort({ createdAt:-1 });
  res.json({ proofs });
});
app.post('/api/admin/proof/:id/verify', adminAuth, async (req,res)=>{
  const id = req.params.id;
  const proof = await PaymentProof.findOne({ id });
  if(!proof) return res.status(404).json({ error:'Not found' });
  if(proof.verified) return res.json({ ok:true, message:'Already verified' });
  const bal = await Balance.findOne({ userId: proof.userId });
  if(bal){ bal.balance = Number(bal.balance) + Number(proof.amount); await bal.save(); }
  proof.verified = true; await proof.save();
  res.json({ ok:true, message:'Proof verified and wallet credited.' });
});

// admin: orders list & approve
app.get('/api/admin/orders', adminAuth, async (req,res)=>{
  const orders = await Order.find().sort({ createdAt:-1 });
  res.json({ orders });
});
app.post('/api/admin/order/:id/approve', adminAuth, async (req,res)=>{
  const id = req.params.id;
  const order = await Order.findOne({ id });
  if(!order) return res.status(404).json({ error:'Not found' });
  order.status = 'approved'; order.approvedAt = new Date(); await order.save();
  res.json({ ok:true, order });
});

// serve uploaded proofs
app.use('/uploads', express.static(path.join(__dirname, UPLOAD_DIR)));

// webhooks (placeholders)
app.post('/api/webhook/paystack', express.json({ type: '*/*' }), async (req,res)=>{
  console.log('Paystack webhook (prototype):', req.body);
  res.json({ ok:true });
});
app.post('/api/webhook/flutterwave', express.json({ type: '*/*' }), async (req,res)=>{
  console.log('Flutterwave webhook (prototype):', req.body);
  res.json({ ok:true });
});

app.listen(PORT, ()=> console.log('Server running on port', PORT));
