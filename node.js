
// const express = require('express');
// const rateLimit = require('express-rate-limit');
// const Web3 = require('web3');
// const jwt = require('jsonwebtoken');
// const dotenv = require('dotenv');
// const cors = require('cors');

// // Initialize app
// const app = express();
// const PORT = process.env.PORT || 3000;
// require("dotenv").config(); // Load environment variables
// const web3 = new Web3(process.env.ALCHEMY_SEPOLIA_RPC_URL);

// // Load environment variables
// dotenv.config();

// // Validate required env vars
// const requiredEnvVars = ['ALCHEMY_SEPOLIA_RPC_URL', 'BLOCKCHAIN_RPC_URL', 'JWT_SECRET'];
// for (const envVar of requiredEnvVars) {
//   if (!process.env[envVar]) {
//     console.error(`Missing required environment variable: ${envVar}`);
//     process.exit(1);
//   }
// }

// // Middleware
// app.use(express.json());
// app.use(cors());

// // Initialize Web3 instances
// const sepoliaWeb3 = new Web3(new Web3.providers.HttpProvider(process.env.ALCHEMY_SEPOLIA_RPC_URL));
// const mainnetWeb3 = new Web3(new Web3.providers.HttpProvider(process.env.BLOCKCHAIN_RPC_URL));

// app.get('/blockchain-info', async (req, res) => {
//     try {
//         const blockNumber = await mainnetWeb3.eth.getBlockNumber();
//         res.json({ message: "Connected to Blockchain!", latestBlock: blockNumber });
//     } catch (error) {
//         res.status(500).json({ message: "Error connecting to blockchain", error: error.toString() });
//     }
// });

// // In-memory user store (replace with database in production)
// const users = {
//   'user1': { 
//     apiKey: process.env.DEFAULT_API_KEY || 'apikey123', 
//     wallet: process.env.DEFAULT_WALLET || '0x123...', 
//     tokens: 100 
//   }
// };

// // Contract details - replace with actual values
// const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || "0xf8DD6A6D30D46D9F945Cf0eDAc1A5594b2e5DaD5";
// const CONTRACT_ABI = require('./contractABI.json'); // Load from file
// const contract = new sepoliaWeb3.eth.Contract(CONTRACT_ABI, CONTRACT_ADDRESS);

// // ✅ Route to check token balance
// app.get("/balance/:address", async (req, res) => {
//     try {
//         const address = req.params.address;
//         const balance = await contract.methods.balanceOf(address).call();
//         res.json({ address, balance: sepoliaWeb3.utils.fromWei(balance, "ether") });
//     } catch (error) {
//         res.status(500).json({ error: error.message });
//     }
// });

// // Middleware to check API key and token balance
// const tokenMiddleware = async (req, res, next) => {
//   const apiKey = req.headers['x-api-key'];
//   if (!apiKey || !users[apiKey]) return res.status(401).json({ error: 'Invalid API Key' });

//   const user = users[apiKey];
//   const tokenBalance = await getTokenBalance(user.wallet);
//   if (tokenBalance <= 0) return res.status(403).json({ error: 'Insufficient Tokens' });

//   req.user = user;
//   next();
// };

// // Function to get token balance (simulate blockchain call)
// const getTokenBalance = async (wallet) => {
//   try {
//     if (!sepoliaWeb3.utils.isAddress(wallet)) {
//       throw new Error('Invalid wallet address');
//     }
//     const balance = await contract.methods.balanceOf(wallet).call();
//     return sepoliaWeb3.utils.fromWei(balance, "ether");
//   } catch (error) {
//     console.error('Error getting token balance:', error);
//     return 0;
//   }
// };

// // Apply rate limiting using express-rate-limit
// const apiLimiter = rateLimit({
//   windowMs: 60 * 1000, // 1 minute
//   max: 10, // Limit each API key to 10 requests per minute
//   message: { error: 'Rate limit exceeded' },
// });

// app.get('/', (req, res) => {
//   res.json({ message: "Server is running and rate limiting is active!" });
// });

// // Protected API route
// app.get('/data', tokenMiddleware, apiLimiter, (req, res) => {
//   users[req.user.apiKey].tokens -= 1; // Deduct a token per request
//   res.json({ data: 'Protected API response', remainingTokens: users[req.user.apiKey].tokens });
// });

// // Endpoint for users to check their token balance
// app.get('/balance', tokenMiddleware, async (req, res) => {
//   const tokenBalance = await getTokenBalance(req.user.wallet);
//   res.json({ wallet: req.user.wallet, tokens: tokenBalance });
// });
// const rateLimitMiddleware = async (req, res, next) => {
//   const userAddress = req.query.address;
//   if (!userAddress) return res.status(400).json({ error: "Missing address" });

//   try {
//       const balance = await contract.methods.balanceOf(userAddress).call();
//       console.log(`User Balance: ${balance}`);

//       if (web3.utils.fromWei(balance, "ether") < 1) {
//           return res.status(403).json({ error: "Insufficient tokens for API access" });
//       }

//       next(); // If the user has enough tokens, proceed to the API
//   } catch (error) {
//       res.status(500).json({ error: error.message });
//   }
// };

// app.get("/protected-api", rateLimitMiddleware, (req, res) => {
//   res.json({ message: "Access granted! You have enough tokens." });
// });

// // Start server
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });
// app.post("/request-access", async (req, res) => {
//   const { address } = req.body; // Get wallet address from request

//   if (!address) return res.status(400).json({ error: "Missing wallet address" });

//   if (!ethers.utils.isAddress(address)) {
//       return res.status(400).json({ error: "Invalid Ethereum address" });
//   }

//   try {
//       const gasEstimate = await contract.methods.requestAccess().estimateGas({
//           from: address,
//       });

//       const tx = await contract.methods.requestAccess().send({
//           from: address,
//           gas: gasEstimate,
//       });

//       res.json({ message: "Access granted! Tokens deducted.", transaction: tx.transactionHash });
//   } catch (error) {
//       res.status(500).json({ error: error.message });
//   }
// });



// const express = require('express');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const { Pool } = require('pg');
// const dotenv = require('dotenv');

// dotenv.config();
// const app = express();
// const PORT = process.env.PORT || 3000;

// // PostgreSQL Connection
// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
// });

// app.use(express.json());

// // User Registration
// app.post('/register', async (req, res) => {
//   const { username, password } = req.body;
//   const hashedPassword = await bcrypt.hash(password, 10);

//   try {
//     const result = await pool.query(
//       'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
//       [username, hashedPassword]
//     );
//     res.status(201).json({ message: 'User registered!', userId: result.rows[0].id });
//   } catch (error) {
//     res.status(500).json({ error: 'Error registering user' });
//   }
// });

// // User Login
// app.post('/login', async (req, res) => {
//   const { username, password } = req.body;

//   try {
//     const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
//     if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

//     const user = result.rows[0];
//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
//     res.json({ message: 'Login successful', token });
//   } catch (error) {
//     res.status(500).json({ error: 'Error logging in' });
//   }
// });

// // Secure API Route
// app.get('/protected-api', async (req, res) => {
//   const authHeader = req.headers.authorization;
//   if (!authHeader) return res.status(401).json({ error: 'Missing token' });

//   try {
//     const token = authHeader.split(' ')[1];
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     res.json({ message: 'Access granted!', userId: decoded.userId });
//   } catch (error) {
//     res.status(403).json({ error: 'Invalid token' });
//   }
// });

// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.log("MongoDB error:", err));

  
// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});
const User = mongoose.model('User', userSchema);

// Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered!' });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Protected Route
app.get('/protected-api', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ message: 'Access granted!', userId: decoded.userId });
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
