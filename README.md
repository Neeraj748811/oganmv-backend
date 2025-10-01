# oganmv-backend
oganmv-backend/
├── config/
│   └── // config/db.js
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      // options not required for modern mongoose but safe
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    process.exit(1);
  }
};

module.exports = connectDB;

├── middleware/
│   └── // middleware/auth.js
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const auth = async (req, res, next) => {
  try {
    const header = req.header("Authorization");
    if (!header) return res.status(401).json({ message: "No authorization header" });
    const token = header.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (!user) return res.status(401).json({ message: "Invalid token / user not found" });

    req.user = user; // attach user doc
    next();
  } catch (err) {
    console.error("Auth error:", err.message);
    return res.status(401).json({ message: "Authentication failed" });
  }
};

module.exports = auth;

├── models/
│   ├── // models/User.js
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  // optional measurements saved for the user
  measurements: {
    size: { type: Number, default: 1 },
    width: { type: Number, default: 1 },
    height: { type: Number, default: 1 },
    sleeve: { type: Number, default: 1 }
  }
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);

│   ├──// models/Clothing.js
const mongoose = require("mongoose");

const ClothingSchema = new mongoose.Schema({
  name: { type: String, required: true },
  modelPath: { type: String, required: true }, // ex: /models/clothing/tshirt.glb (served by frontend/public)
  price: { type: Number, default: 0 },
  category: { type: String, default: "uncategorized" },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Clothing", ClothingSchema);

│   └── // models/CartItem.js
const mongoose = require("mongoose");

const CartItemSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  clothingId: { type: mongoose.Schema.Types.ObjectId, ref: "Clothing", required: true },
  quantity: { type: Number, default: 1 },
  size: { type: Number, default: 1 },
  addedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("CartItem", CartItemSchema);

├── routes/
│   ├──// routes/auth.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const router = express.Router();

// Helper to sign token
const signToken = (userId) => jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "1d" });

// REGISTER (also expose /signup alias)
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    const token = signToken(user._id);
    res.json({ user: { _id: user._id, name: user.name, email: user.email }, token });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ message: "Registration failed" });
  }
});

// alias /signup -> same handler
router.post("/signup", (req, res) => {
  // delegate to /register logic by calling directly
  req.url = "/register";
  router.handle(req, res);
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    const token = signToken(user._id);
    res.json({ user: { _id: user._id, name: user.name, email: user.email, measurements: user.measurements }, token });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ message: "Login failed" });
  }
});

module.exports = router;

│   ├── // routes/clothing.js
const express = require("express");
const Clothing = require("../models/Clothing");
const router = express.Router();

// GET all
router.get("/", async (req, res) => {
  try {
    const items = await Clothing.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    console.error("Clothing fetch error:", err.message);
    res.status(500).json({ message: "Failed to fetch clothing" });
  }
});

module.exports = router;

│   └── // routes/cart.js
const express = require("express");
const CartItem = require("../models/CartItem");
const Clothing = require("../models/Clothing");
const auth = require("../middleware/auth");
const router = express.Router();

// Get cart items for logged-in user
router.get("/", auth, async (req, res) => {
  try {
    const items = await CartItem.find({ userId: req.user._id }).lean();
    // include clothing metadata
    const detailed = await Promise.all(items.map(async (it) => {
      const clothing = await Clothing.findById(it.clothingId).lean();
      return {
        _id: it._id,
        clothingId: it.clothingId,
        clothingName: clothing?.name || "Unknown",
        clothingModelPath: clothing?.modelPath || null,
        quantity: it.quantity,
        size: it.size
      };
    }));
    res.json(detailed);
  } catch (err) {
    console.error("Cart fetch error:", err.message);
    res.status(500).json({ message: "Failed to fetch cart" });
  }
});

// Add to cart
router.post("/add", auth, async (req, res) => {
  try {
    const { clothingId, quantity = 1, size = 1 } = req.body;
    if (!clothingId) return res.status(400).json({ message: "Missing clothingId" });
    // If the same clothingId exists for user, increment quantity
    let item = await CartItem.findOne({ userId: req.user._id, clothingId });
    if (item) {
      item.quantity += Number(quantity);
      item.size = size; // update size to latest
      await item.save();
    } else {
      item = await CartItem.create({ userId: req.user._id, clothingId, quantity, size });
    }
    res.json({ message: "Added to cart" });
  } catch (err) {
    console.error("Cart add error:", err.message);
    res.status(500).json({ message: "Failed to add to cart" });
  }
});

// Checkout - clears the user's cart
router.post("/checkout", auth, async (req, res) => {
  try {
    await CartItem.deleteMany({ userId: req.user._id });
    res.json({ message: "Checkout successful" });
  } catch (err) {
    console.error("Checkout error:", err.message);
    res.status(500).json({ message: "Checkout failed" });
  }
});

module.exports = router;

├── // seed.js
require("dotenv").config();
const connectDB = require("./config/db");
const Clothing = require("./models/Clothing");

const data = [
  { name: "T-Shirt (Basic)", modelPath: "/models/clothing/tshirt.glb", price: 199 },
  { name: "Light Jacket", modelPath: "/models/clothing/jacket.glb", price: 499 },
];

const seed = async () => {
  try {
    await connectDB();
    await Clothing.deleteMany({});
    await Clothing.insertMany(data);
    console.log("Seeded clothing items");
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

seed();

├── // server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const clothingRoutes = require("./routes/clothing");
const cartRoutes = require("./routes/cart");
const path = require("path");

const app = express();
connectDB();

app.use(cors());
app.use(express.json());

// If you want to serve static 3D models from backend (optional):
// place GLB files in backend/public/models/... and uncomment:
// app.use("/models", express.static(path.join(__dirname, "public/models")));

app.use("/api/auth", authRoutes);
app.use("/api/clothing", clothingRoutes);
app.use("/api/cart", cartRoutes);

// health
app.get("/", (req, res) => res.send("OganMV backend is running"));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));

├── PORT=5000
MONGO_URI=mongodb://127.0.0.1:27017/oganmv
JWT_SECRET=replace_with_a_strong_secret

└──{
  "name": "oganmv-backend",
  "version": "1.0.0",
  "private": true,
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "seed": "node seed.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.0",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.0.0"
  }
}
 env examples curl -X POST http://localhost:5000/api/auth/register -H "Content-Type: application/json" -d '{"name":"Alice","email":"alice@example.com","password":"pass123"}'
curl -X POST http://localhost:5000/api/auth/login -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"pass123"}'
curl http://localhost:5000/api/clothing
curl -X POST http://localhost:5000/api/cart/add -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" -d '{"clothingId":"<id_from_clothing>","quantity":1,"size":1.1}'
curl -H "Authorization: Bearer TOKEN" http://localhost:5000/api/cart
curl -X POST -H "Authorization: Bearer TOKEN" http://localhost:5000/api/cart/checkout

