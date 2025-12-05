// server.ts
import express from "express";
import cors from "cors";
import multer from "multer";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import { registerDynamicAsset } from "./scripts/registration/registerDynamic";
import { account, client} from './utils/config' // Story SDK client
import { WIP_TOKEN_ADDRESS } from "@story-protocol/core-sdk";
import type { TokenAmountInput } from '@story-protocol/core-sdk'
import { ethers } from "ethers";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "*",
    credentials: true,
  })
);

app.use(express.json());

// JWT secret (set in .env)
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Sepolia ETH provider & wallet
const sepProvider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const sepWallet = new ethers.Wallet(process.env.WALLET_PRIVATE_KEY!, sepProvider);

// ERC20 ABI for token transfers if needed
const ERC20_ABI = [
  "function transfer(address to, uint256 amount) public returns (bool)"
];
// Converts a decimal number (ETH or token amount) to BigInt in smallest unit
function toWei(amount: number | string) {
  return ethers.parseEther(amount.toString()); // for ETH (18 decimals)
}

// For ERC20 tokens with custom decimals:
function toTokenUnits(amount: number | string, decimals: number = 18) {
  return BigInt(Math.floor(Number(amount) * 10 ** decimals));
}
// Initialize SQLite
const dbPath = process.env.DB_PATH || "./database.db";
const db = new Database(dbPath);


// ---------------------- Database Setup ----------------------

// Users table
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  wallet_address TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).run();

// Assets table
db.prepare(`
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  ipfs_metadata TEXT,
  nft_metadata TEXT,
  tx_hash TEXT,
  ip_id TEXT,
  license_terms TEXT,
  totalShares INTEGER DEFAULT 100000,
  creatorShares INTEGER DEFAULT 100000,
  investors TEXT DEFAULT '[]',
  revenueEarned TEXT DEFAULT '{}',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`).run();

// License marketplace
db.prepare(`
CREATE TABLE IF NOT EXISTS license_listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_id TEXT NOT NULL,
  price INTEGER NOT NULL,
  creator_wallet TEXT NOT NULL,
  active BOOLEAN DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).run();

db.prepare(` CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_id TEXT,
  listing_id INTEGER,
  from_wallet TEXT,
  to_wallet TEXT,
  amount INTEGER,
  token TEXT DEFAULT 'ETH',
  tx_hash TEXT,
  claimed BOOLEAN DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS owned_licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_id TEXT,
  listing_id INTEGER,
  buyer_wallet TEXT,
  license_metadata TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).run();
// Fix BigInt serialization
// Recursively converts all BigInt values to strings
function serialize(obj: any): any {
  if (obj === null || obj === undefined) return null;

  if (typeof obj === "bigint") {
    return obj.toString();
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => serialize(item));
  }

  if (typeof obj === "object") {
    const res: any = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        res[key] = serialize(obj[key]);
      }
    }
    return res;
  }

  // primitive (string, number, boolean)
  return obj;
}


// Multer setup
const upload = multer({ storage: multer.memoryStorage() });

// ---------------------- Auth Helpers ----------------------

// Generate JWT
function generateToken(user: any) {
  return jwt.sign({ id: user.id, wallet: user.wallet_address }, JWT_SECRET, { expiresIn: "7d" });
}

// Verify JWT
function authMiddleware(req: any, res: any, next: any) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.id);
    if (!user) return res.status(401).json({ error: "Invalid token" });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ---------------------- Auth Routes ----------------------

// Signup

app.post("/signup", async (req, res) => {
  const { name, email, walletAddress, password } = req.body;
  if (!name || !email || !walletAddress || !password) 
    return res.status(400).json({ error: "Missing fields" });

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = db.prepare(`
      INSERT INTO users (name, email, wallet_address, password)
      VALUES (?, ?, ?, ?)
    `).run(name, email, walletAddress, hashedPassword);

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    const token = generateToken(user);
    res.json({ success: true, user, token });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});


// Login
app.post("/login", async (req, res) => {
  const { walletAddress, password } = req.body;
  if (!walletAddress || !password) return res.status(400).json({ error: "Missing fields" });

  const user = db.prepare("SELECT * FROM users WHERE wallet_address = ?").get(walletAddress);
  if (!user) return res.status(404).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: "Incorrect password" });

  const token = generateToken(user);
  res.json({ success: true, user, token });
});


// ---------------------- Asset Registration ----------------------
// ---------------------- Asset Registration ----------------------
app.post(
  "/register",
  authMiddleware,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "media", maxCount: 1 },
  ]),
  async (req: any, res) => {
    try {
      const imageFile = req.files?.image?.[0];
      const mediaFile = req.files?.media?.[0];

      // Metadata for the asset
      const metadata = {
        title: req.body.title,
        description: req.body.description,
        creatorName: req.user.name,
        creatorWallet: req.user.wallet_address,
      };

      // License options (must match SDK type)
      const licenseOptions = {
        commercialAllowed: req.body.commercialAllowed === "true",
        remixAllowed: req.body.remixAllowed === "true",
        aiTrainingAllowed: req.body.aiTrainingAllowed === "true",
        revShare: Number(req.body.revShare || 0),
        maxLicenses: Number(req.body.maxLicenses || 0),
      };

      // Investors (for fractional ownership, stored in DB)
      const investors = req.body.investors
        ? JSON.parse(req.body.investors)
        : [];

      // 1️⃣ Register asset via Story SDK
      const output = await registerDynamicAsset({
        metadata,
        licenseOptions, // investors should NOT be here
        imageFile,
        mediaFile,
      });
const licenseTermsSafe = serialize(output.licenseTerms);
      // 2️⃣ Save asset to DB
      db.prepare(`
        INSERT INTO assets (user_id, ipfs_metadata, nft_metadata, tx_hash, ip_id, license_terms, creatorShares, investors)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id,
        JSON.stringify({
          title: metadata.title,
          description: metadata.description,
          imageUrl: output.imageUrl || null,
          mediaUrl: output.mediaUrl || null,
          mediaFileName: mediaFile?.originalname || null, 
        }),
        JSON.stringify(metadata),
        output.txHash,
        output.ipId,
        JSON.stringify(licenseTermsSafe),
        100000, // default creator shares
        JSON.stringify(investors)
      );

      res.json(serialize({ success: true, data: output }));
    } catch (err: any) {
      console.error("Register API error:", err);
      res.status(500).json(serialize({ success: false, error: err.message }));
    }
  }
);

// ---------------------- Claim Revenue ----------------------
// ---------------------- Claim Revenue ----------------------
// ---------------------- Claim Revenue ----------------------
app.post("/claim", authMiddleware, async (req, res) => {
  const { ipId } = req.body;
  if (!ipId) return res.status(400).json({ error: "Missing ipId" });

  try {
    const asset = db.prepare(`SELECT * FROM assets WHERE ip_id = ?`).get(ipId);
    if (!asset) return res.status(404).json({ error: "Asset not found" });

    const nftMetadata = JSON.parse(asset.nft_metadata || "{}");
    const investors = JSON.parse(asset.investors || "[]");
    const totalShares = asset.totalShares;
    const creatorShares = asset.creatorShares;
    const creatorWallet = nftMetadata.creatorWallet || sepWallet.address;

    // 1️⃣ Pay WIP revenue from revenueEarned (if any)
    const revenueObj: Record<string, number> = JSON.parse(asset.revenueEarned || "{}");
    db.prepare(`UPDATE assets SET revenueEarned = '{}' WHERE ip_id = ?`).run(ipId);
    let totalWIP = BigInt(0);
    for (const val of Object.values(revenueObj)) {
      totalWIP += toTokenUnits(val);
    }

    if (totalWIP > BigInt(0)) {
      await client.royalty.payRoyaltyOnBehalf({
        receiverIpId: ipId as `0x${string}`,
        payerIpId: ipId as `0x${string}`,
        token: WIP_TOKEN_ADDRESS as `0x${string}`,
        amount: totalWIP.toString() as unknown as TokenAmountInput,
      });
    }

    // 2️⃣ Pay Sepolia ETH / other payments
    const payments = db.prepare(`SELECT * FROM payments WHERE ip_id = ? AND claimed = 0`).all(ipId);

    for (const payment of payments) {
      const token = payment.token || "SEPOLIA_ETH";
      const amount = token === "SEPOLIA_ETH"
        ? toWei(Number(payment.amount))
        : toTokenUnits(Number(payment.amount));

      // Creator share
      const creatorAmount = (amount * BigInt(creatorShares)) / BigInt(totalShares);
      if (creatorAmount > BigInt(0)) {
        if (token === "SEPOLIA_ETH") {
          const tx = await sepWallet.sendTransaction({
            to: creatorWallet,
            value: creatorAmount,
          });
          console.log("Creator ETH payout tx:", tx.hash);
        } else {
          const tokenContract = new ethers.Contract(token, ERC20_ABI, sepWallet);
          await tokenContract.transfer(creatorWallet, creatorAmount);
        }
      }

      // Investor shares
      for (const inv of investors) {
        const invAmount = (amount * BigInt(inv.shares)) / BigInt(totalShares);
        if (invAmount > BigInt(0)) {
          if (token === "SEPOLIA_ETH") {
            const txInvestor = await sepWallet.sendTransaction({
              to: inv.wallet,
              value: invAmount,
            });
            console.log("Investor ETH payout tx:", txInvestor.hash);
          } else {
            const tokenContract = new ethers.Contract(token, ERC20_ABI, sepWallet);
            await tokenContract.transfer(inv.wallet, invAmount);
          }
        }
      }

      // ✅ Mark this payment as claimed
      db.prepare(`UPDATE payments SET claimed = 1 WHERE id = ?`).run(payment.id);
    }

    // 3️⃣ Clear revenueEarned after WIP payout
    db.prepare(`UPDATE assets SET revenueEarned = '{}' WHERE ip_id = ?`).run(ipId);

    res.json({
      success: true,
      message: "Revenue claimed and all payments distributed",
      totalPayments: payments.length,
    });

  } catch (err: any) {
    console.error("Claim revenue error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});




// ---------------------- Fetch Assets ----------------------

app.get("/assets", authMiddleware, async (req, res) => {
  try {
    const rows = db.prepare(
      `SELECT * FROM assets WHERE user_id = ? ORDER BY created_at DESC`
    ).all(req.user.id);

    const parsed = await Promise.all(
      rows.map(async (r: any) => {
        const licenseIds = JSON.parse(r.license_terms || "[]");
        let licenseData = null;

       const licenseTerms = JSON.parse(r.license_terms || "[]")[0] || null;

return {
  id: r.id,
  explorer: `https://aeneid.explorer.story.foundation/ipa/${r.ip_id}`,
  txHash: r.tx_hash,
  ipId: r.ip_id,
  metadata: JSON.parse(r.nft_metadata || "{}"),
  license: licenseTerms, // ✅ send full license terms to frontend
  imageUrl: JSON.parse(r.ipfs_metadata || "{}").imageUrl || null,
  totalShares: r.totalShares,
  creatorShares: r.creatorShares,
  investors: JSON.parse(r.investors || "[]"),
  revenueEarned: JSON.parse(r.revenueEarned || "{}"),
};

      })
    );

    res.json({ assets: parsed });
  } catch (err) {
    console.error("FAILED /assets:", err);
    res.status(500).json({ error: "Error loading assets" });
  }
});


// ---------------------- IPFi Fractional Ownership ----------------------

// Add an investor
function addInvestor(ipId: string, wallet: string, shares: number) {
  const asset = db.prepare(`SELECT * FROM assets WHERE ip_id = ?`).get(ipId);
  if (!asset) return false;

  const investors = JSON.parse(asset.investors || "[]");
  investors.push({ wallet, shares });
  db.prepare(`UPDATE assets SET investors = ? WHERE ip_id = ?`).run(JSON.stringify(investors), ipId);
  return true;
}

// Distribute revenue correctly with fractional amounts
function distributeRevenue(ipId: string, amount: number) {
  const asset = db.prepare(`SELECT * FROM assets WHERE ip_id = ?`).get(ipId);
  if (!asset) return false;

  const investors = JSON.parse(asset.investors || "[]");
  const revenue: Record<string, number> = JSON.parse(asset.revenueEarned || "{}");

  const totalShares = asset.totalShares;
  const creatorShares = asset.creatorShares;

  // Parse creator wallet from NFT metadata
  const nftMetadata = JSON.parse(asset.nft_metadata || "{}");
  const creatorWallet = nftMetadata.creatorWallet || "";

  // 1️⃣ Calculate creator revenue (allow fractions)
  const creatorAmount = (amount * creatorShares) / totalShares;
  revenue[creatorWallet] = (revenue[creatorWallet] || 0) + creatorAmount;

  // 2️⃣ Calculate investor revenue (allow fractions)
  for (const inv of investors) {
    const invAmount = (amount * inv.shares) / totalShares;
    revenue[inv.wallet] = (revenue[inv.wallet] || 0) + invAmount;
  }

  // 3️⃣ Save back to DB as JSON
  db.prepare(`UPDATE assets SET revenueEarned = ? WHERE ip_id = ?`).run(
    JSON.stringify(revenue),
    ipId
  );

  return true;
}


// ---------------------- License Marketplace ----------------------

// List a license for sale
app.post("/list-license", authMiddleware, (req, res) => {
  const { ipId, price } = req.body;
  if (!ipId || !price) return res.status(400).json({ error: "Missing fields" });

  db.prepare(`
    INSERT INTO license_listings (ip_id, price, creator_wallet)
    VALUES (?, ?, ?)
  `).run(ipId, price, req.user.wallet_address);

  res.json({ success: true });
});

// Buy a license
// Buy a license
// ---------------------- Buy a license (fixed) ----------------------
// Buy a license
// ---------------------- Buy License (WITH PAYMENT RECORDING) ---------------------- 
app.post("/buy-license", authMiddleware, async (req, res) => {
  const { listingId, paymentTxHash } = req.body;

  if (!listingId) return res.status(400).json({ error: "Missing listingId" });
  if (!paymentTxHash) return res.status(400).json({ error: "Missing paymentTxHash" });

  const listing = db.prepare(
    `SELECT * FROM license_listings WHERE id = ? AND active = 1`
  ).get(listingId);

  if (!listing) return res.status(404).json({ error: "Listing not found or inactive" });

  const asset = db.prepare(`SELECT * FROM assets WHERE ip_id = ?`).get(listing.ip_id);
  if (!asset) return res.status(500).json({ error: "Asset not found" });

  try {
    // SAVE PAYMENT RECORD
    db.prepare(`
  INSERT INTO payments (ip_id, listing_id, from_wallet, to_wallet, amount, token, tx_hash)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`).run(
  listing.ip_id,
  listingId,
  req.user.wallet,
  account.address,
  listing.price,
  req.body.token || "ETH",
  paymentTxHash
);


    // Parse license terms
    let rawTerms = JSON.parse(asset.license_terms || "{}");
    const licenseTermsArray = Array.isArray(rawTerms) ? rawTerms : [rawTerms];
    const validTerm = licenseTermsArray.find((t) => t && (t.licenseTermsId || t.id));

    if (!validTerm) {
      return res.status(500).json({ error: "Invalid license terms in DB" });
    }

    const licenseTermsId = BigInt(validTerm.licenseTermsId || validTerm.id);

    // Mint Story Protocol License Token
    const response = await client.license.mintLicenseTokens({
      licenseTermsId,
      licensorIpId: listing.ip_id,
      amount: 1,
    });

    // Revenue distribution
    const nftMetadata = JSON.parse(asset.nft_metadata || "{}");
    const creatorWallet = nftMetadata.creatorWallet || listing.creator_wallet;

    const investors = JSON.parse(asset.investors || "[]");
    const revenue: Record<string, number> = JSON.parse(asset.revenueEarned || "{}");

    const totalShares = asset.totalShares;
    const creatorShares = asset.creatorShares;
    const amount = listing.price;

    // Creator earnings
  const creatorAmount = (amount * creatorShares) / totalShares;
revenue[creatorWallet] = (revenue[creatorWallet] || 0) + creatorAmount;

investors.forEach((inv: any) => {
  const invAmount = (amount * inv.shares) / totalShares;
  revenue[inv.wallet] = (revenue[inv.wallet] || 0) + invAmount;
});


    // Update DB
    db.prepare(`UPDATE assets SET revenueEarned = ? WHERE ip_id = ?`).run(
      JSON.stringify(revenue),
      listing.ip_id
    );

    // Disable listing
    db.prepare(`UPDATE license_listings SET active = 0 WHERE id = ?`).run(listingId);
const safeTerm = serialize(validTerm);
    db.prepare(`
  INSERT INTO owned_licenses (ip_id, listing_id, buyer_wallet, license_metadata)
  VALUES (?, ?, ?, ?)
`).run(
  listing.ip_id,
  listingId,
  req.user.wallet_address,
  JSON.stringify(safeTerm)
);

    return res.json(
      serialize({
        success: true,
        paymentTxHash,
        txHash: response.txHash,
        licenseTokenIds: response.licenseTokenIds,
      })
    );
  } catch (err: any) {
    console.error("Buy license error:", err);
    res.status(500).json({ error: "Failed to buy license", details: err.message });
  }
});

// ---------------------- Fetch Owned Licenses ----------------------
function toGateway(url: string | null): string | null {
  if (!url) return null;

  // handle ipfs://CID
  if (url.startsWith("ipfs://"))
    return url.replace("ipfs://", "https://gateway.pinata.cloud/ipfs/");

  // handle https://ipfs.io/ipfs/CID
  if (url.includes("ipfs.io/ipfs/"))
    return url.replace("https://ipfs.io/ipfs/", "https://gateway.pinata.cloud/ipfs/");

  // handle any other gateway
  if (url.includes("/ipfs/"))
    return url.replace(/https?:\/\/[^/]+\/ipfs\//, "https://gateway.pinata.cloud/ipfs/");

  return url;
}


app.get("/my-licenses", authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT ol.*, a.ipfs_metadata 
    FROM owned_licenses ol
    LEFT JOIN assets a ON ol.ip_id = a.ip_id
    WHERE ol.buyer_wallet = ?
  `).all(req.user.wallet_address);

  const licenses = rows.map((r: any) => {
    const terms = JSON.parse(r.license_metadata);
    const metadata = JSON.parse(r.ipfs_metadata || "{}");
const media = toGateway(metadata.mediaUrl || metadata.media);
    return {
      id: r.id,
      ipId: r.ip_id,
      terms: {
        ...terms,
        imageUrl: metadata.imageUrl || null, // ✅ merge imageUrl here
        mediaUrl: media || null, // ✅ merge mediaUrl here
      },
      purchasedOn: r.created_at
    };
  });

  res.json({ success: true, licenses });
});





// ---------------------- Fetch IPFi Assets ----------------------

app.get("/ipfi-assets", authMiddleware, (req, res) => {
  const rows = db.prepare(`SELECT * FROM assets WHERE user_id = ?`).all(req.user.id);

  const parsed = rows.map((r: any) => ({
    id: r.id,
    ipId: r.ip_id,
    metadata: JSON.parse(r.nft_metadata || "{}"),
    totalShares: r.totalShares,
    creatorShares: r.creatorShares,
    investors: JSON.parse(r.investors || "[]"),
    revenueEarned: JSON.parse(r.revenueEarned || "{}"),
  }));

  res.json({ assets: parsed });
});


app.get("/market/listings", async (req, res) => {
  const rows = db.prepare(`
    SELECT l.*, a.ipfs_metadata
    FROM license_listings l
    LEFT JOIN assets a ON l.ip_id = a.ip_id
    WHERE l.active = 1
    ORDER BY l.created_at DESC
  `).all();

  const listings = rows.map((r: any) => {
    let imageUrl = null;
    try {
      imageUrl = JSON.parse(r.ipfs_metadata || "{}").imageUrl || null;
    } catch (e) {
      console.error("Failed to parse ipfs_metadata", e);
    }

    return {
      id: r.id,
      ip_id: r.ip_id,
      creator_wallet: r.creator_wallet,
      price: r.price,
      image: imageUrl
    };
  });

  res.json({ listings });
});


// ---------------------- Current User ----------------------

app.get("/me", authMiddleware, (req: any, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    wallet: req.user.wallet_address,
  });
});

// ---------------------- Config Endpoint ----------------------

// Send frontend the WIP token address and server wallet address
app.get("/config", (req, res) => {
  try {
    res.json({
      success: true,
      wipTokenAddress: WIP_TOKEN_ADDRESS,
      serverWalletAddress: account.address, // server wallet from Story SDK
    });
  } catch (err: any) {
    console.error("Failed /config:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});


// ---------------------- Get Server Wallet Address ----------------------
app.get("/wallet/server",authMiddleware, (req, res) => {
  try {
    res.json({
      success: true,
      wallet: account.address, // your backend signer wallet
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// ---------------------- Start Server ----------------------

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Dravik backend running on port ${PORT}`);
});

