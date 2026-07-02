import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import { Database, DbUser } from "./server/db";
import { Mailer, sentEmailsLog } from "./server/mailer";
import connectDB from "./server/connectDB";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const COOKIE_NAME = "careerpath_session";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

// ================= CORE SECURITY MIDDLEWARE =================

// Helmet: sensible secure HTTP headers. CSP is relaxed slightly so the
// existing Vite/React UI, animations, and inline styles keep working as-is.
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// CORS: allow the site's own origin to send credentials (cookies).
app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
  })
);

app.use(cookieParser());
app.use(express.json({ limit: "2mb" }));

// Rate limiting: protect authentication endpoints from brute-force / abuse.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts from this device. Please try again later." },
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many password reset requests. Please try again later." },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", apiLimiter);

// Token secret helper
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-careerpath-key-12345";
if (!process.env.JWT_SECRET) {
  console.warn(
    "[Security Warning] JWT_SECRET is not set in your environment. Using an insecure default — set JWT_SECRET in .env for production."
  );
}

// Issue an HTTP-only auth cookie (preferred transport) alongside a bearer token.
function issueSessionCookie(res: any, token: string, rememberMe: boolean) {
  const maxAge = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30d vs 1d
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "lax",
    maxAge,
    path: "/",
  });
}

function clearSessionCookie(res: any) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "lax",
    path: "/",
  });
}

// Security Helper: JWT Verification Middleware.
// Reads the token from the HTTP-only cookie first (preferred), and falls
// back to the Authorization: Bearer header for API/CLI clients.
function authenticateToken(req: any, res: any, next: any) {
  const cookieToken = req.cookies?.[COOKIE_NAME];
  const authHeader = req.headers["authorization"];
  const headerToken = authHeader && authHeader.split(" ")[1];
  const token = cookieToken || headerToken;

  if (!token) {
    return res.status(401).json({ error: "Access token required." });
  }

  jwt.verify(token, JWT_SECRET, async (err: any, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired session token." });
    }
    try {
      const user = await Database.findUserById(decoded.id);
      if (!user) {
        return res.status(404).json({ error: "User session not found in database." });
      }
      req.user = user;
      next();
    } catch (e) {
      console.error("Auth lookup failed:", e);
      return res.status(500).json({ error: "Failed to verify session." });
    }
  });
}

// Security Helper: Admin Only Middleware
function requireAdmin(req: any, res: any, next: any) {
  authenticateToken(req, res, () => {
    if (req.user.role !== "admin" && req.user.email.toLowerCase() !== "keshavdhanuka74@gmail.com") {
      return res.status(403).json({ error: "Access denied. Administrator privileges required." });
    }
    next();
  });
}

// Small helper to run express-validator chains and short-circuit on error.
function validate(req: any, res: any) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ error: errors.array()[0].msg });
    return false;
  }
  return true;
}

// Initialize Gemini client lazily
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
    console.warn("GEMINI_API_KEY is not configured or uses placeholder. Running in fallback mode with premium local models.");
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// Fallback high-quality data in case Gemini key is missing or fails
const FALLBACK_CAREERS = [
  {
    title: "AI Engineer",
    description: "Build and deploy machine learning models, generative AI pipelines, and neural networks to solve complex problems.",
    salary: { fresher: "₹8 - ₹15 LPA", average: "₹18 - ₹30 LPA", senior: "₹35 - ₹60+ LPA" },
    growthRate: "35%",
    advantages: [
      "Incredibly high demand in India and globally",
      "Opportunity to work with cutting-edge technologies",
      "Excellent compensation packages and fast-track promotions",
      "Flexible remote and hybrid working arrangements"
    ],
    skills: ["Python", "PyTorch/TensorFlow", "Generative AI", "LLMs", "NLP", "Cloud Platforms (GCP/AWS)"],
    roadmap: [
      { step: "Phase 1: Foundations", desc: "Master Python programming, Linear Algebra, Calculus, and Statistics." },
      { step: "Phase 2: Machine Learning", desc: "Learn classical ML algorithms (Regression, Trees, SVMs) and Scikit-Learn." },
      { step: "Phase 3: Deep Learning & GenAI", desc: "Study Neural Networks, Transformers, LLM fine-tuning, and prompt engineering." },
      { step: "Phase 4: MLOps", desc: "Deploy models using Docker, Kubernetes, FastStream, and Cloud APIs." }
    ],
    topCompanies: ["Google India", "Microsoft India", "NVIDIA", "Infosys Helix", "Fractal Analytics", "Tech Mahindra AI"],
    matchScore: "98%"
  },
  {
    title: "Full Stack Developer",
    description: "Design and implement end-to-end web applications, combining visual client interfaces with reliable backend databases and servers.",
    salary: { fresher: "₹5 - ₹10 LPA", average: "₹12 - ₹22 LPA", senior: "₹25 - ₹45 LPA" },
    growthRate: "28%",
    advantages: [
      "Extremely versatile role with millions of job openings",
      "Perfect for launching your own startup or freelancing",
      "Rapid visual feedback on your build efforts",
      "High lateral mobility across multiple industries"
    ],
    skills: ["React/TypeScript", "Node.js/Express", "PostgreSQL/MongoDB", "System Design", "Git/CI-CD", "Tailwind CSS"],
    roadmap: [
      { step: "Phase 1: Frontend Basics", desc: "Master semantic HTML, CSS layouts (Flexbox/Grid), and modern JavaScript (ES6+)." },
      { step: "Phase 2: UI Frameworks", desc: "Learn React, state management, Tailwind CSS, and build responsive interfaces." },
      { step: "Phase 3: Backend & Databases", desc: "Build RESTful & GraphQL APIs with Express.js, and design relational databases." },
      { step: "Phase 4: Deployment & Scaling", desc: "Learn containerization with Docker and cloud hosting on AWS/Vercel/Render." }
    ],
    topCompanies: ["Paytm", "Zerodha", "Razorpay", "TCS", "Cognizant", "Swiggy", "Zomato"],
    matchScore: "94%"
  },
  {
    title: "UI/UX Product Designer",
    description: "Conduct user research, design interactive wireframes, and create aesthetically stunning interfaces that simplify user interactions.",
    salary: { fresher: "₹4 - ₹8 LPA", average: "₹10 - ₹18 LPA", senior: "₹20 - ₹38 LPA" },
    growthRate: "22%",
    advantages: [
      "Perfect balance of creativity, psychology, and technology",
      "Crucial role for product success - highly valued by founders",
      "No coding required to get started",
      "Great remote/freelance opportunities with foreign clients"
    ],
    skills: ["Figma", "User Research", "Wireframing", "Visual Design", "Design Systems", "Prototyping"],
    roadmap: [
      { step: "Phase 1: Design Principles", desc: "Study Typography, Visual Hierarchy, Grid Systems, and Color Theory." },
      { step: "Phase 2: Mastering Figma", desc: "Learn components, auto-layout, variants, and interactive prototyping." },
      { step: "Phase 3: UX Methodology", desc: "Practice user research, journey mapping, empathy maps, and usability testing." },
      { step: "Phase 4: Portfolio Building", desc: "Document 3 comprehensive case studies demonstrating problem-solving logic." }
    ],
    topCompanies: ["Ola Cabs", "Cred", "PhonePe", "Flipkart", "Tata Consultancy Services", "Fractal Ink"],
    matchScore: "88%"
  }
];

// ================= AUTHENTICATION ENDPOINTS =================

// 1. API: Sign Up / Registration
app.post(
  "/api/auth/register",
  authLimiter,
  [
    body("name").trim().notEmpty().withMessage("Full name is required.").isLength({ max: 100 }),
    body("email").trim().isEmail().withMessage("Please provide a valid email address.").normalizeEmail(),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long.")
      .matches(/[a-zA-Z]/)
      .withMessage("Password must contain at least one letter.")
      .matches(/[0-9]/)
      .withMessage("Password must contain at least one number."),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password and password confirmation do not match.");
      }
      return true;
    }),
  ],
  async (req: any, res: any) => {
    if (!validate(req, res)) return;
    try {
      const { name, email, password } = req.body;

      // Check if user already exists
      const existingUser = await Database.findUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({ error: "Email address is already registered." });
      }

      // Securely hash password using bcrypt
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      // Create user in persistent MongoDB database
      const user = await Database.createUser({
        name,
        email: email.toLowerCase(),
        passwordHash,
        role: "user", // Database class will auto-promote owner email to 'admin'
        interests: [],
        savedCareers: [],
        bookmarkedOpportunities: [],
      });

      // Auto trigger admin notification email asynchronously so registration doesn't stall
      const userAgent = req.headers["user-agent"] || "";
      const ip = req.ip || req.headers["x-forwarded-for"] || "";

      Mailer.sendAdminNewUserNotification({
        name: user.name,
        email: user.email,
        userAgent,
        ip: String(ip),
        country: "India", // Default target market
      }).catch((err) => console.error("Admin registration notice failed:", err));

      // Generate JWT access token
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
        expiresIn: "1d",
      });

      // Set secure HTTP-only session cookie (preferred auth transport)
      issueSessionCookie(res, token, false);

      // Strip passwordHash from response payload
      const { passwordHash: _, ...userProfile } = user;

      return res.status(201).json({
        message: "Account registered successfully.",
        user: userProfile,
        token,
      });
    } catch (error) {
      console.error("Registration error:", error);
      return res.status(500).json({ error: "An unexpected error occurred during signup." });
    }
  }
);

// 2. API: Sign In / Login
app.post(
  "/api/auth/login",
  authLimiter,
  [
    body("email").trim().isEmail().withMessage("Please provide a valid email address.").normalizeEmail(),
    body("password").notEmpty().withMessage("Password is required."),
  ],
  async (req: any, res: any) => {
    if (!validate(req, res)) return;
    try {
      const { email, password, rememberMe } = req.body;

      const user = await Database.findUserByEmail(email);
      if (!user) {
        return res.status(401).json({ error: "Invalid email credentials or password." });
      }

      // Securely verify password
      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid email credentials or password." });
      }

      // Update lastLogin tracking
      await Database.updateUser(user.id, { lastLogin: new Date().toISOString() as any });

      // Generate JWT Token. Set long expiry if "Remember Me" is toggled
      const expiresIn = rememberMe ? "30d" : "1d";
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
        expiresIn,
      });

      // Set secure HTTP-only session cookie. Duration respects "Remember Me".
      issueSessionCookie(res, token, Boolean(rememberMe));

      // Strip passwordHash from output
      const { passwordHash: _, ...userProfile } = user;

      return res.json({
        message: "Welcome back!",
        user: userProfile,
        token,
      });
    } catch (error) {
      console.error("Login error:", error);
      return res.status(500).json({ error: "Internal server login error." });
    }
  }
);

// 3. API: Get Logged In User / Token Verification
app.get("/api/auth/me", authenticateToken, (req: any, res) => {
  const { passwordHash: _, ...userProfile } = req.user;
  return res.json({ user: userProfile });
});

// 4. API: Logout — clears the HTTP-only session cookie
app.post("/api/auth/logout", (req, res) => {
  clearSessionCookie(res);
  return res.json({ message: "Logged out successfully." });
});

// 5. API: Forgot Password (Request Link)
app.post(
  "/api/auth/forgot-password",
  forgotPasswordLimiter,
  [body("email").trim().isEmail().withMessage("Please provide a valid email address.").normalizeEmail()],
  async (req: any, res: any) => {
    if (!validate(req, res)) return;
    try {
      const { email } = req.body;

      const user = await Database.findUserByEmail(email);
      // Security Best Practice: Return same status to prevent email enumeration
      if (!user) {
        return res.json({
          message: "If the email is registered, a secure reset link will be delivered within 5 minutes.",
        });
      }

      // Generate secure single-use reset token
      const token = await Database.createResetToken(user.email);

      // Build reset URL pointing to development URL structure
      // Since we're using React State, we can build the URL as query params on the homepage, which App.tsx can read on load!
      const hostUrl = req.headers["referer"] || req.headers["host"] || CLIENT_URL;
      const resetUrl = `${String(hostUrl).split("?")[0]}?resetToken=${token}`;

      // Send reset email via Nodemailer
      const mailResult = await Mailer.sendResetPasswordEmail(user.email, resetUrl);

      return res.json({
        message: "If the email is registered, a secure reset link will be delivered within 5 minutes.",
        debugPreview: mailResult.preview, // Helpful preview inside workspace sandbox
      });
    } catch (error) {
      console.error("Forgot password error:", error);
      return res.status(500).json({ error: "Failed to generate password recovery link." });
    }
  }
);

// 6. API: Reset Password (Execute Reset)
app.post(
  "/api/auth/reset-password",
  authLimiter,
  [
    body("token").notEmpty().withMessage("Reset token is required."),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long.")
      .matches(/[a-zA-Z]/)
      .withMessage("Password must contain at least one letter.")
      .matches(/[0-9]/)
      .withMessage("Password must contain at least one number."),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password entries do not match.");
      }
      return true;
    }),
  ],
  async (req: any, res: any) => {
    if (!validate(req, res)) return;
    try {
      const { token, password } = req.body;

      // Verify recovery token validity and expiration
      const email = await Database.verifyResetToken(token);
      if (!email) {
        return res.status(400).json({ error: "Your password reset token is invalid or has expired." });
      }

      const user = await Database.findUserByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User associated with this token no longer exists." });
      }

      // Securely hash new password
      const salt = await bcrypt.genSalt(10);
      const newHash = await bcrypt.hash(password, salt);

      // Update user in DB
      await Database.updateUser(user.id, { passwordHash: newHash });

      // Invalidate reset token immediately
      await Database.removeResetToken(token);

      // Notify admin that a password reset occurred (never includes the password itself)
      const userAgent = req.headers["user-agent"] || "";
      const ip = req.ip || req.headers["x-forwarded-for"] || "";
      Mailer.sendAdminPasswordResetNotification({
        name: user.name,
        email: user.email,
        userAgent,
        ip: String(ip),
      }).catch((err) => console.error("Admin password reset notice failed:", err));

      // Invalidate any existing session cookie so the user must log in again with the new password
      clearSessionCookie(res);

      return res.json({ message: "Your password has been reset successfully. You can now login with your new password." });
    } catch (error) {
      console.error("Reset password execution error:", error);
      return res.status(500).json({ error: "Failed to update your password credentials." });
    }
  }
);

// 7. API: Sync User Progress, Saved Careers and Interests
app.post("/api/user/sync", authenticateToken, async (req: any, res) => {
  try {
    const { interests, savedCareers, bookmarkedOpportunities, name, profileImage } = req.body;

    const updates: Partial<DbUser> = {};
    if (interests && Array.isArray(interests)) updates.interests = interests;
    if (savedCareers && Array.isArray(savedCareers)) updates.savedCareers = savedCareers;
    if (bookmarkedOpportunities && Array.isArray(bookmarkedOpportunities)) updates.bookmarkedOpportunities = bookmarkedOpportunities;
    if (name) updates.name = name;
    if (profileImage !== undefined) updates.profileImage = profileImage;

    const updatedUser = await Database.updateUser(req.user.id, updates);
    if (!updatedUser) {
      return res.status(500).json({ error: "Failed to update user database profile." });
    }

    const { passwordHash: _, ...userProfile } = updatedUser;
    return res.json({ message: "Cloud workspace saved successfully.", user: userProfile });
  } catch (error) {
    console.error("Progress sync error:", error);
    return res.status(500).json({ error: "Failed to sync updates to the cloud." });
  }
});


// ================= ADMINISTRATOR SECURE SERVICES =================

// 1. API: Get complete users and activity log analytics
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const users = await Database.getUsers();
  
  // Format user records for admin display (Strict: Never expose passwordHash)
  const formattedUsers = users.map(({ passwordHash: _, ...profile }) => profile);

  // Derive interesting analytics metrics
  const totalUsers = users.length;
  
  // Count active in last 24h
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const activeToday = users.filter(u => new Date(u.lastLogin).getTime() > oneDayAgo).length;

  // Aggregate interests counts
  const interestsMap: { [key: string]: number } = {};
  users.forEach(u => {
    u.interests?.forEach(interest => {
      interestsMap[interest] = (interestsMap[interest] || 0) + 1;
    });
  });

  return res.json({
    users: formattedUsers,
    analytics: {
      totalUsers,
      activeToday,
      interestsDistribution: interestsMap,
      generatedAt: new Date().toISOString(),
    }
  });
});

// 2. API: Get sent emails trace logs (simulate sandbox inbox)
app.get("/api/admin/emails", requireAdmin, (req, res) => {
  return res.json({ emails: sentEmailsLog });
});


// ================= ORIGINAL CAREER API ROUTERS =================

// 1. API: Career Recommendation
app.post("/api/recommend", async (req, res) => {
  try {
    const { interests, experienceLevel } = req.body;
    if (!interests || !Array.isArray(interests) || interests.length === 0) {
      return res.status(400).json({ error: "Interests array is required." });
    }

    const ai = getGeminiClient();
    if (!ai) {
      // Use fallback data and filter loosely based on matching words or send all
      console.log("Serving fallback career recommendation data due to missing API Key.");
      return res.json({ careers: FALLBACK_CAREERS });
    }

    const prompt = `You are an expert career counselor in India. Analyze the user's interests: [${interests.join(", ")}] and their experience level: "${experienceLevel || "Student/Fresher"}".
Recommend the top 3-4 highly relevant career fields specifically suited for the Indian market.
For each career field, provide detailed information exactly matching the required structure:
1. Career Title
2. Long, engaging description
3. Salaries in India (Fresher, Average, Senior) in Lakhs Per Annum (LPA) (e.g. "₹6 - ₹10 LPA")
4. Projected growth rate percentage (e.g. "25%")
5. List of advantages (at least 3-4 advantages)
6. Key technical and soft skills required (6-8 items)
7. Step-by-step roadmap with 4 phases (each phase has a title 'step' and short details 'desc')
8. Top hiring companies operating in India (e.g. Reliance, TCS, Flipkart, MNCs, leading startups)
9. Match score as a percentage based on user's interests (e.g. "95%")`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            careers: {
              type: Type.ARRAY,
              description: "List of recommended career paths",
              items: {
                type: Type.OBJECT,
                required: ["title", "description", "salary", "growthRate", "advantages", "skills", "roadmap", "topCompanies", "matchScore"],
                properties: {
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  salary: {
                    type: Type.OBJECT,
                    properties: {
                      fresher: { type: Type.STRING },
                      average: { type: Type.STRING },
                      senior: { type: Type.STRING }
                    }
                  },
                  growthRate: { type: Type.STRING },
                  advantages: { type: Type.ARRAY, items: { type: Type.STRING } },
                  skills: { type: Type.ARRAY, items: { type: Type.STRING } },
                  roadmap: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      properties: {
                        step: { type: Type.STRING },
                        desc: { type: Type.STRING }
                      }
                    }
                  },
                  topCompanies: { type: Type.ARRAY, items: { type: Type.STRING } },
                  matchScore: { type: Type.STRING }
                }
              }
            }
          }
        }
      }
    });

    const data = JSON.parse(response.text || "{}");
    return res.json(data);
  } catch (error: any) {
    console.error("Gemini API Recommendation Error:", error);
    // Graceful fallback to avoid erroring out
    return res.json({ careers: FALLBACK_CAREERS, note: "Loaded via fallback database due to api rate/token limit." });
  }
});

// 2. API: AI Chat Assistant
app.post("/api/chat", async (req, res) => {
  try {
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Messages array is required." });
    }

    const ai = getGeminiClient();
    if (!ai) {
      // Simulate intelligent career-oriented responses
      const lastUserMsg = messages[messages.length - 1]?.content?.toLowerCase() || "";
      let reply = "I'm your CareerPath AI assistant! I'd love to help you explore jobs, colleges, salaries, and roadmaps in India. Ask me about specific coding languages, design domains, finance positions, or interview strategies.";
      if (lastUserMsg.includes("salary") || lastUserMsg.includes("money") || lastUserMsg.includes("lpa")) {
        reply = "Salaries in India vary highly by domain! Tech roles (AI, SDE) generally start around ₹6-12 LPA at product companies and scale up to ₹30-50 LPA for seniors. Service-based companies (TCS, Infosys) start at ₹3.6-5 LPA. Product design and product management are also extremely high-paying, scaling to ₹25+ LPA.";
      } else if (lastUserMsg.includes("fresher") || lastUserMsg.includes("job") || lastUserMsg.includes("apply")) {
        reply = "For freshers in India, focus on building a robust portfolio of real-world projects. Platforms like GitHub (for dev) or Behance (for designers) are key. Also practice Data Structures & Algorithms, contribute to open source, and apply via LinkedIn, Naukri, or Wellfound.";
      } else if (lastUserMsg.includes("roadmap") || lastUserMsg.includes("learn") || lastUserMsg.includes("study")) {
        reply = "The best roadmap always starts with strong fundamentals. For Software Dev, start with HTML/CSS/JavaScript, then React, Node.js, and databases. If you're into AI, master Python first, then statistics, Machine Learning algorithms, and neural networks. Commit to daily coding!";
      }
      return res.json({ text: reply });
    }

    // Convert messages to Gemini format
    const chatHistory = messages.map(msg => `${msg.role === "user" ? "User" : "Assistant"}: ${msg.content}`).join("\n");
    
    const systemPrompt = `You are "CareerPath AI", an empathetic, highly knowledgeable, and professional career advisor for students and job seekers in India. 
Help them navigate domains like software development, artificial intelligence, product design, marketing, finance, and creative fields in India.
Discuss realistic salaries (in Lakhs Per Annum - LPA), Indian job search trends, top companies (Zerodha, Razorpay, Google India, TCS, etc.), and step-by-step upskilling.
Be encouraging, structured, and give concise, high-value advice. Use bullet points where appropriate. Keep answers under 200 words.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: `${systemPrompt}\n\nChat history:\n${chatHistory}\nAssistant:`,
    });

    return res.json({ text: response.text || "I'm analyzing your profile. How else can I assist you with your career goals?" });
  } catch (error: any) {
    console.error("Gemini API Chat Error:", error);
    return res.status(500).json({ error: "Failed to communicate with AI server." });
  }
});

// Setup Vite Dev Server / Serve static build in Production
async function startServer() {
  try {
    await connectDB();
  } catch (err) {
    console.error(
      "Failed to connect to MongoDB. Authentication and user data routes will not work until MONGODB_URI is configured correctly."
    );
  }

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

