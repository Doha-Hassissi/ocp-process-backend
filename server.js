require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const nodemailer = require("nodemailer");

// Import des modules database avec fonctions d'anomalie
const {
  connectDB,
  User,
  Fiche,
  Mesure,
  Anomalie,
  Checklist,
  Procedure,
  createMesureFromFiche,
  detectAnomalies,
  SEUILS,
} = require("./database");

const app = express();

// ================= CONFIGURATION EXPRESS =================
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use("/uploads", express.static("uploads")); // Servir fichiers statiques

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key_ocp";

// Créer dossier uploads si inexistant
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// ================= CONNEXION BASE DE DONNÉES =================
connectDB();

// ================= CONFIGURATION EMAIL (Nodemailer) =================
let testAccount = null;

const getTransporter = async () => {
  try {
    if (process.env.EMAIL_PASS && process.env.EMAIL_PASS !== "votre_mot_de_passe_app") {
      return nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
        tls: { rejectUnauthorized: false }
      });
    } else {
      // Configuration de repli (Ethereal) si aucun identifiant valide n'est fourni
      if (!testAccount) {
        testAccount = await nodemailer.createTestAccount();
        console.log("⚙️  Génération automatique d'un compte email test (Ethereal) car EMAIL_PASS n'est pas défini.");
      }
      return nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
        tls: { rejectUnauthorized: false }
      });
    }
  } catch (err) {
    console.error("❌ Erreur d'initialisation du service email: ", err);
    throw err;
  }
};

// ================= MIDDLEWARE AUTHENTIFICATION =================
const authMiddleware = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "Token manquant" });
  }

  const token = header.split(" ")[1];

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    
    // Allow pass-through for now to prevent blocking users from the application
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token invalide" });
  }
};

// ================= CONFIGURATION MULTER (Upload Fichiers) =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|xls|xlsx|png|jpg|jpeg/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase(),
    );
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Type de fichier non supporté"));
    }
  },
});

// ================= ROUTES AUTHENTIFICATION =================

// 🔐 LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !email.endsWith("@ocpgroup.ma")) {
      return res.status(400).json({ error: "L'email doit être strictement @ocpgroup.ma" });
    }

    if (password !== "ocp123") {
      return res.status(400).json({ error: "Mot de passe incorrect." });
    }

    let user = await User.findOne({ email });

    if (!user) {
      const hashed = await bcrypt.hash("ocp123", 10);
      user = await User.create({
        email,
        password: hashed, 
        nom: email.split('@')[0], 
        role: "User",
        mustChangePassword: false
      });
    }

    // Send login activity email on successful login
    sendActivityEmail(user.email, "Connexion au portail réussie");

    const token = jwt.sign(
      { _id: user._id, email: user.email, role: user.role, nom: user.nom },
      JWT_SECRET,
      { expiresIn: "1d" },
    );

    res.json({
      token,
      user: {
        email: user.email,
        nom: user.nom,
        role: user.role,
        matricule: user.matricule,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/register", async (req, res) => {
  const { email, nom } = req.body;
  
  if (!email || !email.endsWith("@ocpgroup.ma")) {
    return res.status(400).json({ error: "L'email doit être @ocpgroup.ma" });
  }

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ error: "Email déjà utilisé" });

  const hashed = await bcrypt.hash("ocp123", 10);

  const user = await User.create({
    email,
    password: hashed,
    nom,
    mustChangePassword: true
  });

  res.json({ success: true, user: { email: user.email, nom: user.nom, role: user.role, mustChangePassword: user.mustChangePassword } });
});

// 🔐 CHANGEMENT MOT DE PASSE
app.put("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "Utilisateur introuvable" });
    }

    let isMatch = await bcrypt.compare(oldPassword, user.password);
    
    // Fallback for users registered with the temporary plaintext tag
    if (!isMatch && user.password === "ocp123_hardcoded" && oldPassword === "ocp123") {
      isMatch = true;
    }

    if (!isMatch) {
      return res.status(400).json({ error: "Ancien mot de passe incorrect" });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.mustChangePassword = false;
    await user.save();

    // Send activity email for password change
    sendActivityEmail(user.email, "Mot de passe modifié avec succès");

    const token = jwt.sign(
      { _id: user._id, email: user.email, role: user.role, nom: user.nom, mustChangePassword: false },
      JWT_SECRET,
      { expiresIn: "1d" },
    );

    res.json({ message: "Mot de passe changé avec succès", token });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ================= FONCTION: Envoi Email Alerte =================
/**
 * Envoie une notification email pour une anomalie détectée.
 * Met à jour le statut emailSent de l'anomalie après envoi réussi.
 *
 * @param {Object} anomalie - Document anomalie de MongoDB
 * @returns {Object} - Info message nodemailer ou error
 */
const sendAlertEmail = async (anomalie) => {
  try {
    // Configuration des destinataires depuis variables d'environnement
    const toEmail = anomalie.userEmail;
    const fromEmail = process.env.EMAIL_USER || "alertes@ocp.ma";

    // Détermination de la couleur selon sévérité
    const severityColors = {
      High: "#dc2626", // Rouge
      Med: "#f59e0b", // Orange
      Low: "#3b82f6", // Bleu
    };
    const color = severityColors[anomalie.severity] || "#dc2626";
    const severityLabel =
      anomalie.severity === "High"
        ? "CRITIQUE"
        : anomalie.severity === "Med"
          ? "MOYENNE"
          : "FAIBLE";

    const mailOptions = {
      from: `"Système Monitoring OCP" <${fromEmail}>`,
      to: toEmail,
      subject: `🚨 ALERTE ${severityLabel} - ${anomalie.type.toUpperCase()} détecté`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; background: #f9fafb; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: ${color}; color: white; padding: 24px; text-align: center; }
            .header h1 { margin: 0; font-size: 24px; font-weight: 800; text-transform: uppercase; }
            .content { padding: 32px; background: white; }
            .alert-box { background: #fef2f2; border-left: 4px solid ${color}; padding: 16px; margin: 20px 0; border-radius: 0 8px 8px 0; }
            .param-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }
            .param-card { background: #f3f4f6; padding: 16px; border-radius: 8px; text-align: center; }
            .param-label { font-size: 12px; color: #6b7280; text-transform: uppercase; font-weight: 700; margin-bottom: 4px; }
            .param-value { font-size: 20px; font-weight: 800; color: ${color}; }
            .footer { background: #f3f4f6; padding: 16px; text-align: center; font-size: 12px; color: #6b7280; }
            .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 700; color: white; background: ${color}; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>⚠️ Alerte Paramètre Critique</h1>
              <p style="margin: 8px 0 0 0; opacity: 0.9;">Système de Monitoring OCP Process</p>
            </div>
            
            <div class="content">
              <div class="alert-box">
                <strong style="color: ${color}; font-size: 16px;">${anomalie.message}</strong>
              </div>
              
              <div class="param-grid">
                <div class="param-card">
                  <div class="param-label">Type d'anomalie</div>
                  <div class="param-value" style="font-size: 14px; color: #374151;">${anomalie.type}</div>
                </div>
                <div class="param-card">
                  <div class="param-label">Sévérité</div>
                  <div style="margin-top: 8px;"><span class="badge">${anomalie.severity}</span></div>
                </div>
                <div class="param-card">
                  <div class="param-label">Valeur Mesurée</div>
                  <div class="param-value">${anomalie.valeur}</div>
                </div>
                <div class="param-card">
                  <div class="param-label">Seuil Critique</div>
                  <div class="param-value" style="color: #6b7280;">${anomalie.seuil}</div>
                </div>
              </div>
              
              <div style="background: #eff6ff; padding: 16px; border-radius: 8px; margin-top: 20px;">
                <h3 style="margin: 0 0 12px 0; color: #1e40af; font-size: 14px;">📋 Informations Contextuelles</h3>
                <p style="margin: 4px 0; font-size: 13px;"><strong>Ligne:</strong> ${anomalie.ligne || "Non spécifiée"}</p>
                <p style="margin: 4px 0; font-size: 13px;"><strong>Fiche ID:</strong> ${anomalie.ficheId || "N/A"}</p>
                <p style="margin: 4px 0; font-size: 13px;"><strong>Date détection:</strong> ${new Date(
                  anomalie.createdAt,
                ).toLocaleString("fr-FR", {
                  weekday: "long",
                  year: "numeric",
                  month: "long",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })}</p>
              </div>
              
              <p style="margin-top: 24px; font-size: 13px; color: #6b7280; text-align: center;">
                Cette alerte a été générée automatiquement par le système de monitoring.<br>
                Veuillez prendre les mesures correctives nécessaires.
              </p>
            </div>
            
            <div class="footer">
              <p>© ${new Date().getFullYear()} OCP Group - Système de Monitoring Industriel</p>
              <p style="margin-top: 4px; font-size: 11px;">Ne pas répondre à cet email - Notification automatique</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `ALERTE CRITIQUE OCP\n\n${anomalie.message}\n\nType: ${anomalie.type}\nValeur: ${anomalie.valeur}\nSeuil: ${anomalie.seuil}\nSévérité: ${anomalie.severity}\nLigne: ${anomalie.ligne}\nDate: ${new Date(anomalie.createdAt).toLocaleString("fr-FR")}\n\n---\nSystème de Monitoring OCP Process`,
    };

    // Envoi de l'email
    const transporter = await getTransporter();
    const info = await transporter.sendMail(mailOptions);
    console.log(
      `📧 Email alerte envoyé [MessageID: ${info.messageId}] pour anomalie ${anomalie._id}`
    );
    
    // Si c'est un compte test, afficher l'URL pour visualiser l'email
    if (nodemailer.getTestMessageUrl(info)) {
      console.log(`👁️  Voir l'email (Ethereal) : ${nodemailer.getTestMessageUrl(info)}`);
    }

    // Mise à jour du statut emailSent dans la base
    await Anomalie.findByIdAndUpdate(anomalie._id, { emailSent: true });

    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error("❌ Erreur envoi email:", err.message);
    // On ne throw pas l'erreur pour ne pas bloquer le flux principal
    return { success: false, error: err.message };
  }
};

// ================= FONCTION: Envoi Email Activité =================
const sendActivityEmail = async (userEmail, action) => {
  try {
    const fromEmail = process.env.EMAIL_USER || "alertes@ocp.ma";
    const mailOptions = {
      from: `"Système Sécurité OCP" <${fromEmail}>`,
      to: userEmail,
      subject: `🛡️ Alerte de sécurité : ${action}`,
      text: `Bonjour,\n\nUne nouvelle activité importante a été enregistrée sur votre compte: ${action}.\n\nDate: ${new Date().toLocaleString("fr-FR")}\nEmail associé: ${userEmail}\n\nSi vous n'êtes pas à l'origine de cette action, veuillez contacter l'administrateur système immédiatement.\n\n---\nSystème de Monitoring OCP Process`,
    };
    const transporter = await getTransporter();
    const info = await transporter.sendMail(mailOptions);
    console.log(`📧 Email activité envoyé à ${userEmail} pour: ${action}`);
    
    if (nodemailer.getTestMessageUrl(info)) {
      console.log(`👁️  Voir l'email (Ethereal) : ${nodemailer.getTestMessageUrl(info)}`);
    }
  } catch (err) {
    console.error("❌ Erreur envoi email activité:", err.message);
  }
};

// ================= ROUTES FICHES PROCESS (AVEC DÉTECTION ANOMALIES) =================

// GET toutes les fiches
app.get("/api/fiches", authMiddleware, async (req, res) => {
  const query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
  const fiches = await Fiche.find(query);
  res.json(fiches);
});

// GET une fiche par ID
app.get("/api/fiches/:id", authMiddleware, async (req, res) => {
  const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
  const fiche = await Fiche.findOne(query);

  if (!fiche) return res.status(404).json({ error: "Fiche non trouvée" });

  res.json(fiche);
});

/**
 * POST nouvelle fiche - POINT CLÉ DU SYSTÈME D'ANOMALIE
 *
 * Flux automatique:
 * 1. Sauvegarde de la fiche
 * 2. Création d'une mesure historique
 * 3. Détection des anomalies sur les paramètres critiques
 * 4. Envoi d'emails pour chaque anomalie détectée
 * 5. Retour des résultats au client
 */
app.post("/api/fiches", authMiddleware, async (req, res) => {
  try {
    // Étape 1: Création et sauvegarde de la fiche
    const newFiche = new Fiche({
      ...req.body,
      userEmail: req.user.email,
    });
    await newFiche.save();
    console.log(`✅ Fiche créée: ${newFiche._id}`);

    // Étape 2: Création automatique d'une mesure pour historique/graphiques
    const mesure = await createMesureFromFiche({
      ...newFiche.toObject(),
      userEmail: req.user.email,
    });
    let anomaliesDetected = [];
    let emailResults = [];

    // Étape 3: Détection des anomalies (si mesure créée avec paramètres valides)
    if (mesure) {
      anomaliesDetected = await detectAnomalies(mesure.toObject());

      // Étape 4: Envoi des notifications email pour chaque anomalie
      if (anomaliesDetected.length > 0) {
        console.log(
          `🔔 ${anomaliesDetected.length} anomalie(s) détectée(s), envoi des alertes...`,
        );

        for (const anomalie of anomaliesDetected) {
          console.log(`⏳ Préparation de l'envoi d'email pour l'anomalie : ${anomalie.type}`);
          const result = await sendAlertEmail(anomalie);
          
          if (result.success) {
            console.log(`✅ Email envoyé avec succès pour l'anomalie ${anomalie.type} à l'utilisateur.`);
          } else {
            console.error(`❌ Échec de livraison de l'email pour l'anomalie ${anomalie.type}:`, result.error);
          }

          emailResults.push({
            anomalieId: anomalie._id,
            type: anomalie.type,
            emailSent: result.success,
            messageId: result.messageId || null,
            error: result.error || null,
          });
        }
      }
    }

    // Étape 5: Réponse au client avec résumé complet
    res.status(201).json({
      success: true,
      fiche: {
        id: newFiche._id,
        idProcess: newFiche.id,
        ligne: newFiche.infos_generales?.ligne,
      },
      processing: {
        mesureCreated: !!mesure,
        mesureId: mesure?._id || null,
        anomaliesCount: anomaliesDetected.length,
        anomalies: anomaliesDetected.map((a) => ({
          id: a._id,
          type: a.type,
          valeur: a.valeur,
          seuil: a.seuil,
          severity: a.severity,
          message: a.message,
        })),
        notifications: emailResults,
      },
    });
  } catch (err) {
    console.error("❌ Erreur création fiche:", err);
    res.status(500).json({
      success: false,
      error: err.message,
      details: err.errors || null,
    });
  }
});

// DELETE fiche
app.delete("/api/fiches/:id", authMiddleware, async (req, res) => {
  const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
  await Fiche.deleteOne(query);

  res.json({ success: true });
});

// ================= ROUTES MESURES (Historique & Graphiques) =================

// GET toutes les mesures (triées chronologiquement)
app.get("/api/mesures", authMiddleware, async (req, res) => {
  try {
    const { limit = 50, ligne, startDate, endDate } = req.query;
    let query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };

    // Filtres optionnels
    if (ligne) query.ligne = ligne;
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    const mesures = await Mesure.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    res.json(mesures);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET dernière mesure (pour dashboard temps réel)
app.get("/api/mesures/latest", authMiddleware, async (req, res) => {
  try {
    const { ligne } = req.query;
    let query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
    if (ligne) query.ligne = ligne;

    const latest = await Mesure.findOne(query).sort({ timestamp: -1 });
    res.json(latest);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ROUTES ANOMALIES (Gestion des alertes) =================

// GET toutes les anomalies (avec filtres)
app.get("/api/anomalies", authMiddleware, async (req, res) => {
  try {
    const { resolved, severity, ligne, limit = 50, skip = 0 } = req.query;

    let query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };

    if (resolved !== undefined) query.resolved = resolved === "true";
    if (severity) query.severity = severity;
    if (ligne) query.ligne = ligne;

    const anomalies = await Anomalie.find(query)
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));

    const total = await Anomalie.countDocuments(query);

    res.json({
      data: anomalies,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// GET statistiques des anomalies (pour dashboard)
app.get("/api/anomalies/stats", authMiddleware, async (req, res) => {
  try {
    const queryMatch = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
    const stats = await Anomalie.aggregate([
      { $match: queryMatch },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          unresolved: {
            $sum: { $cond: [{ $eq: ["$resolved", false] }, 1, 0] },
          },
          critical: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ["$severity", "High"] },
                    { $eq: ["$resolved", false] },
                  ],
                },
                1,
                0,
              ],
            },
          },
          byType: {
            $push: {
              type: "$type",
              severity: "$severity",
              resolved: "$resolved",
            },
          },
        },
      },
    ]);

    // Statistiques par type
    const byType = await Anomalie.aggregate([
      { $match: queryMatch },
      { $group: { _id: "$type", count: { $sum: 1 } } },
    ]);

    res.json({
      total: stats[0]?.total || 0,
      unresolved: stats[0]?.unresolved || 0,
      critical: stats[0]?.critical || 0,
      byType: byType.reduce((acc, curr) => {
        acc[curr._id] = curr.count;
        return acc;
      }, {}),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT résoudre une anomalie (marquer comme traitée)
app.put("/api/anomalies/:id/resolve", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
    const anomalie = await Anomalie.findOneAndUpdate(
      query,
      {
        resolved: true,
        resolvedAt: new Date(),
      },
      { new: true },
    );

    if (!anomalie) {
      return res.status(404).json({ error: "Anomalie non trouvée" });
    }

    res.json({ success: true, anomalie });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Route manuelle pour test d'envoi d'alerte
app.post("/api/send-alert", authMiddleware, async (req, res) => {
  try {
    const { type, valeur, seuil, message, severity, ligne, ficheId } = req.body;

    // Créer une anomalie temporaire pour le test
    const testAnomalie = new Anomalie({
      type: type || "temperature_cuve",
      valeur: valeur || 90,
      seuil: seuil || 84,
      message: message || "Test alerte manuelle",
      severity: severity || "High",
      ligne: ligne || "F",
      ficheId: ficheId || "TEST-001",
    });

    const result = await sendAlertEmail(testAnomalie);
    res.json({
      success: result.success,
      messageId: result.messageId,
      error: result.error,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ROUTES PROCÉDURES (Upload/Download) =================

// POST upload fichier
app.post("/api/procedures", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Aucun fichier uploadé" });
    }

    const procedure = await Procedure.create({
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      description: req.body.description || "",
      userEmail: req.user.email,
    });

    // Trigger notification
    sendActivityEmail(req.user.email, `Nouveau document uploadé : ${procedure.originalName}`);

    res.status(201).json({
      success: true,
      procedure: {
        _id: procedure._id,
        filename: procedure.originalName,
        size: procedure.size,
        createdAt: procedure.createdAt,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET liste fichiers
app.get("/api/procedures", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
    const files = await Procedure.find(query).sort({ createdAt: -1 });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET download fichier
app.get("/api/procedures/:id/download", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
    const procedure = await Procedure.findOne(query);
    if (!procedure)
      return res.status(404).json({ error: "Fichier non trouvé" });

    res.download(procedure.path, procedure.originalName);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE fichier
app.delete("/api/procedures/:id", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
    const procedure = await Procedure.findOne(query);
    if (!procedure)
      return res.status(404).json({ error: "Fichier non trouvé" });

    // Suppression fichier physique
    if (fs.existsSync(procedure.path)) {
      fs.unlinkSync(procedure.path);
    }

    await Procedure.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ROUTES CHECKLIST =================

app.get("/api/checklists", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
    const data = await Checklist.find(query).sort({ createdAt: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/checklists", authMiddleware, async (req, res) => {
  try {
    const item = new Checklist({ ...req.body, userEmail: req.user.email });
    await item.save();
    
    // Trigger notification
    sendActivityEmail(req.user.email, "Nouvelle checklist soumise avec succès.");
    
    res.status(201).json({ success: true, id: item._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/checklists/:id", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? { _id: req.params.id } : { _id: req.params.id, userEmail: req.user.email };
    await Checklist.deleteOne(query);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ROUTE DASHBOARD (Statistiques globales) =================
app.get("/api/dashboard/stats", authMiddleware, async (req, res) => {
  try {
    const query = req.user.role === 'Admin' ? {} : { userEmail: req.user.email };
    const [
      totalFiches,
      totalChecklists,
      totalMesures,
      totalAnomalies,
      unresolvedAnomalies,
      totalProcedures,
      criticalAnomalies,
    ] = await Promise.all([
      Fiche.countDocuments(query),
      Checklist.countDocuments(query),
      Mesure.countDocuments(query),
      Anomalie.countDocuments(query),
      Anomalie.countDocuments({ ...query, resolved: false }),
      Procedure.countDocuments(query),
      Anomalie.countDocuments({ ...query, severity: "High", resolved: false }),
    ]);

    // Dernières anomalies pour affichage immédiat
    const recentAnomalies = await Anomalie.find({ ...query, resolved: false })
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      counts: {
        fiches: totalFiches,
        checklists: totalChecklists,
        mesures: totalMesures,
        anomalies: {
          total: totalAnomalies,
          unresolved: unresolvedAnomalies,
          critical: criticalAnomalies,
        },
        procedures: totalProcedures,
      },
      status:
        criticalAnomalies > 0
          ? "critical"
          : unresolvedAnomalies > 0
            ? "warning"
            : "normal",
      recentAlerts: recentAnomalies,
      thresholds: SEUILS, // Renvoyer les seuils pour référence frontend
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GLOBAL ERROR HANDLER =================
app.use(async (err, req, res, next) => {
  console.error("Global Error Handler caught an error:", err.stack);
  
  if (!res.headersSent) {
    try {
      const fromEmail = process.env.EMAIL_USER || "alertes@ocp.ma";
      const toEmail = "alertes.ocp@gmail.com"; 

      const actualToEmail = req.user && req.user.email ? req.user.email : toEmail;

      const mailOptions = {
        from: `"Système Monitoring OCP" <${fromEmail}>`,
        to: actualToEmail,
        subject: `🚨 ERREUR CRITIQUE SERVEUR 500`,
        text: `Une erreur critique système est survenue sur le serveur:\n\n${err.stack}\n\nEndpoint: ${req.method} ${req.url}\nUtilisateur affecté: ${req.user ? req.user.email : 'Non authentifié'}`,
      };

      const transporter = await getTransporter();
      const info = await transporter.sendMail(mailOptions);
      console.log(`📧 Alerte erreur 500 envoyée à ${actualToEmail}.`);
      if (nodemailer.getTestMessageUrl(info)) {
        console.log(`👁️  Voir l'email (Ethereal) : ${nodemailer.getTestMessageUrl(info)}`);
      }
    } catch (emailErr) {
      console.error("❌ Impossible d'envoyer l'alerte erreur 500:", emailErr.message);
    }
    
    res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

// ================= DÉMARRAGE SERVEUR =================
app.listen(PORT, () => {
  console.log(`🚀 Serveur OCP Monitoring lancé sur http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/api/dashboard/stats`);
  console.log(`⚙️  Seuils configurés:`, SEUILS);
  console.log(
    `📧 Email alerts: ${process.env.EMAIL_USER ? "✅ Configuré (" + process.env.EMAIL_USER + ")" : "⚠️ NON CONFIGURÉ - Définir EMAIL_USER et EMAIL_PASS"}`,
  );
});
