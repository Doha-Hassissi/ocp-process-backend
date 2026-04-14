const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ================= CONNEXION À MONGODB =================
const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ocp_process';
    await mongoose.connect(mongoUri);
    console.log('✅ Connecté à MongoDB');
    await seedDatabase();
  } catch (err) {
    console.error('❌ Erreur MongoDB :', err.message);
    process.exit(1);
  }
};

// ================= SCHEMA UTILISATEUR =================
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/@ocpgroup\.ma$/, "L'email doit se terminer par @ocpgroup.ma"]
  },
  password: { type: String, required: true },
  nom: { type: String, default: "Utilisateur OCP" },
  matricule: { type: String },
  role: { type: String, default: "User" },
  mustChangePassword: { type: Boolean, default: true }
}, { timestamps: true });

// ================= SCHEMA FICHE PROCESS =================
const ficheProcessSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  infos_generales: {
    date: Date,
    ligne: String,
    chef_equipe: String,
    operateur: String,
    code_document: String
  },
  u03_attaque: {
    niveau_m01: Number,      // 🔴 PARAMÈTRE CRITIQUE - Seuil: 100
    niveau_m02: Number,      // 🔴 PARAMÈTRE CRITIQUE - Seuil: 100
    temperature_cuve: Number, // 🔴 PARAMÈTRE CRITIQUE - Seuil: 84°C
    delta_t: Number          // 🔴 PARAMÈTRE CRITIQUE - Zone critique: 1.8-3
    
  },
  u13_stockage: {
    orientation_production: { type: String, default: "F" },
    bac_1_val: Number,
    bac_2_val: Number
  },
  compteurs: {
    h2so4: { debut: Number, fin: Number, conso: Number },
    acide_produit: { debut: Number, fin: Number, conso: Number },
    eau_brute: { debut: Number, fin: Number, conso: Number },
    heures_marche: Number
  },
  userEmail: {
  type: String,
  required: true
},
  typeDoc: { type: String, default: "PROCESS" }
}, { timestamps: true });

// ================= SCHEMA MESURE (pour historique et graphiques) =================
const mesureSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  niveau_m01: { type: Number, required: true },
  niveau_m02: { type: Number, required: true },
  temperature_cuve: { type: Number, required: true },
  delta_t: { type: Number, required: true },
  ficheId: { type: String, ref: 'FicheProcess' }, // Lien vers la fiche source
  ligne: String, // Pour filtrer par ligne de production
  userEmail: { type: String, required: true } // Propriétaire de la mesure
}, { timestamps: true });

// ================= SCHEMA ANOMALIE (Alertes critiques) =================
const anomalieSchema = new mongoose.Schema({
  type: { 
    type: String, 
    enum: ['niveau_m01', 'niveau_m02', 'temperature_cuve', 'delta_t'],
    required: true 
  },
  valeur: { type: Number, required: true },      // Valeur mesurée
  seuil: { type: Number, required: true },       // Seuil dépassé
  message: { type: String, required: true },     // Description lisible
  severity: { 
    type: String, 
    enum: ['Low', 'Med', 'High'], 
    default: 'High' 
  },
  ligne: String,                                 // Ligne de production concernée
  ficheId: { type: String, ref: 'FicheProcess' }, // Référence fiche source
  resolved: { type: Boolean, default: false },  // Statut résolution
  emailSent: { type: Boolean, default: false }, // Confirmation envoi email
  userEmail: { type: String, required: true },
  notificationCount: { type: Number, default: 1 } // Compteur pour relances
}, { timestamps: true });

// ================= SCHEMA CHECKLIST =================
const checklistSchema = new mongoose.Schema({
  date: String,
  entite: String,
  unite: String,
  zone: String,
  tag: String,
  observations: String,
  nom: String,
  matricule: String,
  userEmail: {
  type: String,
  required: true
},
}, { timestamps: true });

// ================= SCHEMA PROCÉDURE (Upload fichiers) =================
const procedureSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  path: { type: String, required: true },
  size: Number,
  mimetype: String,
  uploadedBy: { type: String, default: 'Système' },
  description: { type: String, default: '' },
  userEmail: { type: String, required: true }
}, { timestamps: true });

// ================= MODÈLES MONGOOSE =================
const User = mongoose.model('User', userSchema);
const Fiche = mongoose.model('FicheProcess', ficheProcessSchema);
const Mesure = mongoose.model('Mesure', mesureSchema);
const Anomalie = mongoose.model('Anomalie', anomalieSchema);
const Checklist = mongoose.model('Checklist', checklistSchema);
const Procedure = mongoose.model('Procedure', procedureSchema);

// ================= CONFIGURATION DES SEUILS CRITIQUES =================
const SEUILS = {
  niveau_m01: 100,        // Seuil maximum niveau M01 (%)
  niveau_m02: 100,        // Seuil maximum niveau M02 (%)
  temperature_cuve: 84,   // Seuil maximum température (°C)
  delta_t_min: 1.8,       // Borne inférieure zone critique Delta T
  delta_t_max: 3          // Borne supérieure zone critique Delta T
};

// ================= FONCTION: Créer Mesure depuis Fiche =================
/**
 * Extrait les paramètres critiques d'une fiche et crée un enregistrement Mesure
 * pour l'historique et les graphiques de tendance.
 * @param {Object} ficheData - Données de la fiche process
 * @returns {Object|null} - Document Mesure créé ou null si données insuffisantes
 */
const createMesureFromFiche = async (ficheData) => {
  try {
    const u03 = ficheData.u03_attaque || {};
    
    const mesure = await Mesure.create({
      timestamp: ficheData.infos_generales?.date || new Date(),
      niveau_m01: u03.niveau_m01 !== undefined ? parseFloat(u03.niveau_m01) : null,
      niveau_m02: u03.niveau_m02 !== undefined ? parseFloat(u03.niveau_m02) : null,
      temperature_cuve: u03.temperature_cuve !== undefined ? parseFloat(u03.temperature_cuve) : null,
      delta_t: u03.delta_t !== undefined ? parseFloat(u03.delta_t) : null,
      ficheId: ficheData.id || ficheData._id?.toString(),
      ligne: ficheData.infos_generales?.ligne || 'Inconnue',
      userEmail: ficheData.userEmail
    });

    console.log('✅ Mesure créée depuis fiche:', mesure._id);
    return mesure;
  } catch (err) {
    console.error('❌ Erreur création mesure:', err.message);
    return null;
  }
};

// ================= FONCTION: Détecter et Créer Anomalies =================
/**
 * Analyse les paramètres critiques et crée des alertes pour chaque dépassement.
 * Vérifie:
 * - niveau_m01 >= 100%
 * - niveau_m02 >= 100%
 * - temperature_cuve >= 84°C
 * - delta_t entre 1.8 et 3 (zone critique à éviter)
 * 
 * @param {Object} mesureData - Données de mesure avec paramètres critiques
 * @returns {Array} - Liste des anomalies détectées et sauvegardées
 */
const detectAnomalies = async (mesureData) => {
  const anomalies = [];
  const { 
    niveau_m01, 
    niveau_m02, 
    temperature_cuve, 
    delta_t, 
    ficheId, 
    ligne 
  } = mesureData;

  // Conversion explicite en nombres pour éviter les erreurs de comparaison
  const n_m01 = parseFloat(niveau_m01);
  const n_m02 = parseFloat(niveau_m02);
  const temp = parseFloat(temperature_cuve);
  const d_t = parseFloat(delta_t);

  // 🔴 ANOMALIE: Niveau M01 critique (≥ 100%)
  if (!isNaN(n_m01) && n_m01 >= SEUILS.niveau_m01) {
    anomalies.push({
      type: 'niveau_m01',
      valeur: n_m01,
      seuil: SEUILS.niveau_m01,
      message: `🚨 Niveau M01 CRITIQUE: ${n_m01}% (seuil: ${SEUILS.niveau_m01}%) - Risque de débordement`,
      severity: 'High'
    });
  }

  // 🔴 ANOMALIE: Niveau M02 critique (≥ 100%)
  if (!isNaN(n_m02) && n_m02 >= SEUILS.niveau_m02) {
    anomalies.push({
      type: 'niveau_m02',
      valeur: n_m02,
      seuil: SEUILS.niveau_m02,
      message: `🚨 Niveau M02 CRITIQUE: ${n_m02}% (seuil: ${SEUILS.niveau_m02}%) - Risque de débordement`,
      severity: 'High'
    });
  }

  // 🔴 ANOMALIE: Température cuve critique (≥ 84°C)
  if (!isNaN(temp) && temp >= SEUILS.temperature_cuve) {
    anomalies.push({
      type: 'temperature_cuve',
      valeur: temp,
      seuil: SEUILS.temperature_cuve,
      message: `🚨 Température cuve CRITIQUE: ${temp}°C (seuil: ${SEUILS.temperature_cuve}°C) - Risque thermique`,
      severity: 'High'
    });
  }

  // 🟡 ANOMALIE: Delta T dans zone critique (entre 1.8 et 3)
  // Cette plage représente une zone de fonctionnement dangereuse à éviter
  if (!isNaN(d_t) && d_t >= SEUILS.delta_t_min && d_t <= SEUILS.delta_t_max) {
  anomalies.push({
    type: 'delta_t',
    valeur: d_t,
    seuil: `${SEUILS.delta_t_min}-${SEUILS.delta_t_max}`,
    message: `⚠️ Delta T hors plage normale: ${d_t}`,
    severity: 'High'
  });
}

  // Sauvegarde des anomalies en base de données
  const savedAnomalies = [];
  for (const anomalie of anomalies) {
    try {
      const saved = await Anomalie.create({
  ...anomalie,
  ficheId: ficheId || null,
  ligne: ligne || 'Inconnue',
  resolved: false,
  emailSent: false,
  userEmail: mesureData.userEmail
});
      savedAnomalies.push(saved);
      console.log(`🚨 Anomalie détectée et sauvegardée [ID: ${saved._id}]: ${anomalie.message}`);
    } catch (err) {
      console.error('❌ Erreur sauvegarde anomalie:', err.message);
    }
  }

  return savedAnomalies;
};

// ================= FONCTION: Vérifier Anomalies Existantes (Éviter doublons) =================
/**
 * Vérifie si une anomalie similaire existe déjà (non résolue) pour éviter
 * les notifications répétitives inutiles.
 */
const checkExistingAnomaly = async (type, ficheId, timeframeMinutes = 30) => {
  const cutoffTime = new Date(Date.now() - timeframeMinutes * 60000);
  
  return await Anomalie.findOne({
    type,
    ficheId,
    resolved: false,
    createdAt: { $gte: cutoffTime }
  });
};

// ================= SEED DATABASE =================
const seedDatabase = async () => {
  try {
    // Création admin par défaut si aucun utilisateur
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log('🌱 Création Admin par défaut...');
      const hashedPassword = await bcrypt.hash('ocp123', 10);
      await User.create({
        email: 'admin@ocpgroup.ma',
        password: hashedPassword,
        nom: 'Admin Principal',
        matricule: '0000A',
        role: 'Admin',
        mustChangePassword: false
      });
      console.log('✅ Admin créé: admin@ocpgroup.ma / ocp123');
    }
  } catch (err) {
    console.error('❌ Erreur Seed Database :', err.message);
  }
};

// ================= EXPORT =================
module.exports = {
  connectDB,
  User,
  Fiche,
  Mesure,
  Anomalie,
  Checklist,
  Procedure,
  createMesureFromFiche,
  detectAnomalies,
  checkExistingAnomaly,
  SEUILS // Export pour référence dans d'autres modules
};