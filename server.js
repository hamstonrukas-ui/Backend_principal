const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CONNEXION POSTGRESQL
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

console.log('🔗 Pool PostgreSQL créé');

async function initStorage() {
  try {
    const client = await pool.connect();
    console.log('💾 PostgreSQL connecté avec succès');
    client.release();
  } catch (error) {
    console.error('❌ Erreur connexion PostgreSQL:', error.message);
    console.error('Vérifiez votre variable DATABASE_URL');
    process.exit(1);
  }
}

// ===== CONFIGURATION CORS =====
// Autorise plusieurs origines : l'app principale ET le dashboard admin.
// FRONTEND_URL peut contenir une liste séparée par des virgules, ex:
//   https://kivirafacilee.vercel.app,https://kivirafacile-admin.vercel.app
const defaultOrigins = [
  'https://kivirafacilee.vercel.app',
  'https://kivirafacile-admin.vercel.app',
  'http://localhost:8000'
];

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(o => o.trim())
  : defaultOrigins;

console.log('📍 Origines CORS autorisées:', allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    // Autoriser les requêtes sans origine (ex: Postman, curl, apps mobiles)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    console.warn(`⚠️ CORS refusé pour l'origine: ${origin}`);
    return callback(new Error('Non autorisé par CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Password', 'X-Device-Fingerprint']
};

app.use(cors(corsOptions));
app.use(express.json());

// ===== CONFIGURATION PAIEMENT MANUEL =====
const PAYMENT_CONFIG = {
  airtelNumber: '+243 97 805 0574',
  airtelAccountName: 'Mulezi Hamston',
  orangeNumber: '+243 85 421 7357',
  orangeAccountName: 'Sauveur Mulopwe',
  mpesaNumber: '+243 83 442 4452',
  mpesaAccountName: 'Alexis',
  amount: '1000',
  currency: 'FC',
  temporaryPremiumDuration: 48
};

// ===== CONFIGURATION ANTI-FRAUDE =====
const FRAUD_PROTECTION = {
  maxAccountsPerIP: 3,
  maxAccountsPerDevice: 2,
  maxPaymentsPerHour: 2,
  ipBlockDuration: 24 * 60 * 60 * 1000,
  paymentCooldown: 60 * 60 * 1000,
  allowDeviceChange: false,
  maxFailedPaymentAttempts: 5 // bloqué après ce nombre de tentatives ratées (mauvais ID/numéro)
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// VALIDATION INTELLIGENTE — Transaction ID et numéro de téléphone
// Objectif : rejeter poliment (retry), jamais bloquer le compte
// pour une simple erreur de saisie ou un format inhabituel.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Format observé sur les SMS de confirmation Mobile Money en RDC :
// MP260308.1429.H23086  →  MP + AAMMJJ + . + HHMM + . + Lettre + 5 chiffres
// Le préfixe devant (TID:, Ref:, Référence:, Trans ID:, Transaction:, ...) varie
// selon l'opérateur et n'est plus exigé — on cherche le cœur invariant
// (date.heure.numéro) n'importe où dans la chaîne saisie.
const TRANSACTION_ID_CORE_REGEX = /([A-Z]{2}\d{6})\.(\d{4})\.([A-Z]\d{5})/i;

// Format réel M-Pesa (Vodacom) observé sur SMS : ex. DGE866QPHO4, DGH76751R8X.
// Pas de points, 10 à 12 caractères alphanumériques commençant par une lettre.
// On ne le cherche pas "n'importe où" comme le format à points (trop générique,
// risque de faux positifs dans une phrase) : on retire juste un préfixe connu
// puis on exige que le reste corresponde exactement.
const TRANSACTION_ID_MPESA_REGEX = /^[A-Z][A-Z0-9]{9,11}$/i;
const KNOWN_ID_PREFIX_REGEX = /^(TID|REF|REFERENCE|R[EÉ]F[EÉ]RENCE|TRANSACTION\s*ID|TRANSACTION|ID)\s*:?\s*/i;

function validateTransactionIdFormat(rawId) {
  const cleaned = (rawId || '').trim().toUpperCase();
  const match = cleaned.match(TRANSACTION_ID_CORE_REGEX);

  if (match) {
    // On normalise sur le seul cœur (sans préfixe), pour que la détection de
    // doublon fonctionne peu importe comment l'utilisateur a copié son SMS
    // (ex: "TID: MP250726..." et "Ref:MP250726..." → même ID normalisé).
    return { valid: true, normalized: `${match[1]}.${match[2]}.${match[3]}` };
  }

  const withoutPrefix = cleaned.replace(KNOWN_ID_PREFIX_REGEX, '').trim();
  if (TRANSACTION_ID_MPESA_REGEX.test(withoutPrefix)) {
    return { valid: true, normalized: withoutPrefix };
  }

  return {
    valid: false,
    error: "Ce Transaction ID ne ressemble pas à un vrai identifiant de transaction. " +
           "Il doit correspondre à la référence indiquée dans le SMS de confirmation " +
           "(ex: MP250726.1900.H23086 ou DGE866QPHO4 pour M-Pesa), avec ou sans préfixe " +
           "(TID:, Ref:, Référence:...). Vérifiez et réessayez."
  };
}

// Préfixes réseau en RDC — à titre indicatif seulement (portabilité des
// numéros = pas 100% fiable). Sert à AVERTIR, jamais à bloquer à lui seul.
const OPERATOR_PREFIXES = {
  mpesa:  ['81', '82', '83'],
  orange: ['80', '84', '85', '89', '90'],
  airtel: ['96', '97', '98', '99']
};
const OPERATOR_LABELS = { mpesa: 'M-Pesa (Vodacom)', orange: 'Orange Money', airtel: 'Airtel Money' };

function validateCongoPhoneNumber(rawPhone) {
  const digits = (rawPhone || '').replace(/\D/g, ''); // enlève espaces, points, tirets, +
  let local = digits;
  if (local.startsWith('243')) local = local.slice(3);
  if (local.length === 9) local = '0' + local;

  if (local.length !== 10 || local[0] !== '0') {
    return {
      valid: false,
      error: 'Numéro de téléphone invalide. Entrez un numéro congolais valide (9 ou 10 chiffres), par exemple 0991234567 — chiffres uniquement, pas de points ni de tirets.'
    };
  }

  const prefix = local.substring(1, 3);
  let detectedOperator = null;
  for (const [op, prefixes] of Object.entries(OPERATOR_PREFIXES)) {
    if (prefixes.includes(prefix)) { detectedOperator = op; break; }
  }

  return { valid: true, normalized: local, detectedOperator };
}

// Incrémente le compteur d'échecs de paiement de l'utilisateur.
// Si le seuil est atteint, bloque le compte (et l'appareil) et le signale.
async function registerFailedPaymentAttempt(user, deviceFingerprint) {
  const result = await pool.query(
    'UPDATE users SET paymentFailedAttempts = COALESCE(paymentFailedAttempts, 0) + 1 WHERE uuid = $1 RETURNING paymentFailedAttempts',
    [user.uuid]
  );
  const attempts = result.rows[0] ? result.rows[0].paymentfailedattempts : 1;

  if (attempts >= FRAUD_PROTECTION.maxFailedPaymentAttempts) {
    await pool.query('UPDATE users SET isBlocked = $1 WHERE uuid = $2', [true, user.uuid]);
    if (deviceFingerprint) {
      await blockDevice(deviceFingerprint, `${attempts} tentatives de paiement invalides`);
    }
    console.log(`🚨 Compte bloqué après ${attempts} tentatives de paiement invalides: ${user.uuid}`);
    return { blocked: true, attempts };
  }

  return { blocked: false, attempts, remaining: FRAUD_PROTECTION.maxFailedPaymentAttempts - attempts };
}

async function resetFailedPaymentAttempts(uuid) {
  await pool.query('UPDATE users SET paymentFailedAttempts = 0 WHERE uuid = $1', [uuid]);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FONCTIONS DE STOCKAGE PostgreSQL
// (une seule version propre — l'ancien fichier en avait 3 copies)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function getUsers() {
  const result = await pool.query('SELECT * FROM users');
  return result.rows;
}

async function getPayments() {
  const result = await pool.query('SELECT * FROM payments ORDER BY submittedAt DESC');
  return result.rows;
}

async function getBlockedPhones() {
  const result = await pool.query('SELECT * FROM blockedPhones');
  return result.rows;
}

async function getBlockedDevices() {
  const result = await pool.query('SELECT * FROM blockedDevices');
  return result.rows;
}

async function getTranslations() {
  const result = await pool.query('SELECT * FROM translations');
  return result.rows;
}
// Note : pas de saveUsers()/savePayments()/saveTranslations() — les INSERT/UPDATE
// se font directement dans les routes via pool.query(), comme pour le reste du fichier.

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ⚠️ NOTE IMPORTANTE SUR LA CASSE DES COLONNES (spécifique PostgreSQL)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PostgreSQL met automatiquement en minuscules les noms de colonnes non
// "quotées" (isPremium → ispremium en base). Le texte des requêtes SQL
// ci-dessous (ex: "SELECT isPremium FROM ...") fonctionne sans souci —
// PostgreSQL fait lui-même la conversion en minuscules pour comparer.
// MAIS quand on lit le résultat en JavaScript, il FAUT utiliser la version
// minuscule : row.ispremium (pas row.isPremium), row.devicefingerprint,
// row.premiumexpiresat, row.useruuid, row.transactionid, row.phonenumber,
// row.submittedat, row.validatedat, row.paymentuuid, row.username,
// row.useremail, row.registrationip, row.createdat, row.isblocked,
// row.sourcetext, row.translatedtext, row.savedat.
// Toutes les lectures ci-dessous respectent déjà cette règle.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ===== MIDDLEWARE D'AUTHENTIFICATION =====
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Accès refusé. Token manquant.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'votre_secret_jwt', async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide ou expiré.' });
    }

    const users = await getUsers();
    const user = users.find(u => u.uuid === decoded.uuid);

    if (!user) {
      return res.status(403).json({ error: 'Utilisateur non trouvé.' });
    }

    // NOTE: la vérification de l'appareil (device fingerprint) ne se fait
    // désormais QU'À LA CONNEXION (/api/auth/login), pas ici. La revérifier
    // à chaque requête authentifiée (donc à chaque actualisation de page)
    // causait des faux blocages pour des utilisateurs légitimes dont le
    // fingerprint pouvait varier légèrement d'une session à l'autre.
    // Le token JWT valide suffit à prouver l'identité pour la durée de
    // la session (30 jours).

    req.user = decoded;
    next();
  });
};

// ===== FONCTIONS UTILITAIRES =====

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress;
}

async function isPhoneBlocked(phoneNumber) {
  const cleanNumber = phoneNumber.replace(/\s/g, '');
  const result = await pool.query(
    'SELECT COUNT(*) as count FROM blockedPhones WHERE number = $1',
    [cleanNumber]
  );
  return parseInt(result.rows[0].count, 10) > 0;
}

async function blockPhoneNumber(phoneNumber, reason) {
  const cleanNumber = phoneNumber.replace(/\s/g, '');

  if (!await isPhoneBlocked(cleanNumber)) {
    await pool.query(
      'INSERT INTO blockedPhones (number, reason, blockedAt) VALUES ($1, $2, $3)',
      [cleanNumber, reason, new Date()]
    );
    console.log(`🚫 Numéro bloqué: ${cleanNumber} - Raison: ${reason}`);
  }
}

async function isDeviceBlocked(deviceFingerprint) {
  const result = await pool.query(
    'SELECT COUNT(*) as count FROM blockedDevices WHERE fingerprint = $1',
    [deviceFingerprint]
  );
  return parseInt(result.rows[0].count, 10) > 0;
}

async function blockDevice(deviceFingerprint, reason) {
  if (!await isDeviceBlocked(deviceFingerprint)) {
    await pool.query(
      'INSERT INTO blockedDevices (fingerprint, reason, blockedAt) VALUES ($1, $2, $3)',
      [deviceFingerprint, reason, new Date()]
    );
    console.log(`🚫 Appareil bloqué: ${deviceFingerprint} - Raison: ${reason}`);
  }
}

async function checkIPAccountLimit(ip) {
  const result = await pool.query(
    'SELECT COUNT(*) as count FROM ip_tracking WHERE ip_address = $1',
    [ip]
  );
  return parseInt(result.rows[0].count, 10) < FRAUD_PROTECTION.maxAccountsPerIP;
}

async function checkPaymentRateLimit(uuid) {
  const result = await pool.query(
    `SELECT COUNT(*) as count FROM payments
     WHERE userUuid = $1
     AND submittedAt > NOW() - INTERVAL '1 hour'
     AND status != 'REJECTED'`,
    [uuid]
  );
  return parseInt(result.rows[0].count, 10) < FRAUD_PROTECTION.maxPaymentsPerHour;
}

async function checkDeviceAccountLimit(deviceFingerprint) {
  const blockedResult = await pool.query(
    'SELECT COUNT(*) as count FROM users WHERE deviceFingerprint = $1 AND isBlocked = true',
    [deviceFingerprint]
  );

  if (parseInt(blockedResult.rows[0].count, 10) > 0) {
    return {
      allowed: false,
      reason: 'DEVICE_HAS_FRAUD',
      message: 'Cet appareil a été utilisé pour fraude. Impossible de créer un nouveau compte.'
    };
  }

  const countResult = await pool.query(
    'SELECT COUNT(*) as count FROM users WHERE deviceFingerprint = $1',
    [deviceFingerprint]
  );

  if (parseInt(countResult.rows[0].count, 10) >= FRAUD_PROTECTION.maxAccountsPerDevice) {
    return {
      allowed: false,
      reason: 'DEVICE_LIMIT_REACHED',
      message: `Maximum ${FRAUD_PROTECTION.maxAccountsPerDevice} comptes par appareil atteint.`
    };
  }

  return { allowed: true };
}

// Statistiques d'un appareil (pour l'admin) — pas encore branchée à une route
async function getDeviceStats(deviceFingerprint) {
  const users = await getUsers();
  const accountsOnDevice = users.filter(u => u.devicefingerprint === deviceFingerprint);

  return {
    totalAccounts: accountsOnDevice.length,
    blockedAccounts: accountsOnDevice.filter(u => u.isblocked).length,
    activeAccounts: accountsOnDevice.filter(u => !u.isblocked).length,
    accounts: accountsOnDevice.map(u => ({
      uuid: u.uuid,
      email: u.email,
      name: u.name,
      isBlocked: u.isblocked,
      isPremium: u.ispremium,
      createdAt: u.createdat
    }))
  };
}

// ===== ROUTES D'AUTHENTIFICATION =====

// Inscription
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const clientIP = getClientIP(req);
    const deviceFingerprint = req.headers['x-device-fingerprint'];

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });
    }

    if (!deviceFingerprint) {
      return res.status(400).json({ error: 'Impossible d\'identifier votre appareil.' });
    }

    if (await isDeviceBlocked(deviceFingerprint)) {
      console.log(`🚨 FRAUDE: Appareil bloqué tente de s'inscrire: ${deviceFingerprint}`);
      return res.status(403).json({ error: 'Cet appareil a été bloqué pour fraude.' });
    }

    const deviceCheck = await checkDeviceAccountLimit(deviceFingerprint);
    if (!deviceCheck.allowed) {
      console.log(`🚨 FRAUDE: ${deviceCheck.reason} - Device: ${deviceFingerprint.substring(0, 8)}...`);
      return res.status(403).json({ error: deviceCheck.message });
    }

    const existingResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    if (existingResult.rows[0]) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé.' });
    }

    if (!await checkIPAccountLimit(clientIP)) {
      console.log(`🚨 FRAUDE: Trop de comptes depuis IP ${clientIP}`);
      return res.status(403).json({
        error: `Trop de comptes créés depuis cette connexion. Limite: ${FRAUD_PROTECTION.maxAccountsPerIP} comptes.`
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userUuid = uuidv4();

    await pool.query(
      `INSERT INTO users (uuid, name, email, password, isPremium, isBlocked,
                         premiumExpiresAt, registrationIP, deviceFingerprint, createdAt)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [userUuid, name, email, hashedPassword, false, false,
       null, clientIP, deviceFingerprint, new Date()]
    );

    await pool.query(
      'INSERT INTO ip_tracking (ip_address, userUuid) VALUES ($1, $2)',
      [clientIP, userUuid]
    );

    const token = jwt.sign(
      { uuid: userUuid, email: email },
      process.env.JWT_SECRET || 'votre_secret_jwt',
      { expiresIn: '30d' }
    );

    console.log(`✅ Nouveau compte créé: ${email} (UUID: ${userUuid}) depuis IP ${clientIP} Device: ${deviceFingerprint.substring(0, 8)}...`);

    res.status(201).json({
      message: 'Compte créé avec succès !',
      token,
      user: {
        uuid: userUuid,
        name,
        email,
        isPremium: false
      }
    });

  } catch (error) {
    console.error('Erreur inscription:', error);
    res.status(500).json({ error: 'Erreur lors de l\'inscription.' });
  }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const deviceFingerprint = req.headers['x-device-fingerprint'];

    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis.' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
    }

    if (user.isblocked) {
      return res.status(403).json({
        error: 'Votre compte a été bloqué pour activité suspecte. Contactez le support.'
      });
    }

    if (user.devicefingerprint && deviceFingerprint && user.devicefingerprint !== deviceFingerprint) {
      if (!FRAUD_PROTECTION.allowDeviceChange) {
        console.log(`🚨 DEVICE MISMATCH: User ${user.uuid} tente de se connecter depuis un autre appareil`);
        return res.status(403).json({
          error: 'Ce compte est lié à un autre appareil. Vous ne pouvez pas vous connecter depuis cet appareil.',
          code: 'DEVICE_MISMATCH'
        });
      }
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
    }

    if (!user.devicefingerprint && deviceFingerprint) {
      await pool.query(
        'UPDATE users SET deviceFingerprint = $1 WHERE uuid = $2',
        [deviceFingerprint, user.uuid]
      );
      user.devicefingerprint = deviceFingerprint;
      console.log(`🔄 Device fingerprint mis à jour pour ${user.email} après déblocage`);
    }

    // Vérifier expiration premium
    let isPremium = user.ispremium;
    let premiumExpiresAt = user.premiumexpiresat;
    if (premiumExpiresAt && new Date() > new Date(premiumExpiresAt)) {
      await pool.query(
        'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
        [false, null, user.uuid]
      );
      isPremium = false;
      premiumExpiresAt = null;
    }

    const token = jwt.sign(
      { uuid: user.uuid, email: user.email },
      process.env.JWT_SECRET || 'votre_secret_jwt',
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Connexion réussie !',
      token,
      user: {
        uuid: user.uuid,
        name: user.name,
        email: user.email,
        isPremium,
        premiumExpiresAt
      }
    });

  } catch (error) {
    console.error('Erreur connexion:', error);
    res.status(500).json({ error: 'Erreur lors de la connexion.' });
  }
});

// Récupérer les informations de l'utilisateur connecté
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const users = await getUsers();
    const user = users.find(u => u.uuid === req.user.uuid);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    let isPremium = user.ispremium;
    let premiumExpiresAt = user.premiumexpiresat;

    if (premiumExpiresAt && new Date() > new Date(premiumExpiresAt)) {
      await pool.query(
        'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
        [false, null, user.uuid]
      );
      isPremium = false;
      premiumExpiresAt = null;
    }

    // Vérifier expiration premium traduction
    let isTranslationPremium = user.istranslationpremium;
    let translationPremiumExpiresAt = user.translationpremiumexpiresat;

    if (translationPremiumExpiresAt && new Date() > new Date(translationPremiumExpiresAt)) {
      await pool.query(
        'UPDATE users SET isTranslationPremium = $1, translationPremiumExpiresAt = $2 WHERE uuid = $3',
        [false, null, user.uuid]
      );
      isTranslationPremium = false;
      translationPremiumExpiresAt = null;
    }

    res.json({
      
      uuid: user.uuid,
      name: user.name,
      email: user.email,
      isPremium,
      premiumExpiresAt,
      isBlocked: user.isblocked,
      isTranslationPremium,
      translationPremiumExpiresAt
    });
  } catch (error) {
    console.error('Erreur /api/auth/me:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===== ROUTES PAIEMENT MANUEL =====

app.get('/api/payments/instructions', authenticateToken, (req, res) => {
  res.json({
    instructions: `
💰 INSTRUCTIONS DE PAIEMENT

Envoyez ${PAYMENT_CONFIG.amount} ${PAYMENT_CONFIG.currency} à l'un de ces numéros :

📱 Airtel Money : ${PAYMENT_CONFIG.airtelNumber} (${PAYMENT_CONFIG.airtelAccountName})
📱 Orange Money : ${PAYMENT_CONFIG.orangeNumber} (${PAYMENT_CONFIG.orangeAccountName})
📱 M-Pesa (Vodacom) : ${PAYMENT_CONFIG.mpesaNumber} (${PAYMENT_CONFIG.mpesaAccountName})

⚠️ IMPORTANT :
1. Le montant EXACT doit être ${PAYMENT_CONFIG.amount} ${PAYMENT_CONFIG.currency}
2. Une fois le paiement effectué, vous recevrez un Transaction ID
3. Revenez sur cette page et entrez le Transaction ID
4. Vous aurez un accès premium temporaire pendant la vérification
5. Nous validerons votre paiement sous 24h maximum

❌ Fraude = Blocage définitif du compte, numéro ET appareil
    `.trim(),
    config: PAYMENT_CONFIG
  });
});

// Statut des paiements de l'utilisateur connecté (par type de produit)
// Utilisé côté client pour savoir s'il faut ré-afficher le formulaire de
// paiement ou plutôt un écran "vérification en cours" (cas Traduction).
app.get('/api/payments/my-status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT productType, status, submittedAt, validatedAt
       FROM payments
       WHERE userUuid = $1
       ORDER BY submittedAt DESC`,
      [req.user.uuid]
    );

    const latestByType = {};
    for (const row of result.rows) {
      const type = row.producttype || 'general';
      if (!latestByType[type]) {
        latestByType[type] = {
          status: row.status,
          submittedAt: row.submittedat,
          validatedAt: row.validatedat
        };
      }
    }

    res.json({
      general: latestByType.general || null,
      translation: latestByType.translation || null
    });
  } catch (error) {
    console.error('Erreur /api/payments/my-status:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Soumettre un Transaction ID
app.post('/api/payments/submit', authenticateToken, async (req, res) => {
  try {
    const { transactionId, phoneNumber, operator: operatorRaw } = req.body;
    // Normaliser la casse : les deux formulaires (paiement général et
    // traduction) n'envoient pas la même casse ("airtel" vs "Airtel"),
    // et cette comparaison doit fonctionner peu importe laquelle.
    const operator = (operatorRaw || '').toLowerCase();
    const deviceFingerprint = req.headers['x-device-fingerprint'];

    const users = await getUsers();
    const user = users.find(u => u.uuid === req.user.uuid);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé.' });
    }

    if (user.isblocked) {
      return res.status(403).json({ error: 'Votre compte est bloqué.' });
    }

    if (!transactionId || !phoneNumber || !operator) {
      return res.status(400).json({
        error: 'Transaction ID, numéro et opérateur requis.'
      });
    }

    // VALIDATION : le Transaction ID doit ressembler à un vrai identifiant
    const idCheck = validateTransactionIdFormat(transactionId);
    if (!idCheck.valid) {
      const attempt = await registerFailedPaymentAttempt(user, deviceFingerprint);
      if (attempt.blocked) {
        return res.status(403).json({
          error: `Trop de tentatives avec un Transaction ID invalide. Votre compte a été bloqué. Contactez le support si c'est une erreur.`
        });
      }
      return res.status(400).json({
        error: `${idCheck.error} (${attempt.remaining} tentative(s) restante(s) avant blocage du compte)`
      });
    }

    // VALIDATION : le numéro doit être un vrai numéro congolais (chiffres uniquement)
    const phoneCheck = validateCongoPhoneNumber(phoneNumber);
    if (!phoneCheck.valid) {
      const attempt = await registerFailedPaymentAttempt(user, deviceFingerprint);
      if (attempt.blocked) {
        return res.status(403).json({
          error: `Trop de tentatives avec un numéro invalide. Votre compte a été bloqué. Contactez le support si c'est une erreur.`
        });
      }
      return res.status(400).json({
        error: `${phoneCheck.error} (${attempt.remaining} tentative(s) restante(s) avant blocage du compte)`
      });
    }

    // AVERTISSEMENT : le préfixe ne correspond pas à l'opérateur choisi
    // (compte aussi comme tentative ratée : soit le numéro, soit l'opérateur est faux)
    if (phoneCheck.detectedOperator && phoneCheck.detectedOperator !== operator) {
      const attempt = await registerFailedPaymentAttempt(user, deviceFingerprint);
      if (attempt.blocked) {
        return res.status(403).json({
          error: `Trop de tentatives avec un numéro/opérateur incohérents. Votre compte a été bloqué. Contactez le support si c'est une erreur.`
        });
      }
      return res.status(400).json({
        error: `Ce numéro ressemble à un numéro ${OPERATOR_LABELS[phoneCheck.detectedOperator]}, ` +
               `mais vous avez sélectionné ${OPERATOR_LABELS[operator] || operator}. ` +
               `Vérifiez votre numéro ou l'opérateur sélectionné. (${attempt.remaining} tentative(s) restante(s) avant blocage du compte)`
      });
    }

    
    // PROTECTION: Numéro bloqué (seulement si explicitement bloqué par admin pour fraude)
// Un numéro peut payer plusieurs fois légitimement (abonnement général + traduction)
if (await isPhoneBlocked(phoneNumber)) {
    console.log(`⚠️ Numéro bloqué tente un paiement: ${phoneNumber}`);
    return res.status(403).json({
        error: 'Ce numéro de téléphone a été signalé. Contactez le support.'
    });
    // Note: on NE bloque plus le compte automatiquement
    // Un admin a explicitement bloqué ce numéro → juste refuser, pas bloquer le compte
      }

    // PROTECTION: Limite paiements par heure
    if (!await checkPaymentRateLimit(user.uuid)) {
      console.log(`🚨 FRAUDE: User ${user.uuid} tente trop de paiements rapidement`);

      return res.status(429).json({
        error: `Trop de tentatives de paiement. Maximum ${FRAUD_PROTECTION.maxPaymentsPerHour} par heure. Réessayez plus tard.`
      });
    }

    // Transaction ID déjà utilisé : on REFUSE la soumission, mais on ne
    // bloque plus automatiquement les comptes/appareils. Un ID dupliqué
    // peut venir d'une simple erreur (double-clic, coquille) — la décision
    // de bloquer pour fraude avérée reste un choix humain, fait par un
    // admin depuis le dashboard (bouton "Rejeter pour fraude").
    const existingResult = await pool.query(
      'SELECT * FROM payments WHERE transactionId = $1',
      [idCheck.normalized]
    );

    if (existingResult.rows.length > 0) {
      console.log(`⚠️ Transaction ID déjà utilisé: ${idCheck.normalized} (nouvelle tentative par ${user.uuid})`);

      const attempt = await registerFailedPaymentAttempt(user, deviceFingerprint);
      if (attempt.blocked) {
        return res.status(403).json({
          error: `Trop de tentatives avec un Transaction ID déjà utilisé. Votre compte a été bloqué. Contactez le support si c'est une erreur.`
        });
      }
      return res.status(409).json({
        error: 'Ce Transaction ID a déjà été utilisé pour un autre paiement. ' +
               'Vérifiez que vous avez bien copié le bon ID depuis votre SMS de confirmation. ' +
               `(${attempt.remaining} tentative(s) restante(s) avant blocage du compte)`
      });
    }

    

  // Récupérer productType depuis le body (general ou translation)
    const productType = req.body.productType === 'translation' ? 'translation' : 'general';
    const amount = productType === 'translation' ? '2000' : PAYMENT_CONFIG.amount;

    const paymentUuid = uuidv4();

    // Succès : on remet le compteur de tentatives ratées à zéro
    await resetFailedPaymentAttempts(user.uuid);

    await pool.query(
        `INSERT INTO payments (paymentUuid, userUuid, userName, userEmail,
                              transactionId, phoneNumber, operator, amount, currency,
                              status, deviceFingerprint, submittedAt, validatedAt, productType)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [paymentUuid, user.uuid, user.name, user.email,
         idCheck.normalized, phoneCheck.normalized, operator,
         amount, PAYMENT_CONFIG.currency,
         'PENDING', deviceFingerprint, new Date(), null, productType]
    );

    // Premium temporaire — UNIQUEMENT pour l'accès général (leçons/dictionnaire).
    // Pour la traduction : plus d'accès temporaire automatique, la qualité du
    // service n'est pas encore fiable à 100% — l'utilisateur doit attendre la
    // validation manuelle avant d'avoir accès, pour éviter que quelqu'un
    // "jette un coup d'œil" sans avoir vraiment payé.
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + PAYMENT_CONFIG.temporaryPremiumDuration);

    if (productType === 'translation') {
      // Rien à activer ici : isTranslationPremium ne sera mis à true que
      // lorsqu'un admin approuve le paiement depuis le dashboard.
      console.log(`💳 Paiement traduction soumis (en attente de validation manuelle): User ${user.uuid}`);
    } else {
      await pool.query(
        'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
        [true, expiresAt, user.uuid]
      );
      }

    console.log(`💳 Paiement soumis: ${productType} - ${amount} FC - User: ${user.uuid}`);

    res.json({
      message: 'Transaction ID soumis avec succès !',
      payment: {
        uuid: paymentUuid,
        status: 'PENDING',
        submittedAt: new Date(),
        productType: productType
      },
      premium: productType === 'translation'
        ? {
            isTemporary: false,
            expiresAt: null,
            message: 'Votre paiement est en cours de vérification. L\'accès traduction sera activé après validation manuelle (généralement sous 24h).'
          }
        : {
            isTemporary: true,
            expiresAt,
            message: `Accès temporaire activé (${PAYMENT_CONFIG.temporaryPremiumDuration}h)`
          }
    });

  } catch (error) {
    console.error('Erreur soumission paiement:', error);
    res.status(500).json({ error: 'Erreur lors de la soumission.' });
  }
});

// ===== ROUTES ADMIN =====
// ===== ROUTES ADMIN =====

app.get('/api/admin/payments', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const payments = await getPayments();

    const stats = {
      pending: payments.filter(p => p.status === 'PENDING').length,
      approved: payments.filter(p => p.status === 'APPROVED').length,
      rejected: payments.filter(p => p.status === 'REJECTED').length,
      total: payments.length
    };

    res.json({ payments, stats });
  } catch (error) {
    console.error('Erreur récupération paiements:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/admin/payments/all', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const payments = await getPayments();
    res.json({ payments });
  } catch (error) {
    console.error('Erreur récupération paiements (all):', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/admin/stats', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const usersCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const blockedUsersCount = await pool.query('SELECT COUNT(*) as count FROM users WHERE isBlocked = true');
    const blockedPhonesCount = await pool.query('SELECT COUNT(*) as count FROM blockedPhones');
    const blockedDevicesCount = await pool.query('SELECT COUNT(*) as count FROM blockedDevices');
    const paymentsCount = await pool.query('SELECT COUNT(*) as count FROM payments');
    const pendingCount = await pool.query("SELECT COUNT(*) as count FROM payments WHERE status = 'PENDING'");
    const approvedCount = await pool.query("SELECT COUNT(*) as count FROM payments WHERE status = 'APPROVED'");
    const rejectedCount = await pool.query("SELECT COUNT(*) as count FROM payments WHERE status = 'REJECTED'");

    res.json({
      totalUsers: parseInt(usersCount.rows[0].count, 10),
      blockedUsers: parseInt(blockedUsersCount.rows[0].count, 10),
      blockedPhoneNumbers: parseInt(blockedPhonesCount.rows[0].count, 10),
      blockedDevices: parseInt(blockedDevicesCount.rows[0].count, 10),
      totalPayments: parseInt(paymentsCount.rows[0].count, 10),
      pendingPayments: parseInt(pendingCount.rows[0].count, 10),
      approvedPayments: parseInt(approvedCount.rows[0].count, 10),
      rejectedPayments: parseInt(rejectedCount.rows[0].count, 10)
    });
  } catch (error) {
    console.error('Erreur stats:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/payments/:id/approve', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const paymentId = parseInt(req.params.id, 10);

    const paymentResult = await pool.query(
      'SELECT * FROM payments WHERE id = $1',
      [paymentId]
    );

    if (paymentResult.rows.length === 0) {
      return res.status(400).json({ error: 'Paiement introuvable.' });
    }

    const payment = paymentResult.rows[0];

    if (payment.status !== 'PENDING') {
      return res.status(400).json({ error: 'Paiement déjà traité.' });
    }

    await pool.query(
      'UPDATE payments SET status = $1, validatedAt = $2 WHERE id = $3',
      ['APPROVED', new Date(), paymentId]
    );

    // Activer le bon premium selon le type de produit payé
    if (payment.producttype === 'translation') {
      await pool.query(
        'UPDATE users SET isTranslationPremium = $1, translationPremiumExpiresAt = $2 WHERE uuid = $3',
        [true, null, payment.useruuid]
      );
    } else {
      await pool.query(
        'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
        [true, null, payment.useruuid]
      );
    }

    console.log(`✅ Paiement ${paymentId} approuvé - User ${payment.useruuid} est maintenant premium PERMANENT`);

    res.json({
      message: 'Paiement approuvé avec succès !',
      payment: {
        id: paymentId,
        status: 'APPROVED',
        userUuid: payment.useruuid
      }
    });

  } catch (error) {
    console.error('Erreur approbation paiement:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/payments/:id/reject', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const paymentId = parseInt(req.params.id, 10);
    const { isFraud, reason } = req.body;

    const paymentResult = await pool.query(
      'SELECT * FROM payments WHERE id = $1',
      [paymentId]
    );

    if (paymentResult.rows.length === 0) {
      return res.status(400).json({ error: 'Paiement introuvable.' });
    }

    const payment = paymentResult.rows[0];

    if (payment.status !== 'PENDING') {
      return res.status(400).json({ error: 'Paiement déjà traité.' });
    }

    await pool.query(
      'UPDATE payments SET status = $1, validatedAt = $2 WHERE id = $3',
      ['REJECTED', new Date(), paymentId]
    );

    await pool.query(
      'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
      [false, null, payment.useruuid]
    );

    if (isFraud) {
      const fraudReason = reason || 'Paiement frauduleux détecté par admin';

      await pool.query(
        'UPDATE users SET isBlocked = $1 WHERE uuid = $2',
        [true, payment.useruuid]
      );

      if (payment.phonenumber) {
        await blockPhoneNumber(payment.phonenumber, fraudReason);
      }

      if (payment.devicefingerprint) {
        await blockDevice(payment.devicefingerprint, fraudReason);
      }

      console.log(`🚨 FRAUDE DÉTECTÉE par admin - Paiement ${paymentId}:`);
      console.log(`   - User bloqué: ${payment.useruuid}`);
      console.log(`   - Téléphone bloqué: ${payment.phonenumber}`);
      console.log(`   - Appareil bloqué: ${payment.devicefingerprint}`);
      console.log(`   - Raison: ${fraudReason}`);

      res.json({
        message: 'Paiement rejeté pour fraude. Compte, téléphone et appareil bloqués.',
        blocked: {
          user: payment.useruuid,
          phone: payment.phonenumber,
          device: payment.devicefingerprint
        }
      });

    } else {
      console.log(`❌ Paiement ${paymentId} rejeté (non-fraude) - User ${payment.useruuid} premium retiré`);

      res.json({
        message: 'Paiement rejeté.',
        payment: {
          id: paymentId,
          status: 'REJECTED',
          userUuid: payment.useruuid
        }
      });
    }

  } catch (error) {
    console.error('Erreur rejet paiement:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Lister tous les comptes bloqués
app.get('/api/admin/blocked-users', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const users = await getUsers();
    const blockedUsers = users.filter(u => u.isblocked).map(u => ({
      uuid: u.uuid,
      name: u.name,
      email: u.email,
      createdAt: u.createdat,
      deviceFingerprint: u.devicefingerprint,
      registrationIP: u.registrationip
    }));

    res.json({ blockedUsers, total: blockedUsers.length });
  } catch (error) {
    console.error('Erreur blocked-users:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Lister tous les utilisateurs (avec stats)
app.get('/api/admin/users', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const users = await getUsers();
    const payments = await getPayments();

    const enrichedUsers = users.map(user => {
      const userPayments = payments.filter(p => p.useruuid === user.uuid);
      const approvedPayments = userPayments.filter(p => p.status === 'APPROVED');

      return {
        uuid: user.uuid,
        name: user.name,
        email: user.email,
        isPremium: user.ispremium,
        isBlocked: user.isblocked,
        createdAt: user.createdat,
        premiumExpiresAt: user.premiumexpiresat,
        registrationIP: user.registrationip,
        deviceFingerprint: user.devicefingerprint,
        totalPayments: userPayments.length,
        approvedPayments: approvedPayments.length
      };
    });

    const stats = {
      total: users.length,
      premium: users.filter(u => u.ispremium).length,
      free: users.filter(u => !u.ispremium && !u.isblocked).length,
      blocked: users.filter(u => u.isblocked).length,
      newToday: users.filter(u => {
        const today = new Date();
        const createdAt = new Date(u.createdat);
        return createdAt.toDateString() === today.toDateString();
      }).length
    };

    res.json({ users: enrichedUsers, stats });
  } catch (error) {
    console.error('Erreur admin/users:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Débloquer un compte
app.post('/api/admin/users/:uuid/unblock', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const { uuid } = req.params;
    const users = await getUsers();
    const user = users.find(u => u.uuid === uuid);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    if (!user.isblocked) {
      return res.status(400).json({ error: 'Ce compte n\'est pas bloqué.' });
    }

    // Débloquer le compte + réinitialiser le device fingerprint
    // (l'utilisateur devra se connecter depuis son appareil actuel)
    await pool.query(
      'UPDATE users SET isBlocked = $1, deviceFingerprint = $2 WHERE uuid = $3',
      [false, null, uuid]
    );

    console.log(`🔓 Compte débloqué: ${user.email} (UUID: ${uuid})`);
    console.log(`   ⚠️ Device fingerprint réinitialisé - L'utilisateur pourra se connecter depuis n'importe quel appareil`);

    res.json({
      message: 'Compte débloqué avec succès. L\'utilisateur peut se reconnecter.',
      user: {
        uuid: user.uuid,
        name: user.name,
        email: user.email,
        isBlocked: false
      }
    });
  } catch (error) {
    console.error('Erreur unblock:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// SUPPRIMER un compte utilisateur définitivement
app.delete('/api/admin/users/:uuid', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const { uuid } = req.params;
    const users = await getUsers();
    const user = users.find(u => u.uuid === uuid);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    // Nettoyer d'abord toutes les données liées à ce compte
    // (évite les erreurs de contrainte de clé étrangère)
    await pool.query('DELETE FROM translations WHERE userUuid = $1', [uuid]);
    await pool.query('DELETE FROM translation_history WHERE userUuid = $1', [uuid]);
    await pool.query('DELETE FROM translation_usage WHERE userUuid = $1', [uuid]);
    await pool.query('DELETE FROM payments WHERE userUuid = $1', [uuid]);
    await pool.query('DELETE FROM ip_tracking WHERE userUuid = $1', [uuid]);

    // Supprimer le compte lui-même
    await pool.query('DELETE FROM users WHERE uuid = $1', [uuid]);

    console.log(`🗑️ Compte supprimé définitivement: ${user.email} (UUID: ${uuid})`);

    res.json({
      message: `Compte de ${user.email} supprimé définitivement.`,
      deletedUser: { uuid: user.uuid, email: user.email }
    });
  } catch (error) {
    console.error('Erreur suppression utilisateur:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ROUTES SPONSORS — Mur des Sponsors (Diamant / Or / Argent)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// PUBLIQUE : liste des sponsors visibles, pour le frontend
app.get('/api/sponsors', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, tier, message FROM sponsors
      WHERE isVisible = true
      ORDER BY
        CASE tier
          WHEN 'diamant' THEN 1
          WHEN 'or' THEN 2
          WHEN 'argent' THEN 3
        END,
        displayOrder ASC, addedAt ASC
    `);
    res.json({ sponsors: result.rows });
  } catch (error) {
    console.error('Erreur récupération sponsors:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ADMIN : liste complète (y compris masqués)
app.get('/api/admin/sponsors', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const result = await pool.query('SELECT * FROM sponsors ORDER BY tier, displayOrder, addedAt');
    res.json({ sponsors: result.rows });
  } catch (error) {
    console.error('Erreur récupération sponsors (admin):', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ADMIN : ajouter un sponsor
app.post('/api/admin/sponsors', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const { name, tier, amount, currency, message, displayOrder } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Le nom du sponsor est requis.' });
    }
    if (!['diamant', 'or', 'argent'].includes(tier)) {
      return res.status(400).json({ error: 'Palier invalide. Utilisez diamant, or ou argent.' });
    }

    const result = await pool.query(
      `INSERT INTO sponsors (name, tier, amount, currency, message, displayOrder)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [name.trim(), tier, amount || null, currency || 'USD', message || null, displayOrder || 0]
    );

    console.log(`✅ Sponsor ajouté : ${name} (${tier})`);
    res.json({ message: 'Sponsor ajouté avec succès.', sponsor: result.rows[0] });

  } catch (error) {
    console.error('Erreur ajout sponsor:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ADMIN : modifier un sponsor
app.put('/api/admin/sponsors/:id', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const id = parseInt(req.params.id, 10);
    const { name, tier, amount, currency, message, isVisible, displayOrder } = req.body;

    if (tier && !['diamant', 'or', 'argent'].includes(tier)) {
      return res.status(400).json({ error: 'Palier invalide. Utilisez diamant, or ou argent.' });
    }

    const result = await pool.query(
      `UPDATE sponsors SET
         name = COALESCE($1, name),
         tier = COALESCE($2, tier),
         amount = COALESCE($3, amount),
         currency = COALESCE($4, currency),
         message = COALESCE($5, message),
         isVisible = COALESCE($6, isVisible),
         displayOrder = COALESCE($7, displayOrder)
       WHERE id = $8
       RETURNING *`,
      [name, tier, amount, currency, message, isVisible, displayOrder, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sponsor introuvable.' });
    }

    res.json({ message: 'Sponsor mis à jour.', sponsor: result.rows[0] });

  } catch (error) {
    console.error('Erreur modification sponsor:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ADMIN : supprimer un sponsor
app.delete('/api/admin/sponsors/:id', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const id = parseInt(req.params.id, 10);
    const result = await pool.query('DELETE FROM sponsors WHERE id = $1 RETURNING name', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sponsor introuvable.' });
    }

    console.log(`🗑️ Sponsor supprimé : ${result.rows[0].name}`);
    res.json({ message: 'Sponsor supprimé.' });

  } catch (error) {
    console.error('Erreur suppression sponsor:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===== ROUTE DE TRACKING DES TRADUCTIONS (entraînement IA) =====

// Enregistrer une traduction (un INSERT direct, pas de push/save global)
app.post('/api/track/translation', authenticateToken, async (req, res) => {
  try {
    const { userUuid, translation } = req.body;

    if (!userUuid || !translation || !translation.sourceText || !translation.translatedText) {
      return res.status(400).json({ error: 'Données manquantes' });
    }

    // On ne garde que les traductions qui révèlent un manque au corpus —
    // repérées par le marqueur [mot] déjà utilisé par le traducteur pour
    // signaler un mot absent du dictionnaire (cf. FAQ "Pourquoi un mot est
    // affiché entre crochets ?"). Une phrase déjà 100% couverte n'apporte
    // rien de neuf à stocker.
    const hasUnknownWord = /\[[^\]]+\]/.test(translation.translatedText);
    if (!hasUnknownWord) {
      return res.json({ message: 'Traduction déjà couverte par le dictionnaire, non stockée', stored: false });
    }

    // Une seule ligne par (texte source, sens) : les demandes répétées
    // incrémentent juste un compteur au lieu de créer une nouvelle ligne —
    // ça évite que la table grossisse avec des doublons ("bonjour" traduit
    // 10 000 fois = 1 ligne avec requestCount = 10000, pas 10 000 lignes).
    const sourceText = translation.sourceText.trim().slice(0, 500); // garde-fou anti-pavé
    const result = await pool.query(
      `INSERT INTO translations (userUuid, sourceText, translatedText, direction, hasUnknownWord, requestCount, timestamp, date, savedAt)
       VALUES ($1, $2, $3, $4, TRUE, 1, $5, $6, $7)
       ON CONFLICT (sourceText, direction)
       DO UPDATE SET requestCount   = translations.requestCount + 1,
                      translatedText = EXCLUDED.translatedText,
                      savedAt        = EXCLUDED.savedAt
       RETURNING id, requestCount`,
      [
        userUuid,
        sourceText,
        translation.translatedText,
        translation.direction,
        translation.timestamp || new Date().toISOString(),
        translation.date || new Date().toLocaleDateString('fr-FR'),
        new Date().toISOString()
      ]
    );

    console.log(`📝 Traduction enregistrée (mot manquant) : "${sourceText}" → "${translation.translatedText}" (x${result.rows[0].requestcount})`);

    res.json({
      message: 'Traduction enregistrée avec succès',
      translationId: result.rows[0].id,
      requestCount: result.rows[0].requestcount,
      stored: true
    });
  } catch (error) {
    console.error('Erreur tracking traduction:', error);
    res.status(500).json({ error: 'Erreur lors de l\'enregistrement de la traduction' });
  }
});

// Route admin pour récupérer toutes les traductions (pour entraînement IA)
app.get('/api/admin/translations', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const translations = await getTranslations();
    // Les mots/phrases les plus demandés en premier — ce sont les manques
    // du corpus les plus prioritaires à combler.
    translations.sort((a, b) => (b.requestcount || 1) - (a.requestcount || 1));

    const stats = {
      total: translations.length,
      totalRequests: translations.reduce((sum, t) => sum + (t.requestcount || 1), 0),
      byDirection: {
        'fr-to-kivira': translations.filter(t => t.direction === 'fr-to-kivira').length,
        'kivira-to-fr': translations.filter(t => t.direction === 'kivira-to-fr').length
      },
      uniqueUsers: [...new Set(translations.map(t => t.useruuid))].length,
      lastWeek: translations.filter(t => {
        const date = new Date(t.timestamp);
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        return date > weekAgo;
      }).length
    };

    res.json({ translations, stats });
  } catch (error) {
    console.error('Erreur récupération traductions:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des traductions' });
  }
});

// Exporter les traductions pour l'entraînement IA
app.get('/api/admin/translations/export', async (req, res) => {
  const adminPassword = req.headers['x-admin-password'];

  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Accès refusé.' });
  }

  try {
    const translations = await getTranslations();

    const trainingData = translations.map(t => ({
      source: t.sourcetext,
      target: t.translatedtext,
      direction: t.direction,
      requestCount: t.requestcount || 1
    }));

    res.setHeader('Content-Disposition', 'attachment; filename=translations-training-data.json');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(trainingData, null, 2));

    console.log(`📥 Export de ${trainingData.length} traductions pour entraînement IA`);
  } catch (error) {
    console.error('Erreur export traductions:', error);
    res.status(500).json({ error: 'Erreur lors de l\'export des traductions' });
  }
});


// ... tout votre code existant ...


// ROUTES BIBLIOTHÈQUE + DICTIONNAIRE — À ajouter dans server.js
// Placez ce bloc juste avant initStorage().then(...)
// ═══════════════════════════════════════════════════════════

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BIBLIOTHÈQUE — 3 niveaux : Catégories → Titres → Articles
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /api/library/categories
// Renvoie name_fr / name_en / name_sw / name_ki (format attendu par library_frontend.js)
app.get('/api/library/categories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id, slug, icon, display_order,
        title_fr AS name_fr, title_en AS name_en,
        title_sw AS name_sw, title_ki AS name_ki
      FROM lib_categories
      WHERE is_visible = true
      ORDER BY display_order ASC
    `);

    res.json({ success: true, categories: result.rows });
  } catch (err) {
    console.error('Erreur /api/library/categories:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/library/titles?category_id=1
// Renvoie title_fr / title_en / title_sw / title_ki (format attendu par library_frontend.js)
app.get('/api/library/titles', async (req, res) => {
  try {
    const { category_id } = req.query;

    if (!category_id) {
      return res.status(400).json({ success: false, error: 'category_id requis' });
    }

    const catResult = await pool.query(
      `SELECT id, slug, icon,
              title_fr AS name_fr, title_en AS name_en,
              title_sw AS name_sw, title_ki AS name_ki
       FROM lib_categories WHERE id = $1 AND is_visible = true`,
      [category_id]
    );
    if (catResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Catégorie introuvable' });
    }

    const titlesResult = await pool.query(`
      SELECT id, slug, display_order,
             title_fr, title_en, title_sw, title_ki
      FROM lib_titles
      WHERE category_id = $1 AND is_visible = true
      ORDER BY display_order ASC
    `, [category_id]);

    res.json({
      success: true,
      category: catResult.rows[0],
      titles: titlesResult.rows
    });
  } catch (err) {
    console.error('Erreur /api/library/titles:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/library/articles?title_id=1
// Renvoie content_fr / content_en / content_sw / content_ki (format attendu par library_frontend.js)
app.get('/api/library/articles', async (req, res) => {
  try {
    const { title_id } = req.query;

    if (!title_id) {
      return res.status(400).json({ success: false, error: 'title_id requis' });
    }

    const titleResult = await pool.query(
      `SELECT t.id, t.slug,
              t.title_fr, t.title_en, t.title_sw, t.title_ki,
              c.title_fr AS category_name_fr, c.title_en AS category_name_en,
              c.title_sw AS category_name_sw, c.title_ki AS category_name_ki,
              c.id AS category_id
       FROM lib_titles t
       JOIN lib_categories c ON c.id = t.category_id
       WHERE t.id = $1 AND t.is_visible = true`,
      [title_id]
    );
    if (titleResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Titre introuvable' });
    }

    const articlesResult = await pool.query(`
      SELECT
        id, slug, display_order, author, published_at,
        article_title_fr, article_title_en, article_title_sw, article_title_ki,
        content_fr, content_en, content_sw, content_ki
      FROM lib_articles
      WHERE title_id = $1 AND is_visible = true
      ORDER BY display_order ASC
    `, [title_id]);

    res.json({
      success: true,
      title: titleResult.rows[0],
      articles: articlesResult.rows
    });
  } catch (err) {
    console.error('Erreur /api/library/articles:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/library/article?id=1
app.get('/api/library/article', async (req, res) => {
  try {
    const { id } = req.query;

    if (!id) {
      return res.status(400).json({ success: false, error: 'id requis' });
    }

    const result = await pool.query(`
      SELECT
        a.id, a.slug, a.author, a.published_at,
        a.article_title_fr, a.article_title_en, a.article_title_sw, a.article_title_ki,
        a.content_fr, a.content_en, a.content_sw, a.content_ki,
        t.title_fr AS title_name_fr, t.title_en AS title_name_en,
        t.title_sw AS title_name_sw, t.title_ki AS title_name_ki,
        t.id AS title_id,
        c.title_fr AS category_name_fr, c.title_en AS category_name_en,
        c.title_sw AS category_name_sw, c.title_ki AS category_name_ki,
        c.id AS category_id
      FROM lib_articles a
      JOIN lib_titles t     ON t.id = a.title_id
      JOIN lib_categories c ON c.id = t.category_id
      WHERE a.id = $1 AND a.is_visible = true
      LIMIT 1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Article introuvable' });
    }

    res.json({ success: true, article: result.rows[0] });
  } catch (err) {
    console.error('Erreur /api/library/article:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DICTIONNAIRE — Recherche multilingue
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GET /api/dictionary/search?q=bonjour&lang=fr
app.get('/api/dictionary/search', async (req, res) => {
  try {
    const { q, lang = 'fr', limit = 20 } = req.query;

    if (!q || !q.trim()) {
      return res.status(400).json({ success: false, error: 'Paramètre q requis' });
    }

    const search = '%' + q.trim() + '%';
    const lim = Math.min(parseInt(limit) || 20, 50);

    // Recherche selon la langue source
    const result = await pool.query(`
      SELECT
        id, kivira, french, english, swahili,
        category, type,
        example_kivira,
        example_translation_fr,
        example_translation_en,
        example_translation_sw
      FROM dictionary
      WHERE
        kivira  ILIKE $1 OR
        french  ILIKE $1 OR
        english ILIKE $1 OR
        swahili ILIKE $1
      ORDER BY
        CASE
          WHEN kivira  ILIKE $2 THEN 1
          WHEN french  ILIKE $2 THEN 2
          WHEN english ILIKE $2 THEN 3
          ELSE 4
        END,
        LENGTH(kivira) ASC
      LIMIT $3
    `, [search, q.trim(), lim]);

    res.json({
      success: true,
      query: q,
      count: result.rows.length,
      results: result.rows
    });
  } catch (err) {
    console.error('Erreur /api/dictionary/search:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/dictionary/word?kivira=Mwana
app.get('/api/dictionary/word', async (req, res) => {
  try {
    const { kivira } = req.query;
    if (!kivira) {
      return res.status(400).json({ success: false, error: 'Paramètre kivira requis' });
    }

    const result = await pool.query(
      'SELECT * FROM dictionary WHERE kivira ILIKE $1 LIMIT 1',
      [kivira]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Mot introuvable' });
    }

    res.json({ success: true, word: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/dictionary/categories
app.get('/api/dictionary/categories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT category, COUNT(*) as count
      FROM dictionary
      GROUP BY category
      ORDER BY count DESC
    `);
    res.json({ success: true, categories: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/dictionary/random?count=5
app.get('/api/dictionary/random', async (req, res) => {
  try {
    const count = Math.min(parseInt(req.query.count) || 5, 20);
    const result = await pool.query(
      'SELECT id, kivira, french, english, swahili, example_kivira, example_translation_fr FROM dictionary ORDER BY RANDOM() LIMIT $1',
      [count]
    );
    res.json({ success: true, words: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


// Route combinée via ?action= (celle utilisée par library_frontend.js)
// Renvoie les 4 langues (name_fr/title_fr/content_fr etc.) — le frontend choisit lui-même
app.get('/api/library', async (req, res) => {
  const { action, category_id, title_id, id } = req.query;

  try {
    if (!action || action === 'categories') {
      const result = await pool.query(`
        SELECT id, slug, icon, display_order,
               title_fr AS name_fr, title_en AS name_en,
               title_sw AS name_sw, title_ki AS name_ki
        FROM lib_categories
        WHERE is_visible = true
        ORDER BY display_order ASC
      `);
      return res.json({ success: true, categories: result.rows });
    }

    if (action === 'titles') {
      if (!category_id) return res.status(400).json({ success: false, error: 'category_id requis' });
      const cat = await pool.query(
        `SELECT id, slug, icon,
                title_fr AS name_fr, title_en AS name_en,
                title_sw AS name_sw, title_ki AS name_ki
         FROM lib_categories WHERE id = $1 AND is_visible = true`,
        [category_id]
      );
      if (!cat.rows.length) return res.status(404).json({ success: false, error: 'Catégorie introuvable' });
      const titles = await pool.query(`
        SELECT id, slug, display_order,
               title_fr, title_en, title_sw, title_ki
        FROM lib_titles
        WHERE category_id = $1 AND is_visible = true
        ORDER BY display_order ASC
      `, [category_id]);
      return res.json({ success: true, category: cat.rows[0], titles: titles.rows });
    }

    if (action === 'articles') {
      if (!title_id) return res.status(400).json({ success: false, error: 'title_id requis' });
      const titleRes = await pool.query(`
        SELECT t.id, t.slug,
               t.title_fr, t.title_en, t.title_sw, t.title_ki,
               c.title_fr AS category_name_fr, c.title_en AS category_name_en,
               c.title_sw AS category_name_sw, c.title_ki AS category_name_ki,
               c.id AS category_id
        FROM lib_titles t
        JOIN lib_categories c ON c.id = t.category_id
        WHERE t.id = $1 AND t.is_visible = true
      `, [title_id]);
      if (!titleRes.rows.length) return res.status(404).json({ success: false, error: 'Titre introuvable' });
      const articles = await pool.query(`
        SELECT id, slug, display_order, author, published_at,
               article_title_fr, article_title_en, article_title_sw, article_title_ki,
               content_fr, content_en, content_sw, content_ki
        FROM lib_articles
        WHERE title_id = $1 AND is_visible = true
        ORDER BY display_order ASC
      `, [title_id]);
      return res.json({ success: true, title: titleRes.rows[0], articles: articles.rows });
    }

    if (action === 'article') {
      if (!id) return res.status(400).json({ success: false, error: 'id requis' });
      const result = await pool.query(`
        SELECT a.id, a.slug, a.author, a.published_at,
               a.article_title_fr, a.article_title_en, a.article_title_sw, a.article_title_ki,
               a.content_fr, a.content_en, a.content_sw, a.content_ki,
               t.title_fr AS title_name_fr, t.title_en AS title_name_en,
               t.title_sw AS title_name_sw, t.title_ki AS title_name_ki,
               t.id AS title_id,
               c.title_fr AS category_name_fr, c.title_en AS category_name_en,
               c.title_sw AS category_name_sw, c.title_ki AS category_name_ki,
               c.id AS category_id
        FROM lib_articles a
        JOIN lib_titles t ON t.id = a.title_id
        JOIN lib_categories c ON c.id = t.category_id
        WHERE a.id = $1 AND a.is_visible = true
        LIMIT 1
      `, [id]);
      if (!result.rows.length) return res.status(404).json({ success: false, error: 'Article introuvable' });
      return res.json({ success: true, article: result.rows[0] });
    }

    return res.status(400).json({ success: false, error: `Action inconnue: ${action}` });
  } catch (err) {
    console.error('Erreur /api/library:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DICTIONNAIRE
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ===== DÉMARRAGE =====
const PORT = process.env.PORT || 5000;

initStorage().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📍 CORS configuré pour: ${allowedOrigins.join(', ')}`);
    console.log(`💰 Paiement manuel activé: ${PAYMENT_CONFIG.amount} ${PAYMENT_CONFIG.currency}`);
    console.log(`🛡️ Protection anti-fraude activée:`);
    console.log(`   - Max ${FRAUD_PROTECTION.maxAccountsPerIP} comptes par IP`);
    console.log(`   - Max ${FRAUD_PROTECTION.maxAccountsPerDevice} comptes par appareil`);
    console.log(`   - Max ${FRAUD_PROTECTION.maxPaymentsPerHour} paiements par heure`);
    console.log(`   - Device fingerprinting activé`);
    console.log(`   - 1 compte = 1 appareil (connexion)`);
    console.log(`   - Appareil avec fraude bloqué`);
  });
});
