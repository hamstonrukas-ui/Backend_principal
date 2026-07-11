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
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:8000',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Password', 'X-Device-Fingerprint']
};

app.use(cors(corsOptions));
app.use(express.json());

// ===== CONFIGURATION PAIEMENT MANUEL =====
const PAYMENT_CONFIG = {
  airtelNumber: '+243 99 123 4567',
  orangeNumber: '+243 84 123 4567',
  mpesaNumber: '+243 81 123 4567',
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
  allowDeviceChange: false
};

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

    const deviceFingerprint = req.headers['x-device-fingerprint'];
    const users = await getUsers();
    const user = users.find(u => u.uuid === decoded.uuid);

    if (!user) {
      return res.status(403).json({ error: 'Utilisateur non trouvé.' });
    }

    // PROTECTION: Vérifier si l'appareil a changé
    if (user.devicefingerprint && deviceFingerprint && user.devicefingerprint !== deviceFingerprint) {
      if (!FRAUD_PROTECTION.allowDeviceChange) {
        console.log(`🚨 DEVICE CHANGE: User ${user.uuid} tente de se connecter depuis un autre appareil`);
        return res.status(403).json({
          error: 'Ce compte est lié à un autre appareil. Impossible de vous connecter depuis cet appareil.',
          code: 'DEVICE_MISMATCH'
        });
      }
    }

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

📱 Airtel Money : ${PAYMENT_CONFIG.airtelNumber}
📱 Orange Money : ${PAYMENT_CONFIG.orangeNumber}
📱 M-Pesa (Vodacom) : ${PAYMENT_CONFIG.mpesaNumber}

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

// Soumettre un Transaction ID
app.post('/api/payments/submit', authenticateToken, async (req, res) => {
  try {
    const { transactionId, phoneNumber, operator } = req.body;
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

    // PROTECTION: Numéro bloqué
    if (await isPhoneBlocked(phoneNumber)) {
      await pool.query(
        'UPDATE users SET isBlocked = $1 WHERE uuid = $2',
        [true, user.uuid]
      );

      if (deviceFingerprint) {
        await blockDevice(deviceFingerprint, 'Numéro bloqué utilisé');
      }

      console.log(`🚨 FRAUDE: User ${user.uuid} a tenté d'utiliser un numéro bloqué: ${phoneNumber}`);

      return res.status(403).json({
        error: 'Ce numéro de téléphone a été bloqué pour fraude. Votre compte et appareil sont maintenant bloqués.'
      });
    }

    // PROTECTION: Limite paiements par heure
    if (!await checkPaymentRateLimit(user.uuid)) {
      console.log(`🚨 FRAUDE: User ${user.uuid} tente trop de paiements rapidement`);

      return res.status(429).json({
        error: `Trop de tentatives de paiement. Maximum ${FRAUD_PROTECTION.maxPaymentsPerHour} par heure. Réessayez plus tard.`
      });
    }

    // PROTECTION: Transaction ID unique
    const existingResult = await pool.query(
      'SELECT * FROM payments WHERE transactionId = $1',
      [transactionId]
    );

    if (existingResult.rows.length > 0) {
      const existingPayment = existingResult.rows[0];

      await pool.query(
        'UPDATE users SET isBlocked = $1 WHERE uuid = $2',
        [true, user.uuid]
      );

      await pool.query(
        'UPDATE users SET isBlocked = $1, isPremium = $2 WHERE uuid = $3',
        [true, false, existingPayment.useruuid]
      );

      await blockPhoneNumber(phoneNumber, 'Transaction ID réutilisé');
      await blockPhoneNumber(existingPayment.phonenumber, 'Transaction ID réutilisé');

      if (deviceFingerprint) {
        await blockDevice(deviceFingerprint, 'Transaction ID réutilisé');
      }

      const otherUserResult = await pool.query(
        'SELECT deviceFingerprint FROM users WHERE uuid = $1',
        [existingPayment.useruuid]
      );

      if (otherUserResult.rows.length > 0 && otherUserResult.rows[0].devicefingerprint) {
        await blockDevice(otherUserResult.rows[0].devicefingerprint, 'Transaction ID réutilisé');
      }

      console.log(`🚨 FRAUDE DÉTECTÉE: Transaction ID ${transactionId} réutilisé par users ${user.uuid} et ${existingPayment.useruuid}`);

      return res.status(403).json({
        error: 'Ce Transaction ID a déjà été utilisé. Les deux comptes, numéros et appareils ont été bloqués pour fraude.'
      });
    }

    

  // Récupérer productType depuis le body (general ou translation)
    const productType = req.body.productType === 'translation' ? 'translation' : 'general';
    const amount = productType === 'translation' ? '2000' : PAYMENT_CONFIG.amount;

    const paymentUuid = uuidv4();

    await pool.query(
        `INSERT INTO payments (paymentUuid, userUuid, userName, userEmail,
                              transactionId, phoneNumber, operator, amount, currency,
                              status, deviceFingerprint, submittedAt, validatedAt, productType)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [paymentUuid, user.uuid, user.name, user.email,
         transactionId.trim(), phoneNumber.trim(), operator,
         amount, PAYMENT_CONFIG.currency,
         'PENDING', deviceFingerprint, new Date(), null, productType]
    );

    // Premium temporaire selon le type
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + PAYMENT_CONFIG.temporaryPremiumDuration);

    if (productType === 'translation') {
      await pool.query(
        'UPDATE users SET isTranslationPremium = $1, translationPremiumExpiresAt = $2 WHERE uuid = $3',
        [true, expiresAt, user.uuid]
      );
    } else {
      await pool.query(
        'UPDATE users SET isPremium = $1, premiumExpiresAt = $2 WHERE uuid = $3',
        [true, expiresAt, user.uuid]
      );
      }
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

    if (!userUuid || !translation) {
      return res.status(400).json({ error: 'Données manquantes' });
    }

    const result = await pool.query(
      `INSERT INTO translations (userUuid, sourceText, translatedText, direction, timestamp, date, savedAt)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [
        userUuid,
        translation.sourceText,
        translation.translatedText,
        translation.direction,
        translation.timestamp,
        translation.date,
        new Date().toISOString()
      ]
    );

    console.log(`📝 Traduction enregistrée: "${translation.sourceText}" → "${translation.translatedText}" (User: ${userUuid})`);

    res.json({
      message: 'Traduction enregistrée avec succès',
      translationId: result.rows[0].id
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

    const stats = {
      total: translations.length,
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
      direction: t.direction
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PROXY BIBLIOTHÈQUE — Render → AeonFree
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const AEONFREE_URL = 'http://kivirafacile.hstn.me/api/library_api.php';

app.get('/api/library/categories', async (req, res) => {
  try {
    const lang = req.query.lang || 'fr';
    const response = await fetch(`${AEONFREE_URL}?action=categories&lang=${lang}`);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/library/titles', async (req, res) => {
  try {
    const { category_id, lang = 'fr' } = req.query;
    if (!category_id) return res.status(400).json({ error: 'category_id requis' });
    const response = await fetch(`${AEONFREE_URL}?action=titles&category_id=${category_id}&lang=${lang}`);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/library/articles', async (req, res) => {
  try {
    const { title_id, lang = 'fr' } = req.query;
    if (!title_id) return res.status(400).json({ error: 'title_id requis' });
    const response = await fetch(`${AEONFREE_URL}?action=articles&title_id=${title_id}&lang=${lang}`);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/library/article', async (req, res) => {
  try {
    const { id, lang = 'fr' } = req.query;
    if (!id) return res.status(400).json({ error: 'id requis' });
    const response = await fetch(`${AEONFREE_URL}?action=article&id=${id}&lang=${lang}`);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/dictionary/search', async (req, res) => {
  try {
    const { q, lang = 'fr' } = req.query;
    if (!q) return res.status(400).json({ error: 'Paramètre q requis' });
    const response = await fetch(`http://kivirafacile.hstn.me/api/dictionary.php?action=search&q=${encodeURIComponent(q)}&lang=${lang}`);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ← ICI SE TERMINE LE PROXY


// ===== DÉMARRAGE =====
const PORT = process.env.PORT || 5000;

initStorage().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📍 CORS configuré pour: ${process.env.FRONTEND_URL || 'http://localhost:8000'}`);
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
