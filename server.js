// backend/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// AVISO IMPORTANTE DE SEGURANÇA:
// O MD5 não é recomendado para hashear senhas em aplicações modernas.
// Ele é vulnerável a ataques. bcrypt (que estava comentado) é muito mais seguro.
// Use esta implementação apenas para fins de aprendizado/teste, não em produção.
const MD5_GLOBAL_SALT = 'a495af97-7667-4fdb-bc1a-13a566943ad4';

const hashPasswordWithMD5 = (password) => {
  return crypto.createHash('md5').update(password + MD5_GLOBAL_SALT).digest('hex');
};

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Conexão com o MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Conectado ao MongoDB!');
    return mongoose.connection.db.collection('users').createIndexes([
      { key: { email: 1 }, unique: true }
    ]).catch(err => {
      if (err.code !== 11000) {
        console.error('Erro ao criar índice único para email:', err);
      }
    });
  })
  .then(() => console.log('Índices MongoDB garantidos!'))
  .catch(err => console.error('Erro ao conectar ao MongoDB ou criar índices:', err));

// --- Schema e Modelo do Usuário ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = hashPasswordWithMD5(this.password);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// --- Middleware para proteger rotas (já existente) ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token de autenticação não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Erro de verificação do token:', err.message);
      return res.status(403).json({ message: 'Token inválido ou expirado.' });
    }
    req.user = user;
    next();
  });
};

// --- Rotas de Autenticação (já existentes) ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Este email já está em uso. Por favor, use outro.' });
    }

    const newUser = new User({ name, email, password });
    await newUser.save();

    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email já registrado. (Erro de índice único)' });
    }
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    const hashedPasswordAttempt = hashPasswordWithMD5(password);

    if (hashedPasswordAttempt !== user.password) {
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Você acessou uma rota protegida!',
    user: req.user,
    data: 'Informações confidenciais.'
  });
});

// --- NOVA ROTA: Atualizar Perfil do Usuário ---
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { name, oldPassword, newPassword, confirmNewPassword } = req.body;
  const userId = req.user.id; // ID do usuário vem do token JWT

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    let changesMade = false;

    // 1. Atualizar Nome
    if (name && name !== user.name) {
      user.name = name;
      changesMade = true;
    }

    // 2. Atualizar Senha
    if (newPassword) { // Se uma nova senha foi fornecida
      if (!oldPassword) {
        return res.status(400).json({ message: 'Para alterar a senha, a senha antiga é obrigatória.' });
      }
      if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'A nova senha e a confirmação não coincidem.' });
      }

      // Hashear a senha antiga fornecida e comparar com a armazenada
      const hashedOldPasswordAttempt = hashPasswordWithMD5(oldPassword);
      if (hashedOldPasswordAttempt !== user.password) {
        return res.status(400).json({ message: 'Senha antiga incorreta.' });
      }

      // Se a senha antiga estiver correta, atualiza a nova senha
      user.password = newPassword; // O middleware 'pre('save')' irá hashear esta nova senha
      changesMade = true;
    }

    if (changesMade) {
      await user.save(); // Salva as alterações no banco de dados
      return res.status(200).json({ message: 'Perfil atualizado com sucesso!' });
    } else {
      return res.status(200).json({ message: 'Nenhuma alteração foi fornecida ou necessária.' });
    }

  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ message: 'Erro no servidor ao atualizar perfil. Tente novamente mais tarde.' });
  }
});


// --- Iniciar o Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Rotas de API: /api/register, /api/login, /api/protected, /api/profile`);
});