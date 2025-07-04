// backend/server.js
require('dotenv').config(); // Carrega as variáveis de ambiente do .env
const express = require('express');
const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs'); // Comentado: Não usaremos mais bcrypt
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Corrigido: era 'require'
const crypto = require('crypto'); // Módulo crypto para MD5

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// AVISO IMPORTANTE DE SEGURANÇA:
// O MD5 não é recomendado para hashear senhas em aplicações modernas.
// Ele é vulnerável a ataques. bcrypt (que estava comentado) é muito mais seguro.
// Use esta implementação apenas para fins de aprendizado/teste, não em produção.
const MD5_GLOBAL_SALT = 'a495af97-7667-4fdb-bc1a-13a566943ad4'; // String aleatória e difícil para MD5

// Função auxiliar para hashear com MD5
const hashPasswordWithMD5 = (password) => {
  return crypto.createHash('md5').update(password + MD5_GLOBAL_SALT).digest('hex');
};

// --- Middlewares ---
app.use(cors()); // Habilita o CORS para permitir requisições do frontend
app.use(express.json()); // Habilita o parsing de JSON no corpo das requisições

// --- Conexão com o MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Conectado ao MongoDB!');
    // Força a criação de índices únicos (como para o email)
    return mongoose.connection.db.collection('users').createIndexes([
      { key: { email: 1 }, unique: true }
    ]).catch(err => {
      // Ignora erro 11000 (Duplicate Key Error) se o índice já existe
      if (err.code !== 11000) {
        console.error('Erro ao criar índice único para email:', err);
      }
    });
  })
  .then(() => console.log('Índices MongoDB garantidos!')) // Mensagem de sucesso para os índices
  .catch(err => console.error('Erro ao conectar ao MongoDB ou criar índices:', err));

// --- Schema e Modelo do Usuário ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true }, // 'unique: true' garante que emails sejam únicos
  password: { type: String, required: true } // Armazenará o hash MD5
});

// Middleware do Mongoose para hashear a senha com MD5 antes de salvar
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = hashPasswordWithMD5(this.password); // Usa a função de hash MD5
  }
  next();
});

const User = mongoose.model('User', userSchema);

// --- Rotas de Autenticação ---

// Rota de Registro
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {

    const existingUser = await User.findOne({ email });
    if (existingUser) {
    // Se um usuário com este email já foi encontrado, retorne erro 400
    return res.status(400).json({ message: 'Este email já está em uso. Por favor, use outro.' });
    }

    const newUser = new User({ name, email, password });
    await newUser.save(); // A senha será hasheada pelo pre('save') middleware

    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    if (error.code === 11000) { // Erro de chave duplicada (email já existe)
      return res.status(400).json({ message: 'Email já registrado.' });
    }
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    // Hashear a senha fornecida pelo usuário com o mesmo método MD5
    const hashedPasswordAttempt = hashPasswordWithMD5(password);

    // Comparar o hash da senha fornecida com o hash armazenado no banco
    if (hashedPasswordAttempt !== user.password) { // Comparação direta de hashes MD5
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    // Gerar Token JWT
    const token = jwt.sign(
      { id: user._id, email: user.email }, // Payload do token
      JWT_SECRET,
      { expiresIn: '1h' } // Token expira em 1 hora
    );

    res.status(200).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

// --- Rota Protegida de Exemplo ---
// Middleware para proteger rotas
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extrai o token "Bearer <token>"

  if (!token) {
    return res.status(401).json({ message: 'Token de autenticação não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // Se o token for inválido ou expirado, retorna 403 Forbidden
      console.error('Erro de verificação do token:', err.message); // Para debug
      return res.status(403).json({ message: 'Token inválido ou expirado.' });
    }
    req.user = user; // Adiciona o payload do token ao objeto de requisição
    next(); // Continua para a próxima função middleware/rota
  });
};

app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Você acessou uma rota protegida!',
    user: req.user,
    data: 'Informações confidenciais.'
  });
});


// --- Iniciar o Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Rotas de API: /api/register, /api/login, /api/protected`);
});