// backend/server.js
require('dotenv').config(); // Carrega as variáveis de ambiente do .env
const express = require('express');
const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs'); // Comentado: Não usaremos mais bcrypt
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto'); // Módulo crypto para MD5

const app = express();
const PORT = process.env.PORT || 5000; // Porta do servidor (padrão 5000)
const MONGO_URI = process.env.MONGO_URI; // URI de conexão com o MongoDB
const JWT_SECRET = process.env.JWT_SECRET; // Chave secreta para JWT

// AVISO IMPORTANTE DE SEGURANÇA:
// O MD5 não é recomendado para hashear senhas em aplicações modernas.
// Ele é vulnerável a ataques de colisão e tabelas de arco-íris, e não oferece
// a mesma segurança que algoritmos como bcrypt ou scrypt.
// Use esta implementação APENAS para fins de aprendizado/teste, NÃO em produção.
const MD5_GLOBAL_SALT = 'a495af97-7667-4fdb-bc1a-13a566943ad4'; // String aleatória e difícil para MD5

// Função auxiliar para hashear com MD5
const hashPasswordWithMD5 = (password) => {
  return crypto.createHash('md5').update(password + MD5_GLOBAL_SALT).digest('hex');
};

// --- Middlewares ---
// Habilita o CORS para permitir requisições do frontend (que está em um domínio/porta diferente)
app.use(cors());
// Habilita o parsing de JSON no corpo das requisições (req.body)
app.use(express.json());

// --- Conexão com o MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Conectado ao MongoDB!');
    // Garante que o índice único para o email na coleção 'users' seja criado.
    // Isso é crucial para evitar emails duplicados.
    return mongoose.connection.db.collection('users').createIndexes([
      { key: { email: 1 }, unique: true }
    ]).catch(err => {
      // O erro 11000 ocorre se o índice já existe ou se há duplicatas preexistentes.
      // Se não for o erro 11000, logamos para investigação.
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
  email: { type: String, required: true, unique: true }, // 'unique: true' garante que emails sejam únicos
  password: { type: String, required: true } // Armazenará o hash MD5 da senha
});

// Middleware do Mongoose: Executa antes de salvar um documento User.
// Usado para hashear a senha APENAS se ela foi modificada (nova criação ou atualização).
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = hashPasswordWithMD5(this.password); // Hasheia a senha usando a função MD5
  }
  next(); // Continua o processo de salvamento
});

const User = mongoose.model('User', userSchema);

// --- Middleware para Proteger Rotas (Autenticação JWT) ---
// Verifica a presença e a validade do token JWT em cada requisição para rotas protegidas.
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']; // Obtém o cabeçalho Authorization
  // O token vem no formato "Bearer SEU_TOKEN_AQUI", então dividimos para pegar apenas o token.
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    // Se o token não for fornecido, retorna 401 Unauthorized
    return res.status(401).json({ message: 'Token de autenticação não fornecido.' });
  }

  // Verifica o token usando a chave secreta (JWT_SECRET)
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // Se o token for inválido (assinatura errada, expirado, etc.), retorna 403 Forbidden
      console.error('Erro de verificação do token:', err.message); // Log para depuração
      return res.status(403).json({ message: 'Token inválido ou expirado.' });
    }
    req.user = user; // Adiciona o payload decodificado (id do user, email) ao objeto de requisição
    next(); // Permite que a requisição prossiga para a rota protegida
  });
};

// --- Rotas de Autenticação ---

// Rota de Registro de Usuário
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Verificação explícita: Procura por um usuário com o mesmo email antes de tentar salvar.
    // Isso é uma camada extra de segurança/feedback, além do 'unique: true' do schema.
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Este email já está em uso. Por favor, use outro.' });
    }

    const newUser = new User({ name, email, password });
    await newUser.save(); // A senha será hasheada pelo middleware pre('save')

    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    // Caso o erro 11000 (índice único) ainda ocorra por algum motivo
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email já registrado. (Erro de índice único)' });
    }
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

// Rota de Login de Usuário
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Usuário não encontrado
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    // Hashear a senha fornecida pelo usuário e comparar com a senha hasheada no banco
    const hashedPasswordAttempt = hashPasswordWithMD5(password);
    if (hashedPasswordAttempt !== user.password) {
      // Senha incorreta
      return res.status(400).json({ message: 'Credenciais inválidas.' });
    }

    // Gerar Token JWT com o ID e email do usuário, expirando em 1 hora
    const token = jwt.sign(
      { id: user._id, email: user.email }, // Payload do token
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Retorna o token e dados básicos do usuário (sem a senha)
    res.status(200).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

// --- Rotas Protegidas ---

// Rota Protegida de Exemplo
// Apenas usuários com um JWT válido e não expirado podem acessar.
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Você acessou uma rota protegida!',
    user: req.user, // Informações do usuário do token
    data: 'Informações confidenciais.'
  });
});

// Rota para Obter Dados do Perfil do Usuário Logado
app.get('/api/profile', authenticateToken, async (req, res) => {
  const userId = req.user.id; // O ID do usuário vem do token JWT, injetado por 'authenticateToken'

  try {
    // Busca o usuário pelo ID, mas exclui o campo 'password' do resultado
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }
    res.status(200).json({ user }); // Retorna os dados do usuário (sem senha)
  } catch (error) {
    console.error('Erro ao obter perfil:', error);
    res.status(500).json({ message: 'Erro no servidor ao obter perfil. Tente novamente mais tarde.' });
  }
});

// Rota para Atualizar o Perfil do Usuário Logado
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { name, oldPassword, newPassword, confirmNewPassword } = req.body;
  const userId = req.user.id; // O ID do usuário logado vem do token

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    let changesMade = false;

    // 1. Atualizar Nome: Se um novo nome foi fornecido e é diferente do atual
    if (name !== undefined && name !== user.name) { // Verifica se 'name' foi enviado e é diferente
      user.name = name;
      changesMade = true;
    }

    // 2. Atualizar Senha: Se uma nova senha foi fornecida
    if (newPassword) {
      // Validações básicas da nova senha antes de comparar com a antiga
      if (!oldPassword) {
        return res.status(400).json({ message: 'Para alterar a senha, a senha antiga é obrigatória.' });
      }
      if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'A nova senha e a confirmação não coincidem.' });
      }

      // Hashear a senha antiga fornecida e comparar com a senha armazenada
      const hashedOldPasswordAttempt = hashPasswordWithMD5(oldPassword);
      if (hashedOldPasswordAttempt !== user.password) {
        return res.status(400).json({ message: 'Senha antiga incorreta.' });
      }

      // Se a senha antiga estiver correta, atualiza a nova senha
      user.password = newPassword; // O middleware 'pre('save')' irá hashear esta nova senha
      changesMade = true;
    }

    // Salva as alterações apenas se algo foi modificado
    if (changesMade) {
      await user.save(); // Salva as alterações no banco de dados
      return res.status(200).json({ message: 'Perfil atualizado com sucesso!' });
    } else {
      // Se a requisição PUT foi feita mas sem dados para alterar
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
  console.log(`Rotas de API: /api/register (POST), /api/login (POST), ` +
              `/api/protected (GET), /api/profile (GET, PUT)`);
});