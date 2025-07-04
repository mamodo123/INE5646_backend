// backend/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios'); // Importar Axios para fazer requisições HTTP

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const AI_WEBHOOK_URL = process.env.AI_WEBHOOK_URL; // URL do webhook de IA do .env

// AVISO IMPORTANTE DE SEGURANÇA: MD5 NÃO é recomendado para senhas em produção.
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

// --- Schemas e Modelos ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) { this.password = hashPasswordWithMD5(this.password); }
  next();
});
const User = mongoose.model('User', userSchema);

const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, default: 'Nova Conversa' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
chatSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Chat = mongoose.model('Chat', chatSchema);

const messageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  sender: { type: String, required: true, enum: ['user', 'ai'] },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// --- Middleware para Proteger Rotas (Autenticação JWT) ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) { return res.status(401).json({ message: 'Token de autenticação não fornecido.' }); }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) { console.error('Erro de verificação do token:', err.message); return res.status(403).json({ message: 'Token inválido ou expirado.' }); }
    req.user = user;
    next();
  });
};

// --- Rotas de Autenticação ---

// Rota de Registro de Usuário (POST /api/register)
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Verificação explícita: Procura por um usuário com o mesmo email antes de tentar salvar.
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

// Rota de Login de Usuário (POST /api/login)
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

// Rota Protegida de Exemplo (GET /api/protected)
// Apenas usuários com um JWT válido e não expirado podem acessar.
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Você acessou uma rota protegida!',
    user: req.user, // Informações do usuário do token
    data: 'Informações confidenciais.'
  });
});

// Rota para Obter Dados do Perfil do Usuário Logado (GET /api/profile)
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

// Rota para Atualizar o Perfil do Usuário Logado (PUT /api/profile)
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
    if (name !== undefined && name !== user.name) {
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

// --- Rotas de Chat ---

// Rota para Obter todos os Chats do Usuário (GET /api/chats)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({ userId: req.user.id }).sort({ updatedAt: -1 });
    res.status(200).json({ chats });
  } catch (error) {
    console.error('Erro ao buscar chats:', error);
    res.status(500).json({ message: 'Erro no servidor ao buscar chats.' });
  }
});

// Rota para Criar um Novo Chat (com mensagem inicial e nome opcional) (POST /api/chats)
app.post('/api/chats', authenticateToken, async (req, res) => {
  const { initialMessage, name } = req.body;
  if (!initialMessage) { return res.status(400).json({ message: 'A primeira mensagem é obrigatória para criar um chat.' }); }
  if (!AI_WEBHOOK_URL) {
    console.error('AI_WEBHOOK_URL não configurado no .env!');
    return res.status(500).json({ message: 'Serviço de IA não configurado.' });
  }

  try {
    const chatName = name || initialMessage.substring(0, 30) + (initialMessage.length > 30 ? '...' : '');

    const newChat = new Chat({ userId: req.user.id, name: chatName });
    await newChat.save();

    const firstUserMessage = new Message({ chatId: newChat._id, sender: 'user', text: initialMessage });
    await firstUserMessage.save();

    // NOVO: Chamar o Webhook de IA para a primeira mensagem
    const sessionId = `${req.user.id}-${newChat._id}`;
    let aiResponsesFromWebhook = [];

    try {
      // Faz a requisição POST para o webhook da IA
      const aiResponse = await axios.post(AI_WEBHOOK_URL, {
        chatInput: initialMessage, // A mensagem do usuário
        sessionId: sessionId,      // O ID da sessão para a IA lembrar o contexto
      }, {
        // Opcional: configurar timeout para a IA
        timeout: 15000 // 15 segundos
      });
      
      // O webhook retorna { "message": ["msg1", "msg2"] }
      // Certifica que é um array, mesmo se o webhook retornar string única
      aiResponsesFromWebhook = aiResponse.data.message || [];
      if (!Array.isArray(aiResponsesFromWebhook)) { // Adicionado verificação para garantir array
        aiResponsesFromWebhook = [String(aiResponsesFromWebhook)]; // Converte para string e coloca em array
      }
    } catch (aiError) {
      console.error('Erro ao chamar webhook de IA (criação de chat):', aiError.response ? aiError.response.data : aiError.message);
      // Retorna uma mensagem de erro padrão da IA se a chamada falhar
      aiResponsesFromWebhook = ["Desculpe, o serviço de tutor está indisponível no momento. Tente novamente mais tarde."];
    }

    // Salvar as respostas da IA no banco de dados
    const aiMessagesSaved = [];
    for (const text of aiResponsesFromWebhook) {
      const aiMsg = new Message({ chatId: newChat._id, sender: 'ai', text: text });
      await aiMsg.save();
      aiMessagesSaved.push(aiMsg);
    }

    // Retorna o chat recém-criado e TODAS AS MENSAGENS INICIAIS (usuário + IA)
    // O 'messages' aqui é para popular o frontend imediatamente para o novo chat
    res.status(201).json({
      message: 'Chat criado e resposta da IA obtida!',
      chat: { ...newChat._doc, messages: [firstUserMessage, ...aiMessagesSaved] }, // Inclui as mensagens para o frontend
      userMessage: firstUserMessage, // Mantido para compatibilidade
      aiResponses: aiResponsesFromWebhook, // Array de strings para a fila do frontend
    });
  } catch (error) {
    console.error('Erro ao criar chat ou interagir com IA:', error);
    res.status(500).json({ message: 'Erro no servidor ao criar chat ou obter resposta da IA.' });
  }
});

// Rota para Obter Mensagens de um Chat Específico (GET /api/chats/:chatId/messages)
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const userId = req.user.id;
  try {
    const chat = await Chat.findOne({ _id: chatId, userId });
    if (!chat) { return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' }); }
    const messages = await Message.find({ chatId }).sort({ createdAt: 1 });
    res.status(200).json({ messages });
  } catch (error) {
    console.error('Erro ao buscar mensagens do chat:', error);
    res.status(500).json({ message: 'Erro no servidor ao buscar mensagens.' });
  }
});

// Rota para Adicionar uma Nova Mensagem a um Chat Existente (POST /api/chats/:chatId/messages)
app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const { sender, text } = req.body; // 'sender' aqui deve ser 'user' do frontend
  const userId = req.user.id;

  if (!sender || !text) { return res.status(400).json({ message: 'Remetente e texto da mensagem são obrigatórios.' }); }
  if (!AI_WEBHOOK_URL) {
    console.error('AI_WEBHOOK_URL não configurado no .env!');
    return res.status(500).json({ message: 'Serviço de IA não configurado.' });
  }

  try {
    const chat = await Chat.findOne({ _id: chatId, userId });
    if (!chat) { return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' }); }

    const newMessage = new Message({ chatId, sender, text });
    await newMessage.save();

    chat.updatedAt = Date.now();
    await chat.save();

    // Chamar o Webhook de IA para mensagem em chat existente
    const sessionId = `${req.user.id}-${chatId}`; // sessionId para a IA
    let aiResponsesFromWebhook = [];
    try {
      const aiResponse = await axios.post(AI_WEBHOOK_URL, {
        chatInput: text, // Mensagem do usuário
        sessionId: sessionId,
      }, {
        timeout: 15000 // 15 segundos
      });
      aiResponsesFromWebhook = aiResponse.data.message || [];
      if (!Array.isArray(aiResponsesFromWebhook)) { // Adicionado verificação para garantir array
        aiResponsesFromWebhook = [String(aiResponsesFromWebhook)]; // Converte para string e coloca em array
      }
    } catch (aiError) {
      console.error('Erro ao chamar webhook de IA (chat existente):', aiError.response ? aiError.response.data : aiError.message);
      aiResponsesFromWebhook = ["Desculpe, o serviço de tutor está indisponível no momento. Tente novamente mais tarde."];
    }

    // Salvar as respostas da IA no banco de dados
    const aiMessagesSaved = [];
    for (const aiText of aiResponsesFromWebhook) {
      const aiMsg = new Message({ chatId, sender: 'ai', text: aiText });
      await aiMsg.save();
      aiMessagesSaved.push(aiMsg);
    }
    
    // Retorna a mensagem do usuário (opcional) e as respostas da IA (array de strings)
    res.status(201).json({
      message: 'Mensagem e respostas da IA adicionadas com sucesso!',
      userMessage: newMessage,
      aiResponses: aiResponsesFromWebhook, // Array de strings para a fila do frontend
    });
  } catch (error) {
    console.error('Erro ao adicionar mensagem ou obter resposta da IA:', error);
    res.status(500).json({ message: 'Erro no servidor ao adicionar mensagem ou obter resposta da IA. Tente novamente mais tarde.' });
  }
});

// Rota para Excluir um Chat (DELETE /api/chats/:chatId)
app.delete('/api/chats/:chatId', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const userId = req.user.id;
  try {
    const chat = await Chat.findOneAndDelete({ _id: chatId, userId });
    if (!chat) { return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' }); }
    await Message.deleteMany({ chatId: chatId }); // Exclui mensagens associadas
    res.status(200).json({ message: 'Chat e suas mensagens excluídos com sucesso!' });
  } catch (error) {
    console.error('Erro ao excluir chat:', error);
    res.status(500).json({ message: 'Erro no servidor ao excluir chat. Tente novamente mais tarde.' });
  }
});


// --- Iniciar o Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Rotas de API: /api/register (POST), /api/login (POST), ` +
              `/api/protected (GET), /api/profile (GET, PUT), ` +
              `/api/chats (GET, POST, DELETE), /api/chats/:chatId/messages (GET, POST)`);
});