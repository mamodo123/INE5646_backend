// backend/server.js
require('dotenv').config(); // Carrega variáveis de ambiente do arquivo .env
const express = require('express'); // Framework web para Node.js
const mongoose = require('mongoose'); // ODM (Object Data Modeling) para MongoDB
const jwt = require('jsonwebtoken'); // Biblioteca para trabalhar com JSON Web Tokens
const cors = require('cors'); // Middleware para habilitar CORS (Cross-Origin Resource Sharing)
const crypto = require('crypto'); // Módulo nativo do Node.js para operações criptográficas
const axios = require('axios'); // Cliente HTTP para fazer requisições a APIs externas (como a IA)

const app = express(); // Inicializa a aplicação Express
const PORT = process.env.PORT || 5000; // Porta do servidor, padrão 5000
const MONGO_URI = process.env.MONGO_URI; // URI de conexão com o MongoDB
const JWT_SECRET = process.env.JWT_SECRET; // Chave secreta para assinar e verificar JWTs
const AI_WEBHOOK_URL = process.env.AI_WEBHOOK_URL; // URL do webhook da API de IA

// AVISO IMPORTANTE DE SEGURANÇA: MD5 NÃO é recomendado para hash de senhas em produção.
// Use algoritmos mais seguros como bcrypt ou Argon2 para senhas.
const MD5_GLOBAL_SALT = 'a495af97-7667-4fdb-bc1a-13a566943ad4'; // Sal global para hashing MD5

// Função para hashear senhas usando MD5 com um sal global.
const hashPasswordWithMD5 = (password) => {
  return crypto.createHash('md5').update(password + MD5_GLOBAL_SALT).digest('hex');
};

// --- Middlewares ---
app.use(cors()); // Habilita o CORS para permitir requisições de diferentes origens
app.use(express.json()); // Habilita o parsing de JSON para requisições com 'Content-Type: application/json'

// --- Conexão com o MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Conectado ao MongoDB!');
    // Garante a criação de um índice único para o campo 'email' na coleção 'users'.
    // Isso evita que dois usuários se registrem com o mesmo email.
    return mongoose.connection.db.collection('users').createIndexes([
      { key: { email: 1 }, unique: true }
    ]).catch(err => {
      // Ignora o erro se o índice já existir (código 11000)
      if (err.code !== 11000) {
        console.error('Erro ao criar índice único para email:', err);
      }
    });
  })
  .then(() => console.log('Índices MongoDB garantidos!'))
  .catch(err => console.error('Erro ao conectar ao MongoDB ou criar índices:', err));

// --- Schemas e Modelos Mongoose ---

// Schema para o modelo de Usuário
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true }, // Email deve ser único
  password: { type: String, required: true }
});
// Middleware 'pre' do Mongoose: Hasheia a senha antes de salvar o usuário, se a senha foi modificada.
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) { this.password = hashPasswordWithMD5(this.password); }
  next();
});
const User = mongoose.model('User', userSchema); // Cria o modelo 'User'

// Schema para o modelo de Chat
const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Referência ao dono do chat
  name: { type: String, default: 'Nova Conversa' }, // Nome do chat, padrão 'Nova Conversa'
  createdAt: { type: Date, default: Date.now }, // Data de criação do chat
  updatedAt: { type: Date, default: Date.now }, // Data da última atualização do chat
  // Campo para armazenar IDs de usuários com quem o chat foi compartilhado
  sharedWith: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // ID do usuário com quem foi compartilhado
    permission: { type: String, enum: ['read'], default: 'read' } // Tipo de permissão (atualmente apenas 'read')
  }]
});
// Middleware 'pre' do Mongoose: Atualiza a data de 'updatedAt' antes de salvar o chat.
chatSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });
const Chat = mongoose.model('Chat', chatSchema); // Cria o modelo 'Chat'

// Schema para o modelo de Mensagem
const messageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true }, // Referência ao chat ao qual a mensagem pertence
  sender: { type: String, required: true, enum: ['user', 'ai'] }, // Remetente da mensagem (usuário ou IA)
  text: { type: String, required: true }, // Conteúdo da mensagem
  createdAt: { type: Date, default: Date.now } // Data de criação da mensagem
});
const Message = mongoose.model('Message', messageSchema); // Cria o modelo 'Message'

// --- Middleware para Proteger Rotas (Autenticação JWT) ---
// Verifica a presença e validade de um token JWT na requisição.
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extrai o token do cabeçalho 'Authorization: Bearer <token>'
  if (!token) { return res.status(401).json({ message: 'Token de autenticação não fornecido.' }); } // 401 se não houver token

  // Verifica o token usando a chave secreta.
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Erro de verificação do token:', err.message);
      return res.status(403).json({ message: 'Token inválido ou expirado.' }); // 403 se o token for inválido
    }
    req.user = user; // Anexa as informações do usuário decodificadas ao objeto de requisição
    next(); // Continua para a próxima função middleware ou rota
  });
};

// --- Rotas de Autenticação ---

// Rota de Registro de Usuário (POST /api/register)
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Verifica explicitamente se já existe um usuário com o email fornecido.
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Este email já está em uso. Por favor, use outro.' });
    }

    const newUser = new User({ name, email, password });
    await newUser.save(); // A senha será automaticamente hasheada pelo middleware 'pre('save')'

    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    // Trata o erro de índice único (email duplicado) caso a verificação explícita falhe
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
      return res.status(400).json({ message: 'Credenciais inválidas.' }); // Usuário não encontrado
    }

    // Hasheia a senha fornecida pelo usuário para comparação com a senha armazenada
    const hashedPasswordAttempt = hashPasswordWithMD5(password);
    if (hashedPasswordAttempt !== user.password) {
      return res.status(400).json({ message: 'Credenciais inválidas.' }); // Senha incorreta
    }

    // Gera um token JWT com o ID e email do usuário, com expiração de 1 hora
    const token = jwt.sign(
      { id: user._id, email: user.email }, // Payload do token
      JWT_SECRET, // Chave secreta
      { expiresIn: '1h' } // Tempo de expiração
    );

    // Retorna o token JWT e informações básicas do usuário (sem a senha)
    res.status(200).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro no servidor. Tente novamente mais tarde.' });
  }
});

// --- Rotas Protegidas (requerem autenticação) ---

// Rota Protegida de Exemplo (GET /api/protected)
// Apenas usuários com um JWT válido e não expirado podem acessar esta rota.
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Você acessou uma rota protegida!',
    user: req.user, // Informações do usuário extraídas do token JWT
    data: 'Informações confidenciais.'
  });
});

// Rota para Obter Dados do Perfil do Usuário Logado (GET /api/profile)
app.get('/api/profile', authenticateToken, async (req, res) => {
  const userId = req.user.id; // O ID do usuário é obtido do token JWT (injetado por 'authenticateToken')

  try {
    // Busca o usuário pelo ID, excluindo o campo 'password' do resultado
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }
    res.status(200).json({ user }); // Retorna os dados do usuário (sem a senha)
  } catch (error) {
    console.error('Erro ao obter perfil:', error);
    res.status(500).json({ message: 'Erro no servidor ao obter perfil. Tente novamente mais tarde.' });
  }
});

// Rota para Atualizar o Perfil do Usuário Logado (PUT /api/profile)
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { name, oldPassword, newPassword, confirmNewPassword } = req.body;
  const userId = req.user.id; // O ID do usuário logado é obtido do token

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    let changesMade = false; // Flag para verificar se alguma alteração foi feita

    // 1. Atualizar Nome: Se um novo nome foi fornecido e é diferente do atual
    if (name !== undefined && name !== user.name) {
      user.name = name;
      changesMade = true;
    }

    // 2. Atualizar Senha: Se uma nova senha foi fornecida
    if (newPassword) {
      // Validações para a alteração de senha
      if (!oldPassword) {
        return res.status(400).json({ message: 'Para alterar a senha, a senha antiga é obrigatória.' });
      }
      if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'A nova senha e a confirmação não coincidem.' });
      }

      // Hasheia a senha antiga fornecida e compara com a senha armazenada no banco de dados
      const hashedOldPasswordAttempt = hashPasswordWithMD5(oldPassword);
      if (hashedOldPasswordAttempt !== user.password) {
        return res.status(400).json({ message: 'Senha antiga incorreta.' });
      }

      // Se a senha antiga estiver correta, atualiza a nova senha.
      // O middleware 'pre('save')' do Mongoose irá hashear esta nova senha automaticamente.
      user.password = newPassword;
      changesMade = true;
    }

    // Salva as alterações no banco de dados apenas se algo foi modificado.
    if (changesMade) {
      await user.save();
      return res.status(200).json({ message: 'Perfil atualizado com sucesso!' });
    } else {
      // Se a requisição PUT foi feita, mas sem dados para alterar, retorna sucesso sem modificação.
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
    // Busca todos os chats que pertencem ao usuário logado, ordenados pela última atualização.
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
    // Define o nome do chat, usando as primeiras 30 letras da mensagem inicial se nenhum nome for fornecido.
    const chatName = name || initialMessage.substring(0, 30) + (initialMessage.length > 30 ? '...' : '');

    // Cria e salva o novo chat.
    const newChat = new Chat({ userId: req.user.id, name: chatName });
    await newChat.save();

    // Cria e salva a primeira mensagem do usuário no chat.
    const firstUserMessage = new Message({ chatId: newChat._id, sender: 'user', text: initialMessage });
    await firstUserMessage.save();

    // Chama o Webhook da IA para obter uma resposta à primeira mensagem do usuário.
    const sessionId = `${req.user.id}-${newChat._id}`; // Cria um ID de sessão único para a IA.
    let aiResponsesFromWebhook = [];

    try {
      // Faz a requisição POST para o webhook da IA.
      const aiResponse = await axios.post(AI_WEBHOOK_URL, {
        chatInput: initialMessage, // A mensagem do usuário
        sessionId: sessionId,      // O ID da sessão para a IA manter o contexto
      }, {
        timeout: 15000 // Define um timeout de 15 segundos para a requisição da IA.
      });
      
      // Extrai as respostas da IA. O webhook deve retornar um array de strings.
      aiResponsesFromWebhook = aiResponse.data.message || [];
      // Garante que 'aiResponsesFromWebhook' seja sempre um array.
      if (!Array.isArray(aiResponsesFromWebhook)) {
        aiResponsesFromWebhook = [String(aiResponsesFromWebhook)]; // Converte para string e coloca em um array.
      }
    } catch (aiError) {
      console.error('Erro ao chamar webhook de IA (criação de chat):', aiError.response ? aiError.response.data : aiError.message);
      // Em caso de erro na chamada da IA, retorna uma mensagem de erro padrão.
      aiResponsesFromWebhook = ["Desculpe, o serviço de tutor está indisponível no momento. Tente novamente mais tarde."];
    }

    // Salva todas as respostas da IA no banco de dados.
    const aiMessagesSaved = [];
    for (const text of aiResponsesFromWebhook) {
      const aiMsg = new Message({ chatId: newChat._id, sender: 'ai', text: text });
      await aiMsg.save();
      aiMessagesSaved.push(aiMsg);
    }

    // Retorna o chat recém-criado e todas as mensagens iniciais (usuário + IA) para o frontend.
    res.status(201).json({
      message: 'Chat criado e resposta da IA obtida!',
      chat: { ...newChat._doc, messages: [firstUserMessage, ...aiMessagesSaved] }, // Inclui as mensagens para popular o frontend
      userMessage: firstUserMessage, // Mantido para compatibilidade (pode ser removido se 'chat.messages' for suficiente)
      aiResponses: aiResponsesFromWebhook, // Array de strings para a fila de mensagens da IA no frontend
    });
  } catch (error) {
    console.error('Erro ao criar chat ou interagir com IA:', error);
    res.status(500).json({ message: 'Erro no servidor ao criar chat ou obter resposta da IA.' });
  }
});

// Rota para Obter Mensagens de um Chat Específico (GET /api/chats/:chatId/messages)
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const userId = req.user.id; // ID do usuário logado

  try {
    // Busca o chat e verifica se o usuário logado é o dono OU se o chat foi compartilhado com ele.
    const chat = await Chat.findOne({
      _id: chatId,
      $or: [
        { userId: userId }, // O usuário é o dono do chat
        { 'sharedWith.userId': userId } // O chat foi compartilhado com o usuário
      ]
    });

    if (!chat) {
      // Se o chat não for encontrado OU o usuário não tiver permissão de acesso.
      return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' });
    }

    // Se o chat foi encontrado e o usuário tem permissão, busca as mensagens associadas.
    const messages = await Message.find({ chatId }).sort({ createdAt: 1 }); // Ordena as mensagens por data de criação.
    res.status(200).json({ messages });
  } catch (error) {
    console.error('Erro ao buscar mensagens do chat:', error);
    res.status(500).json({ message: 'Erro no servidor ao buscar mensagens.' });
  }
});

// Rota para Adicionar uma Nova Mensagem a um Chat Existente (POST /api/chats/:chatId/messages)
app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const { sender, text } = req.body; // 'sender' aqui deve ser 'user' vindo do frontend
  const userId = req.user.id; // ID do usuário logado

  if (!sender || !text) { return res.status(400).json({ message: 'Remetente e texto da mensagem são obrigatórios.' }); }
  if (!AI_WEBHOOK_URL) {
    console.error('AI_WEBHOOK_URL não configurado no .env!');
    return res.status(500).json({ message: 'Serviço de IA não configurado.' });
  }

  try {
    // Verifica se o chat existe e pertence ao usuário logado.
    const chat = await Chat.findOne({ _id: chatId, userId });
    if (!chat) { return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' }); }

    // Cria e salva a nova mensagem do usuário.
    const newMessage = new Message({ chatId, sender, text });
    await newMessage.save();

    // Atualiza a data de 'updatedAt' do chat para trazê-lo para o topo da lista de chats recentes.
    chat.updatedAt = Date.now();
    await chat.save();

    // Chama o Webhook da IA para obter uma resposta à nova mensagem.
    const sessionId = `${req.user.id}-${chatId}`; // ID de sessão para a IA
    let aiResponsesFromWebhook = [];
    try {
      const aiResponse = await axios.post(AI_WEBHOOK_URL, {
        chatInput: text, // Mensagem do usuário
        sessionId: sessionId, // ID da sessão para a IA manter o contexto
      }, {
        timeout: 15000 // Timeout de 15 segundos
      });
      aiResponsesFromWebhook = aiResponse.data.message || [];
      // Garante que 'aiResponsesFromWebhook' seja sempre um array.
      if (!Array.isArray(aiResponsesFromWebhook)) {
        aiResponsesFromWebhook = [String(aiResponsesFromWebhook)];
      }
    } catch (aiError) {
      console.error('Erro ao chamar webhook de IA (chat existente):', aiError.response ? aiError.response.data : aiError.message);
      // Em caso de erro, retorna uma mensagem de erro padrão da IA.
      aiResponsesFromWebhook = ["Desculpe, o serviço de tutor está indisponível no momento. Tente novamente mais tarde."];
    }

    // Salva todas as respostas da IA no banco de dados.
    const aiMessagesSaved = [];
    for (const aiText of aiResponsesFromWebhook) {
      const aiMsg = new Message({ chatId, sender: 'ai', text: aiText });
      await aiMsg.save();
      aiMessagesSaved.push(aiMsg);
    }
    
    // Retorna a mensagem do usuário (opcional) e as respostas da IA (array de strings) para o frontend.
    res.status(201).json({
      message: 'Mensagem e respostas da IA adicionadas com sucesso!',
      userMessage: newMessage,
      aiResponses: aiResponsesFromWebhook, // Array de strings para a fila de mensagens da IA no frontend
    });
  } catch (error) {
    console.error('Erro ao adicionar mensagem ou obter resposta da IA:', error);
    res.status(500).json({ message: 'Erro no servidor ao adicionar mensagem ou obter resposta da IA. Tente novamente mais tarde.' });
  }
});

// Rota para Excluir um Chat (DELETE /api/chats/:chatId)
app.delete('/api/chats/:chatId', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const userId = req.user.id; // ID do usuário logado

  try {
    // Encontra e deleta o chat se ele pertencer ao usuário logado.
    const chat = await Chat.findOneAndDelete({ _id: chatId, userId });
    if (!chat) { return res.status(404).json({ message: 'Chat não encontrado ou acesso negado.' }); }
    
    // Exclui todas as mensagens associadas a este chat.
    await Message.deleteMany({ chatId: chatId });
    res.status(200).json({ message: 'Chat e suas mensagens excluídos com sucesso!' });
  } catch (error) {
    console.error('Erro ao excluir chat:', error);
    res.status(500).json({ message: 'Erro no servidor ao excluir chat. Tente novamente mais tarde.' });
  }
});

// Rota para Compartilhar um Chat com Outro Usuário (POST /api/chats/:chatId/share)
app.post('/api/chats/:chatId/share', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const { email } = req.body; // Email do usuário com quem o chat será compartilhado
  const ownerId = req.user.id; // ID do usuário que está compartilhando o chat

  if (!email) {
    return res.status(400).json({ message: 'O email do destinatário é obrigatório.' });
  }

  try {
    // 1. Verifica se o chat existe e pertence ao usuário que está compartilhando.
    const chat = await Chat.findOne({ _id: chatId, userId: ownerId });
    if (!chat) {
      return res.status(404).json({ message: 'Chat não encontrado ou você não tem permissão para compartilhá-lo.' });
    }

    // 2. Encontra o usuário com quem o chat será compartilhado pelo email.
    const userToShareWith = await User.findOne({ email });
    if (!userToShareWith) {
      // Retorna erro se o usuário com o email fornecido não for encontrado na plataforma.
      return res.status(404).json({ message: 'Usuário com este email não encontrado em nossa plataforma.' });
    }

    // 3. Verifica se o usuário que está compartilhando não está tentando compartilhar consigo mesmo.
    if (userToShareWith._id.equals(ownerId)) {
        return res.status(400).json({ message: 'Você não pode compartilhar um chat consigo mesmo.' });
    }
    // 4. Verifica se o chat já não está compartilhado com este usuário.
    const alreadyShared = chat.sharedWith.some(share => share.userId.equals(userToShareWith._id));
    if (alreadyShared) {
      return res.status(400).json({ message: 'Este chat já foi compartilhado com este usuário.' });
    }

    // 5. Adiciona o ID do usuário à lista 'sharedWith' do chat.
    chat.sharedWith.push({ userId: userToShareWith._id, permission: 'read' });
    await chat.save(); // Salva as alterações no chat.

    res.status(200).json({ message: `Chat compartilhado com sucesso com ${email}!` });

  } catch (error) {
    console.error('Erro ao compartilhar chat:', error);
    res.status(500).json({ message: 'Erro no servidor ao compartilhar chat. Tente novamente mais tarde.' });
  }
});

// Rota para Obter Chats Compartilhados COM o Usuário Logado (GET /api/shared-chats)
app.get('/api/shared-chats', authenticateToken, async (req, res) => {
  const userId = req.user.id; // ID do usuário logado

  try {
    // Busca todos os chats onde o ID do usuário logado está presente na lista 'sharedWith'.
    // O método 'populate' é usado para preencher os dados do dono do chat (nome e email)
    // a partir do 'userId' referenciado no modelo Chat.
    const sharedChats = await Chat.find({ 'sharedWith.userId': userId })
      .populate('userId', 'name email') // Popula o campo 'userId' do chat com 'name' e 'email' do modelo User.
      .sort({ updatedAt: -1 }); // Ordena os chats pelos mais recentes.

    // Formata os chats para retornar apenas as informações relevantes para o frontend.
    const formattedChats = sharedChats.map(chat => ({
      _id: chat._id,
      name: chat.name,
      owner: { // Informações do dono do chat (populadas)
        _id: chat.userId._id,
        name: chat.userId.name,
        email: chat.userId.email
      },
      createdAt: chat.createdAt,
      updatedAt: chat.updatedAt,
      // O campo 'sharedWith' não é incluído aqui para evitar exposição desnecessária de dados.
    }));

    res.status(200).json({ sharedChats: formattedChats });
  } catch (error) {
    console.error('Erro ao buscar chats compartilhados:', error);
    res.status(500).json({ message: 'Erro no servidor ao buscar chats compartilhados.' });
  }
});

// --- Iniciar o Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Rotas de API disponíveis:`);
  console.log(`  - /api/register (POST): Registro de novo usuário.`);
  console.log(`  - /api/login (POST): Autenticação de usuário.`);
  console.log(`  - /api/profile (GET): Obtém dados do perfil do usuário logado.`);
  console.log(`  - /api/profile (PUT): Atualiza nome e/ou senha do perfil do usuário logado.`);
  console.log(`  - /api/chats (GET): Lista todos os chats do usuário logado.`);
  console.log(`  - /api/chats (POST): Cria um novo chat com uma mensagem inicial e interage com a IA.`);
  console.log(`  - /api/chats/:chatId/messages (GET): Obtém mensagens de um chat específico (requer permissão de dono ou compartilhamento).`);
  console.log(`  - /api/chats/:chatId/messages (POST): Adiciona uma nova mensagem a um chat existente e interage com a IA.`);
  console.log(`  - /api/chats/:chatId (DELETE): Exclui um chat e suas mensagens associadas.`);
  console.log(`  - /api/chats/:chatId/share (POST): Compartilha um chat com outro usuário.`);
  console.log(`  - /api/shared-chats (GET): Lista todos os chats compartilhados com o usuário logado.`);
});
