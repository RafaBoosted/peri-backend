// Adicionar no userController.js - Função para criar usuário (apenas para admins)
exports.createUser = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    // Verificar se o usuário que está criando é admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        msg: "Apenas administradores podem criar novos usuários" 
      });
    }

    // Verificar se usuário já existe
    let existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        msg: "Usuário já existe com este email" 
      });
    }

    // Criar novo usuário
    const user = new User({
      name,
      email,
      password: await bcrypt.hash(password, 12),
      role: role || 'assistente', // Default para assistente
      createdBy: req.user.id, // Quem criou o usuário
      isActive: true
    });

    await user.save();

    // Log da atividade
    await ActivityLog.create({
      userId: req.user.id,
      action: `Usuário criado: ${user.name} (${user.role})`,
      targetId: user._id
    });

    // Retornar usuário sem dados sensíveis
    const userResponse = await User.findById(user._id).select('-password -refreshToken');
    
    res.status(201).json({
      success: true,
      message: "Usuário criado com sucesso",
      user: userResponse
    });

  } catch (error) {
    logger.error("Erro ao criar usuário:", error);
    res.status(500).json({ 
      success: false,
      msg: "Erro interno do servidor" 
    });
  }
};

// Função para listar usuários com permissões
exports.getAllUsersWithPermissions = async (req, res) => {
  try {
    // Verificar se é admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        msg: "Apenas administradores podem listar usuários" 
      });
    }

    const users = await User.find({}, "-password -refreshToken")
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: users.length,
      users
    });

  } catch (error) {
    logger.error("Erro ao buscar usuários:", error);
    res.status(500).json({ 
      success: false,
      msg: "Erro interno do servidor" 
    });
  }
};

// Função para ativar/desativar usuário
exports.toggleUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    // Verificar se é admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        msg: "Apenas administradores podem alterar status de usuários" 
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        msg: "Usuário não encontrado" 
      });
    }

    // Não permitir desativar o próprio usuário
    if (user._id.toString() === req.user.id) {
      return res.status(400).json({ 
        success: false,
        msg: "Você não pode desativar sua própria conta" 
      });
    }

    user.isActive = isActive;
    await user.save();

    // Log da atividade
    await ActivityLog.create({
      userId: req.user.id,
      action: `Usuário ${isActive ? 'ativado' : 'desativado'}: ${user.name}`,
      targetId: user._id
    });

    res.status(200).json({
      success: true,
      message: `Usuário ${isActive ? 'ativado' : 'desativado'} com sucesso`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isActive: user.isActive
      }
    });

  } catch (error) {
    logger.error("Erro ao alterar status do usuário:", error);
    res.status(500).json({ 
      success: false,
      msg: "Erro interno do servidor" 
    });
  }
};

// Função para atualizar permissões específicas de um usuário
exports.updateUserPermissions = async (req, res) => {
  try {
    const { id } = req.params;
    const { permissions } = req.body;

    // Verificar se é admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        msg: "Apenas administradores podem alterar permissões" 
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        msg: "Usuário não encontrado" 
      });
    }

    // Atualizar permissões
    user.permissions = { ...user.permissions, ...permissions };
    await user.save();

    // Log da atividade
    await ActivityLog.create({
      userId: req.user.id,
      action: `Permissões atualizadas para: ${user.name}`,
      targetId: user._id
    });

    res.status(200).json({
      success: true,
      message: "Permissões atualizadas com sucesso",
      user: {
        id: user._id,
        name: user.name,
        role: user.role,
        permissions: user.permissions
      }
    });

  } catch (error) {
    logger.error("Erro ao atualizar permissões:", error);
    res.status(500).json({ 
      success: false,
      msg: "Erro interno do servidor" 
    });
  }
};