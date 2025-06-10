// Adicionar ao middleware auth.js

// Middleware para verificar permissão específica em recursos
const checkResourcePermission = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.userFull) {
        return res.status(401).json({ 
          success: false,
          msg: "Usuário não autenticado" 
        });
      }

      // Admin tem todas as permissões
      if (req.user.role === 'admin') {
        return next();
      }

      // Verificar permissão específica
      const hasPermission = User.hasPermission(req.userFull, resource, action);
      
      if (!hasPermission) {
        return res.status(403).json({ 
          success: false,
          msg: `Sem permissão para ${action} em ${resource}`,
          required: `${resource}:${action}`,
          userRole: req.user.role
        });
      }

      next();
    } catch (error) {
      logger.error("Erro na verificação de permissão:", error);
      return res.status(500).json({ 
        success: false,
        msg: "Erro interno do servidor" 
      });
    }
  };
};

// Middleware para verificar se o usuário pode acessar seus próprios dados ou é admin
const canAccessUserData = async (req, res, next) => {
  try {
    const targetUserId = req.params.id || req.params.userId;
    
    // Se não há ID específico, pode prosseguir (é para dados próprios)
    if (!targetUserId) {
      return next();
    }

    // Admin pode acessar dados de qualquer usuário
    if (req.user.role === 'admin') {
      return next();
    }

    // Usuário só pode acessar seus próprios dados
    if (req.user.id === targetUserId) {
      return next();
    }

    return res.status(403).json({ 
      success: false,
      msg: "Você só pode acessar seus próprios dados" 
    });

  } catch (error) {
    logger.error("Erro na verificação de acesso:", error);
    return res.status(500).json({ 
      success: false,
      msg: "Erro interno do servidor" 
    });
  }
};

module.exports = {
  auth,
  authorize,
  requireAdmin,
  canManageUser,
  logSensitiveAction,
  checkResourcePermission, // NOVO
  canAccessUserData // NOVO
};