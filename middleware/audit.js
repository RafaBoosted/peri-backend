// Criar arquivo middleware/audit.js

const ActivityLog = require('../models/ActivityLog');
const logger = require('../utils/logger');

// Middleware para auditoria completa
const auditLogger = (action, resource = null) => {
  return (req, res, next) => {
    const originalSend = res.send;
    const startTime = Date.now();
    
    res.send = function(data) {
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      // Log apenas operações bem-sucedidas
      if (res.statusCode < 400) {
        const auditData = {
          userId: req.user?.id,
          userRole: req.user?.role,
          action,
          resource,
          method: req.method,
          endpoint: req.originalUrl,
          ip: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent'),
          responseTime,
          timestamp: new Date(),
          statusCode: res.statusCode
        };

        // Adicionar dados específicos baseados na ação
        if (req.params.id) auditData.targetId = req.params.id;
        if (req.body && Object.keys(req.body).length > 0) {
          // Não logar dados sensíveis
          const sanitizedBody = { ...req.body };
          delete sanitizedBody.password;
          delete sanitizedBody.currentPassword;
          delete sanitizedBody.newPassword;
          auditData.requestData = sanitizedBody;
        }

        // Salvar no banco de dados
        ActivityLog.create(auditData).catch(err => {
          logger.error('Erro ao salvar log de auditoria:', err);
        });

        // Log estruturado
        logger.info('Audit Log', auditData);
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

module.exports = { auditLogger };