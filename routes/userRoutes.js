// Adicionar no userRoutes.js
const { auth, requireAdmin, canManageUser, logSensitiveAction } = require("../middleware/auth");

// Schema para criação de usuário
const createUserSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid("admin", "perito", "assistente").default("assistente")
});

// Schema para atualização de status
const toggleStatusSchema = Joi.object({
  isActive: Joi.boolean().required()
});

// Schema para atualização de permissões
const updatePermissionsSchema = Joi.object({
  permissions: Joi.object({
    cases: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    }),
    evidences: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    }),
    reports: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    }),
    patients: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    }),
    dentalRecords: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    }),
    users: Joi.object({
      read: Joi.boolean(),
      write: Joi.boolean(),
      delete: Joi.boolean()
    })
  }).required()
});

// NOVAS ROTAS PARA GESTÃO DE ACESSOS

// Criar novo usuário (apenas admin)
router.post(
  "/create", 
  auth(), 
  requireAdmin, 
  validate(createUserSchema), 
  logSensitiveAction("CREATE_USER"),
  userController.createUser
);

// Listar todos os usuários com permissões (apenas admin)
router.get(
  "/admin/all", 
  auth(), 
  requireAdmin, 
  userController.getAllUsersWithPermissions
);

// Ativar/desativar usuário (apenas admin)
router.patch(
  "/:id/toggle-status", 
  auth(), 
  requireAdmin, 
  canManageUser,
  validate(toggleStatusSchema), 
  logSensitiveAction("TOGGLE_USER_STATUS"),
  userController.toggleUserStatus
);

// Atualizar permissões específicas (apenas admin)
router.patch(
  "/:id/permissions", 
  auth(), 
  requireAdmin, 
  canManageUser,
  validate(updatePermissionsSchema), 
  logSensitiveAction("UPDATE_USER_PERMISSIONS"),
  userController.updateUserPermissions
);

// Atualizar role do usuário (apenas admin) - melhorada
router.put(
  "/:id/role", 
  auth(), 
  requireAdmin, 
  canManageUser,
  logSensitiveAction("UPDATE_USER_ROLE"),
  userController.updateUserRole
);

// Rota para verificar permissões do usuário atual
router.get("/permissions", auth(), (req, res) => {
  res.json({
    success: true,
    permissions: req.userFull.permissions,
    role: req.user.role
  });
});