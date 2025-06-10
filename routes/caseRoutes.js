const express = require("express");
const router = express.Router();
const caseController = require("../controllers/caseController");
const auth = require("../middleware/auth");
const { validate } = require("../middleware/validate");
const Joi = require("joi");
const { auth, checkResourcePermission } = require('../middleware/auth');
const { auditLogger } = require('../middleware/audit');

// Schema de validação para criação de caso
const caseSchema = Joi.object({
  title: Joi.string().min(3).required(),
  description: Joi.string().min(10).required(),
  type: Joi.string().valid("acidente", "identificacao", "criminal").required(),
  status: Joi.string()
    .valid("em_andamento", "finalizado", "arquivado")
    .default("em_andamento"),
  data: Joi.date().iso().required(),
  historico: Joi.string().allow("").optional(),
  analises: Joi.string().allow("").optional(),
});

// Validação do parâmetro ID
const idParamSchema = Joi.object({
  id: Joi.string()
    .pattern(/^[0-9a-fA-F]{22,24}$/) // Aceita IDs com 22 ou 24 caracteres
    .required()
    .messages({
      "string.pattern.base": "O ID deve ter 22 ou 24 caracteres hexadecimais",
      "any.required": "O ID é obrigatório",
      "string.empty": "O ID não pode estar vazio",
    }),
});

router.post(
  "/",
  auth(["perito", "admin", "assistente"]),
  validate(caseSchema),
  caseController.createCase
);
router.put(
  "/:caseId/status",
  auth(["perito", "admin"]),
  caseController.updateCaseStatus
);
router.get("/", auth(), caseController.getCases);

// Rota para buscar caso por ID
router.get(
  "/:id",
  auth(),
  (req, res, next) => {
    // Log para debug
    console.log("Parâmetros recebidos:", req.params);
    next();
  },
  validate(idParamSchema, "params"),
  caseController.getCaseById
);

// Rota para deletar caso
router.delete(
  "/:id",
  auth(["perito", "admin"]),
  validate(idParamSchema, "params"),
  caseController.deleteCase
);

module.exports = router;

// Listar casos - precisa de permissão de leitura
router.get('/', 
  auth(), 
  checkResourcePermission('cases', 'read'),
  auditLogger('LIST_CASES', 'cases'),
  caseController.getAllCases
);

// Criar caso - precisa de permissão de escrita
router.post('/', 
  auth(), 
  checkResourcePermission('cases', 'write'),
  validate(createCaseSchema),
  auditLogger('CREATE_CASE', 'cases'),
  caseController.createCase
);

// Deletar caso - precisa de permissão de exclusão
router.delete('/:id', 
  auth(), 
  checkResourcePermission('cases', 'delete'),
  auditLogger('DELETE_CASE', 'cases'),
  caseController.deleteCase
);