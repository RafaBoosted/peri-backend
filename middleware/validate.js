const Joi = require("joi");

exports.validate = (schema, source = "body") => {
  return (req, res, next) => {
    try {
      // Log para debug
      console.log(
        `Validando ${source}:`,
        source === "params" ? req.params : req.body
      );

      const dataToValidate = source === "params" ? req.params : req.body;
      const { error } = schema.validate(dataToValidate, { abortEarly: false });

      if (error) {
        const errors = error.details.map((detail) => detail.message);
        console.error("Erros de validação:", errors);

        return res.status(400).json({
          success: false,
          message: errors[0],
          errors: errors,
          validation: error.details.reduce((acc, detail) => {
            acc[detail.path[0]] = detail.message;
            return acc;
          }, {}),
        });
      }

      next();
    } catch (err) {
      console.error("Erro no middleware de validação:", err);
      res.status(500).json({
        success: false,
        message: "Erro interno na validação",
        error: err.message,
      });
    }
  };
};


const userSchemas = {
  // Schema para criação de usuário
  createUser: Joi.object({
    name: Joi.string().min(2).max(50).trim().required()
      .messages({
        'string.min': 'Nome deve ter pelo menos 2 caracteres',
        'string.max': 'Nome não pode ter mais de 50 caracteres',
        'any.required': 'Nome é obrigatório'
      }),
    email: Joi.string().email().lowercase().required()
      .messages({
        'string.email': 'Email deve ter um formato válido',
        'any.required': 'Email é obrigatório'
      }),
    password: Joi.string().min(6).required()
      .messages({
        'string.min': 'Senha deve ter pelo menos 6 caracteres',
        'any.required': 'Senha é obrigatória'
      }),
    role: Joi.string().valid('admin', 'perito', 'assistente').default('assistente')
      .messages({
        'any.only': 'Role deve ser admin, perito ou assistente'
      }),
    profile: Joi.object({
      phone: Joi.string().pattern(/^\(\d{2}\)\s\d{4,5}-\d{4}$/).optional(),
      cpf: Joi.string().pattern(/^\d{11}$/).optional(),
      cro: Joi.string().optional(),
      specialization: Joi.string().optional()
    }).optional()
  }),

  // Schema para atualização de perfil
  updateProfile: Joi.object({
    name: Joi.string().min(2).max(50).trim().optional(),
    profile: Joi.object({
      phone: Joi.string().pattern(/^\(\d{2}\)\s\d{4,5}-\d{4}$/).optional(),
      cpf: Joi.string().pattern(/^\d{11}$/).optional(),
      cro: Joi.string().optional(),
      specialization: Joi.string().optional(),
      address: Joi.object({
        street: Joi.string().optional(),
        number: Joi.string().optional(),
        city: Joi.string().optional(),
        state: Joi.string().length(2).optional(),
        zipCode: Joi.string().pattern(/^\d{5}-?\d{3}$/).optional()
      }).optional()
    }).optional()
  }),

  // Schema para mudança de senha
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
      .messages({
        'any.only': 'Confirmação de senha deve ser igual à nova senha'
      })
  })
};

module.exports = { userSchemas };
