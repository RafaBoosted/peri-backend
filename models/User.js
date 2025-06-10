// models/User.js - Modelo de usuário ATUALIZADO (baseado no seu código atual)
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true, 
    trim: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true 
  },
  password: { 
    type: String, 
    required: true, 
    minlength: 6 
  },
  role: { 
    type: String, 
    enum: ['admin', 'perito', 'assistente'], 
    default: 'perito' 
  },
  resetPasswordToken: { type: String },
  resetPasswordExpire: { type: Date },
  refreshToken: { type: String },
  isActive: { 
    type: Boolean, 
    default: true 
  },
  // NOVOS CAMPOS PARA GESTÃO DE ACESSOS
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return this.role !== 'admin'; // admin não precisa de criador
    }
  },
  permissions: {
    cases: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    },
    evidences: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    },
    reports: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    },
    patients: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    },
    dentalRecords: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    },
    users: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false }
    }
  },
  // CAMPOS OPCIONAIS PARA PERFIL EXPANDIDO
  profile: {
    phone: String,
    cpf: {
      type: String,
      unique: true,
      sparse: true, // Permite múltiplos null
      match: [/^\d{11}$/, 'CPF deve ter 11 dígitos']
    },
    cro: String, // Registro no Conselho Regional de Odontologia
    specialization: String,
    address: {
      street: String,
      number: String,
      city: String,
      state: String,
      zipCode: String
    }
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockedUntil: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Índices para performance
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });

// Virtual para verificar se conta está bloqueada
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockedUntil && this.lockedUntil > Date.now());
});

// Virtual para verificar se conta está bloqueada
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockedUntil && this.lockedUntil > Date.now());
});

// Middleware para definir permissões baseadas na função
userSchema.pre('save', function(next) {
  if (!this.isModified('role')) return next();
  
  this.setPermissionsByRole();
  next();
});

// Método para incrementar tentativas de login
userSchema.methods.incLoginAttempts = function() {
  // Se já temos tentativas anteriores e ainda não expirou o bloqueio
  if (this.lockedUntil && this.lockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockedUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Se excedeu 5 tentativas e não está bloqueado, bloquear por 2 horas
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockedUntil: Date.now() + 2 * 60 * 60 * 1000 };
  }
  
  return this.updateOne(updates);
};

// Método para resetar tentativas de login
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockedUntil: 1 },
    $set: { lastLogin: new Date() }
  });
};

// Método para definir permissões baseadas na função
userSchema.methods.setPermissionsByRole = function() {
  const rolePermissions = {
    admin: {
      cases: { read: true, write: true, delete: true },
      evidences: { read: true, write: true, delete: true },
      reports: { read: true, write: true, delete: true },
      patients: { read: true, write: true, delete: true },
      dentalRecords: { read: true, write: true, delete: true },
      users: { read: true, write: true, delete: true }
    },
    perito: {
      cases: { read: true, write: true, delete: false },
      evidences: { read: true, write: true, delete: false },
      reports: { read: true, write: true, delete: false },
      patients: { read: true, write: true, delete: false },
      dentalRecords: { read: true, write: true, delete: false },
      users: { read: true, write: false, delete: false }
    },
    assistente: {
      cases: { read: true, write: false, delete: false },
      evidences: { read: true, write: true, delete: false },
      reports: { read: true, write: false, delete: false },
      patients: { read: true, write: true, delete: false },
      dentalRecords: { read: true, write: false, delete: false },
      users: { read: false, write: false, delete: false }
    }
  };
  
  this.permissions = rolePermissions[this.role] || rolePermissions.assistente;
};

// Método estático para verificar permissões
userSchema.statics.hasPermission = function(user, resource, action) {
  if (!user.isActive) return false;
  if (user.isLocked) return false;
  
  return user.permissions[resource] && user.permissions[resource][action];
};

// Método para obter hierarquia
userSchema.methods.getHierarchyLevel = function() {
  const hierarchy = { admin: 3, perito: 2, assistente: 1 };
  return hierarchy[this.role] || 0;
};

// Método para verificar se pode gerenciar outro usuário
userSchema.methods.canManageUser = function(targetUser) {
  if (this.role !== 'admin') return false;
  return this.getHierarchyLevel() >= targetUser.getHierarchyLevel();
};

module.exports = mongoose.model('User', userSchema);