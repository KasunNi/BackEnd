const mongoose = require('mongoose');

// Admin model
const adminSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const Admin = mongoose.model('Admin', adminSchema);

// Customer model
const customerSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const Customer = mongoose.model('Customer', customerSchema);

// Service Advisor model
const serviceAdvisorSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const ServiceAdvisor = mongoose.model('ServiceAdvisor', serviceAdvisorSchema);

// Booking model
const bookingSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  serviceAdvisor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ServiceAdvisor',
    required: true
  },
  date: {
    type: Date,
    required: true
  },
  vehicleRegNumber: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  }
});

const Booking = mongoose.model('Booking', bookingSchema);

module.exports = { Admin, Customer, ServiceAdvisor, Booking };
