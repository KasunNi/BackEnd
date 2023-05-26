const express = require('express');
const router = express.Router();
const { Admin, Customer, ServiceAdvisor, Booking } = require('./models');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
//const config = require('./config');

require('dotenv').config


// Authentication middleware
const authMiddleware = (req, res, next) => {
  try {
    // Check if the request contains a JWT token
    const token = req.headers.authorization.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Verify the JWT token
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    if (!decodedToken) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // Set the decoded user ID on the request
    req.userId = decodedToken.userId;

    // User is authenticated, proceed to the next middleware or route handler
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
};


// Admin routes
// admin routes
router.post('/admin/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(409).json({ message: 'Admin already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = await Admin.create({ name, email, password: hashedPassword });

    res.json({ admin });
  } catch (error) {
    console.error('Error registering admin:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, admin.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ adminId: admin._id }, process.env.SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.patch('/admin/reset-password', async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/admin/bookings', async (req, res) => {
  try {
    const bookings = await Booking.find();
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.patch('/admin/bookings/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const booking = await Booking.findByIdAndUpdate(id, { status }, { new: true });
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.json({ booking });
  } catch (error) {
    console.error('Error updating booking:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Customer routes
router.post('/customer/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingCustomer = await Customer.findOne({ email });
    if (existingCustomer) {
      return res.status(409).json({ message: 'Customer already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const customer = await Customer.create({ name, email, password: hashedPassword });

    res.json({ customer });
  } catch (error) {
    console.error('Error registering customer:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/customer/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const customer = await Customer.findOne({ email });
    if (!customer) {
      return res.status(404).json({ message: 'Customer not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, customer.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ customerId: customer._id }, process.env.SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.patch('/customer/reset-password', async (req, res) => {
  const { email, password } = req.body;

  try {
    const customer = await Customer.findOne({ email });
    if (!customer) {
      return res.status(404).json({ message: 'Customer not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    customer.password = hashedPassword;
    await customer.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/customer/bookings', authMiddleware, async (req, res) => {
  const { customerId } = req.body;

  try {
    const bookings = await Booking.find({ customer: customerId });
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving customer bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/customer/bookings', async (req, res) => {
  const { customerId, serviceAdvisorId, date } = req.body;

  try {
    const booking = await Booking.create({ customer: customerId, serviceAdvisor: serviceAdvisorId, date });
    res.json({ booking });
  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Service Advisor routes
router.post('/service-advisor/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingServiceAdvisor = await ServiceAdvisor.findOne({ email });
    if (existingServiceAdvisor) {
      return res.status(409).json({ message: 'Service Advisor already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const serviceadvisor = await ServiceAdvisor.create({ name, email, password: hashedPassword });

    res.json({ serviceadvisor });
  } catch (error) {
    console.error('Error registering service advisor:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/service-advisor/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const serviceAdvisor = await ServiceAdvisor.findOne({ email });
    if (!serviceAdvisor) {
      return res.status(404).json({ message: 'Service Advisor not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, serviceAdvisor.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ serviceAdvisorId: serviceAdvisor._id }, process.env.SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.patch('/service-advisor/reset-password', async (req, res) => {
  const { email, password } = req.body;

  try {
    const serviceAdvisor = await ServiceAdvisor.findOne({ email });
    if (!serviceAdvisor) {
      return res.status(404).json({ message: 'Service Advisor not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    serviceAdvisor.password = hashedPassword;
    await serviceAdvisor.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/service-advisor/bookings', async (req, res) => {
  try {
    const bookings = await Booking.find();
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.patch('/service-advisor/bookings/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const booking = await Booking.findByIdAndUpdate(id, { status }, { new: true });
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.json({ booking });
  } catch (error) {
    console.error('Error updating booking:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Logout route
router.post('/logout', authMiddleware, async (req, res) => {
  try {
    // Perform logout logic here
    // For example, you can clear the user session or token

    // Assuming you are using sessions:
    //req.session.destroy();

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});

module.exports = router;
