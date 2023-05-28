const express = require('express');
const router = express.Router();
const { Admin, Customer, ServiceAdvisor, Booking, ServiceCenter, ServicePackage } = require('./models');
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

//Admin check middleware
const adminAuth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    const admin = await Admin.findOne({ _id: decoded._id, 'tokens.token': token });

    if (!admin) {
      throw new Error();
    }

    req.token = token;
    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed' });
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

    res.json({ token, email });
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

router.post('/admin/getbookings', authMiddleware, async (req, res) => {
  const { email } = req.body;

  try {
    const bookings = await Booking.find();
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving customer bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/admin/customers', adminAuth, async (req, res) => {
  try {
    const customers = await Customer.find();
    res.json({ customers });
  } catch (error) {
    console.error('Error retrieving customers:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/admin/admins', authMiddleware, async (req, res) => {
  try {
    const admins = await Admin.find();
    res.json({ admins });
  } catch (error) {
    console.error('Error retrieving admins:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/admin/service-advisors', authMiddleware, async (req, res) => {
  try {
    const serviceadvisors = await ServiceAdvisor.find();
    res.json({ serviceadvisors });
  } catch (error) {
    console.error('Error retrieving service advisors:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.get('/admin/service-centers', authMiddleware, async (req, res) => {
  try {
    const servicecenters = await ServiceCenter.find();
    res.json({ servicecenters });
  } catch (error) {
    console.error('Error retrieving service centers:', error);
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

// Add Service Center
router.post('/admin/service-center', async (req, res) => {
	 const { name, location, contactNumber } = req.body;
  try {
    const serviceCenter = await ServiceCenter.create({ name, location, contactNumber });
    res.json({ serviceCenter });
  } catch (error) {
    console.error('Error creating service center:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.delete('/admin/service-center/:id', async (req, res) => {
	const { id } = req.body;
	console.log(req)
  
  try {
    const serviceCenterId = req.params.id;
    // Find the booking by ID
    const servicecenter = await ServicePackage.findById(serviceCenterId);
    if (!servicecenter) {
      return res.status(404).json({ message: 'Service Center not found' });
    }

    // Delete the booking
    await servicepackage.deleteOne();

    res.json({ message: 'Service package deleted successfully' });
  } catch (error) {
    console.error('Error deleting service package:', error);
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

    res.json({ token, email });
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

router.post('/customer/getbookings', authMiddleware, async (req, res) => {
  const { email } = req.body;

  try {
    const bookings = await Booking.find({ email: email });
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving customer bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/customer/bookings', async (req, res) => {
	console.log(req.body);
  const { email, date, vehicleRegNumber, description, serviceAdvisor  } = req.body;

  try {
    const booking = await Booking.create({ email, date, vehicleRegNumber, description, serviceAdvisor: serviceAdvisor });
    res.json({ booking });
  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.delete('/customer/bookings/:id', async (req, res) => {
	const { id } = req.body;
  
  try {
    const bookingId = req.params.id;
    // Find the booking by ID
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }


    // Delete the booking
    await booking.deleteOne();

    res.json({ message: 'Booking deleted successfully' });
  } catch (error) {
    console.error('Error deleting booking:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET route to fetch all service advisors
router.get('/service-advisors', async (req, res) => {
  try {
    // Fetch all service advisors from the database
    const serviceAdvisors = await ServiceAdvisor.find();

    // Return the service advisors as a response
    res.json(serviceAdvisors);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while fetching service advisors' });
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

    res.json({ token, email });
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

router.get('/service-advisor/bookings', authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find();
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/service-advisor/getbookings', async (req, res) => {
  const { serviceAdvisorId } = req.body;

  try {
    const bookings = await Booking.find({ serviceAdvisor: serviceAdvisorId  });
    res.json({ bookings });
  } catch (error) {
    console.error('Error retrieving service advisor bookings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get service advisor ID by email
router.post('/service-advisor/email', async (req, res) => {
	//console.log(req)
  const { serviceAdvisorEmail } = req.body;

  try {
    const serviceAdvisor = await ServiceAdvisor.findOne({ serviceAdvisorEmail });
    if (!serviceAdvisor) {
      return res.status(404).json({ message: 'Service advisor not found' });
    }
console.log(res);
    res.json({ serviceAdvisorId: serviceAdvisor._id });
  } catch (error) {
    console.error('Error fetching service advisor:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update booking status
router.patch('/service-advisor/bookings/:bookingId', async (req, res) => {
  const { bookingId } = req.params;
  const { status } = req.body;

  try {
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    booking.status = status;
    await booking.save();

    res.json({ message: 'Booking status updated successfully' });
  } catch (error) {
    console.error('Error updating booking status:', error);
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

// Add Service Package
router.post('/service-advisor/service-package', async (req, res) => {
	const { name, description, price } = req.body;
   try {
    const servicePackage = await ServicePackage.create({ name, description, price });
    res.json({ servicePackage });
  } catch (error) {
    console.error('Error creating service package:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/service-advisor/service-packages', authMiddleware, async (req, res) => {
  try {
    const servicepackages = await ServicePackage.find();
    res.json({ servicepackages });
  } catch (error) {
    console.error('Error retrieving service packages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.delete('/service-advisor/service-package/:id', async (req, res) => {
	const { id } = req.body;
	console.log(req)
  
  try {
    const servicePackageId = req.params.id;
    // Find the booking by ID
    const servicepackage = await ServicePackage.findById(servicePackageId);
    if (!servicepackage) {
      return res.status(404).json({ message: 'Service Package not found' });
    }

    // Delete the booking
    await servicepackage.deleteOne();

    res.json({ message: 'Service package deleted successfully' });
  } catch (error) {
    console.error('Error deleting service package:', error);
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
