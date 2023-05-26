const express = require('express');
const app = express();
const routes = require('./src/routes');
const mongoose = require('mongoose');
const cors = require('cors');


require('dotenv').config();

app.use(express.json());

app.use(cors());


mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
})
.catch((error) => {
  console.error('Error connecting to MongoDB:', error);
});

// Set up routes
app.use('/api', routes);

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
