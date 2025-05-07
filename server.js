require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Type', 'Authorization', 'Content-Length']
}));


// MongoDB Connection
// mongoose.connect(process.env.MONGODB_URI)
//   .then(() => console.log('Connected to MongoDB'))
//   .catch(err => console.error('MongoDB connection error:', err));

// // Create uploads directory if it doesn't exist
// const uploadDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadDir)) {
//   fs.mkdirSync(uploadDir, { recursive: true });
// }
// 


// Connection event handlers
const connectWithRetry = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      tls: true,
      authMechanism: 'SCRAM-SHA-256',
      retryWrites: false,
      driverInfo: { 
        name: 'cosmosdb-mongodb-connector',
        version: '1.0'
      }
    });
    console.log('Successfully connected to Azure Cosmos DB MongoDB vCore');
    
    // Verify connection by listing databases
    const adminDb = mongoose.connection.db.admin();
    const dbInfo = await adminDb.command({ listDatabases: 1 });
    console.log(`Connected to ${dbInfo.databases.length} database(s)`);
    
  } catch (err) {
    console.error('Cosmos DB connection error:', err.message);
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  }
};

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('Mongoose default connection open');
});

mongoose.connection.on('error', (err) => {
  console.error(`Mongoose connection error: ${err.message}`);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose connection disconnected');
  console.log('Attempting to reconnect...');
  connectWithRetry();
});

// Initialize connection
connectWithRetry();

// File upload configuration
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    console.log('Uploading file to:', uploadDir); // Add this line

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const filename = uniqueSuffix + path.extname(file.originalname);
    console.log('Generated filename:', filename); // Add this line
    cb(null, filename);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/quicktime'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images and videos are allowed.'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { 
    fileSize: 50 * 1024 * 1024 // 50MB limit
  }
});

// Enhanced Schemas with Cosmos DB optimizations
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    index: true // Important for Cosmos DB performance
  },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['creator', 'consumer'], 
    required: true,
    index: true
  }
}, { timestamps: true });

const mediaSchema = new mongoose.Schema({
  title: { type: String, index: true },
  caption: String,
  location: String,
  people: [{ type: String, index: true }],
  mediaUrl: { type: String, required: true },
  mediaType: { type: String, enum: ['image', 'video'], required: true },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true 
  },
  ratings: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  }
}, { timestamps: true });

const commentSchema = new mongoose.Schema({
  text: String,
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true 
  },
  mediaId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Media',
    index: true 
  }
}, { timestamps: true });

const ratingSchema = new mongoose.Schema({
  value: { 
    type: Number, 
    min: 1, 
    max: 5,
    required: true 
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true 
  },
  mediaId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Media',
    index: true 
  }
}, { timestamps: true });

// Add text index for search functionality
mediaSchema.index({ title: 'text', caption: 'text', location: 'text' });

const User = mongoose.model('User', userSchema);
const Media = mongoose.model('Media', mediaSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Rating = mongoose.model('Rating', ratingSchema);

// Enhanced Authentication Middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false,
      message: 'Authentication token required' 
    });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false,
      message: 'Invalid or expired token' 
    });
  }
};

const authorize = (role) => (req, res, next) => {
  if (req.user.role !== role) {
    return res.status(403).json({ 
      success: false,
      message: 'Unauthorized access' 
    });
  }
  next();
};


// Enhanced Routes with better error handling
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    if (!username || !password || !role) {
      return res.status(400).json({ 
        success: false,
        message: 'All fields are required' 
      });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: 'Username already exists' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ 
      username, 
      password: hashedPassword, 
      role 
    });

    await user.save();

    // Generate token for immediate login
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.status(201).json({ 
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration' 
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Username and password are required' 
      });
    }

    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ 
      success: true,
      token,
      role: user.role,
      user: {
        id: user._id,
        username: user.username,
        role: user.role 
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during login' 
    });
  }
});


app.post('/api/media', authenticate, authorize('creator'), upload.single('media'), async (req, res) => {
    try {
      const { title, caption, location, people } = req.body;
      
      // Validate file exists
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }
  
      // Determine media type
      const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'image';
  
      const media = new Media({
        title,
        caption,
        location,
        people: people.split(',').map(p => p.trim()),
        mediaUrl: `https://instagram-clone-backend.azurewebsites.net/uploads/${req.file.filename}`,
        mediaType,
        userId: req.user._id
      });
  
      await media.save();
      res.status(201).json(media);
    } catch (error) {
      console.error('Upload error:', error);
      // Clean up failed upload
      if (req.file) {
        fs.unlinkSync(path.join(uploadDir, req.file.filename));
      }
      res.status(500).json({ message: error.message });
    }
  });

app.get('/api/media', async (req, res) => {
  try {
    const media = await Media.find().populate('userId', 'username');
    console.log('Media found:', media.length); // Add this line
    res.json(media);
  } catch (error) {
    console.error('Media fetch error:', error); // Add this line
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/media/:id/ratings', authenticate, async (req, res) => {
    try {
      // Check if user already rated this media
      const existingRating = await Rating.findOne({
        userId: req.user._id,
        mediaId: req.params.id
      });
  
      if (existingRating) {
        existingRating.value = req.body.value;
        await existingRating.save();
      } else {
        const rating = new Rating({
          value: req.body.value,
          userId: req.user._id,
          mediaId: req.params.id
        });
        await rating.save();
      }
  
      // Calculate new average rating
      const ratings = await Rating.find({ mediaId: req.params.id });
      const averageRating = ratings.reduce((sum, rating) => sum + rating.value, 0) / ratings.length;
  
      res.json({ averageRating });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  });
  // Comment Routes
app.post('/api/media/:id/comments', authenticate, async (req, res) => {
    try {
      const comment = new Comment({
        text: req.body.text,
        userId: req.user._id,
        mediaId: req.params.id
      });
      await comment.save();
      
      // Populate user info in the response
      const populatedComment = await Comment.findById(comment._id)
        .populate('userId', 'username');
        
      res.status(201).json(populatedComment);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  });
  
  app.get('/api/media/:id/comments', async (req, res) => {
    try {
      const comments = await Comment.find({ mediaId: req.params.id })
        .populate('userId', 'username');
      res.json(comments);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  });


  app.get('/api/health', (req, res) => {
    const status = mongoose.connection.readyState === 1 ? 
      'Database connected' : 'Database disconnected';
    
    res.json({
      status: 'API is running',
      database: status,
      timestamp: new Date().toISOString()
    });
  });
  
  // Error Handling Middleware
  app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ 
        success: false,
        message: err.message 
      });
    }
  
    res.status(500).json({ 
      success: false,
      message: 'Internal server error' 
    });
  });

  app.delete('/api/media/:id', authenticate, async (req, res) => {
    try {
      // 1. Find the media to get the file path
      const media = await Media.findById(req.params.id);
      
      if (!media) {
        return res.status(404).json({ message: 'Media not found' });
      }
  
      // 2. Delete the file from uploads directory
      const filename = media.mediaUrl.split('/').pop();
      const filePath = path.join(uploadDir, filename);
      
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`Deleted file: ${filePath}`);
      }
  
      // 3. Delete all related comments and ratings
      await Comment.deleteMany({ mediaId: req.params.id });
      await Rating.deleteMany({ mediaId: req.params.id });
  
      // 4. Finally delete the media document
      await Media.findByIdAndDelete(req.params.id);
  
      res.json({ success: true, message: 'Media deleted successfully' });
    } catch (error) {
      console.error('Delete error:', error);
      res.status(500).json({ message: error.message });
    }
  });
  
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Upload directory: ${uploadDir}`);
    console.log(`Cosmos DB connection: ${process.env.MONGODB_URI}`);
  });
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
//   console.log(`Upload directory: ${uploadDir}`);
// });

