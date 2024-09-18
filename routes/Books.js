const express = require('express');
const router = express.Router();
const Book = require('../models/Book');
const User = require('../models/User'); // Ensure you have a User model
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// Middleware to protect routes
const auth = (req, res, next) => {
    let token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Remove 'Bearer ' from token if it's present
    if (token.startsWith('Bearer ')) {
        token = token.slice(7, token.length).trim(); // Removes "Bearer " from the token
    }

    try {
        // Verify token and decode it
        const decoded = jwt.verify(token, 'your_jwt_secret_key');

        // Attach the userId to the request object
        req.user = decoded.userId; // Make sure this key exists in your token's payload

        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Get all books (no authentication required)
router.get('/', async (req, res) => {
    try {
        const books = await Book.find();
        res.json(books);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get a single book by ID (no authentication required)
router.get('/:id', async (req, res) => {
    try {
        const book = await Book.findById(req.params.id);
        if (!book) return res.status(404).json({ message: 'Book not found' });
        res.json(book);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Create a new book (authentication required)
router.post('/', auth, async (req, res) => {
    const book = new Book({
        title: req.body.title,
        author: req.body.author,
        description: req.body.description,
        genre: req.body.genre,
        publishedDate: req.body.publishedDate,
        imageUrl: req.body.imageUrl
    });
    try {
        const newBook = await book.save();
        res.status(201).json(newBook);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Update a book (authentication required)
router.patch('/:id', auth, async (req, res) => {
    try {
        const updatedBook = await Book.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedBook) return res.status(404).json({ message: 'Book not found' });
        res.json(updatedBook);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Delete a book (authentication required)
router.delete('/:id', auth, async (req, res) => {
    try {
        const deletedBook = await Book.findByIdAndDelete(req.params.id);
        if (!deletedBook) return res.status(404).json({ message: 'Book not found' });
        res.json({ message: 'Book deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Bulk insert books (authentication required)
router.post('/bulk', auth, async (req, res) => {
    const booksData = req.body;

    // Check if the request body is an array
    if (!Array.isArray(booksData)) {
        return res.status(400).json({ message: 'Input should be an array of books' });
    }

    try {
        // Insert multiple books into the database
        const insertedBooks = await Book.insertMany(booksData);
        res.status(201).json(insertedBooks);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Add a review to a book (authentication required)
router.post('/:id/review', auth, async (req, res) => {
    const { rating, comment } = req.body;

    // Log the received rating and comment
    console.log('Received rating:', rating);
    console.log('Received comment:', comment);

    // Convert rating to a number (if it's a string)
    const numericRating = parseInt(rating, 10);

    if (!numericRating || numericRating < 1 || numericRating > 5) {
        return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    try {
        const book = await Book.findById(req.params.id);
        if (!book) return res.status(404).json({ message: 'Book not found' });

        // Check if user has already reviewed
        const existingReview = book.reviews.find((r) => r.user.toString() === req.user);

        if (existingReview) {
            // Update the existing review
            existingReview.rating = numericRating;
            existingReview.comment = comment;
        } else {
            // Add new review
            const review = { user: req.user, rating: numericRating, comment };
            book.reviews.push(review);
        }

        // Update the book's overall rating
        book.rating = book.reviews.reduce((acc, r) => acc + r.rating, 0) / book.reviews.length;

        await book.save();
        res.status(200).json(book);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get all reviews for a book (no authentication required)
router.get('/:id/reviews', async (req, res) => {
    try {
        const book = await Book.findById(req.params.id).populate('reviews.user', 'username');
        if (!book) return res.status(404).json({ message: 'Book not found' });

        res.json(book.reviews);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Delete a review (authentication required)
router.delete('/:id/review', auth, async (req, res) => {
    try {
        const book = await Book.findById(req.params.id);
        if (!book) return res.status(404).json({ message: 'Book not found' });

        const reviewIndex = book.reviews.findIndex((r) => r.user.toString() === req.user);
        if (reviewIndex === -1) return res.status(404).json({ message: 'Review not found' });

        // Remove the review from the book
        book.reviews.splice(reviewIndex, 1);

        // Update the book's overall rating
        book.rating = book.reviews.length > 0
            ? book.reviews.reduce((acc, r) => acc + r.rating, 0) / book.reviews.length
            : 0;

        await book.save();
        res.json({ message: 'Review deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Register a new user
router.post('/register', [
    body('username').not().isEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Email is invalid'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        user = new User({
            username,
            email,
            password: hashedPassword
        });
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, iat: Math.floor(Date.now() / 1000) },
            'your_jwt_secret_key',
            { expiresIn: '10h' }
        );

        // Send response with username and token
        res.status(201).json({ username: user.username, token });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Login user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ userId: user._id }, 'your_jwt_secret_key', { expiresIn: '1h' });

        // Send response with username and token
        res.json({ username: user.username, token });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get a user's username by userId (authentication not required for this)
router.get('/user/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const user = await User.findById(userId).select('username'); // Only select the username field
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ username: user.username });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
