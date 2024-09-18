const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String }
});

const bookSchema = new mongoose.Schema({
    title: { type: String, required: true },
    author: { type: String, required: true },
    reviews: [reviewSchema], // Array of reviews
    description: { type: String, required: true },
    imageUrl: { type: String },
    genre: { type: String, required: true },
    publishedDate: { type: String, required: true }
});



module.exports = mongoose.model('Book', bookSchema);
