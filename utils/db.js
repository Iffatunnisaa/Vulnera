const { required } = require("joi");

const mongoose = require('mongoose');
require('dotenv').config();

async function connectToDatabase() {
    try {
        await mongoose.connect(process.env.MONGODB_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("Database connected successfully!");
    } catch (error) {
        console.log("Database connection failed:", error.message);
    }
}

connectToDatabase();


// Create a schema
const LoginSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

// Schema fleksibel untuk dataset CSV
const DatasetSchema = new mongoose.Schema({}, { strict: false });
const Dataset = mongoose.model("datasets", DatasetSchema);

const Users = new mongoose.model("users", LoginSchema);

module.exports = { Users, Dataset };