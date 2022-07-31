const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    phone: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        trim: true
    }, // encrypted password
    profileImage: {
        type: String,
        required: true

    }, // s3 link
    isDeleted:{
        type :Boolean,
        default : false
    },
    createdAt: {
        type: String
    },
    updatedAt: {
        type: String
    }
}, { versionKey: false })

module.exports = mongoose.model("users", userSchema)