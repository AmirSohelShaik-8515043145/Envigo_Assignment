const express = require("express")
const { createUser, login, updateUser, getUserProfile } = require("../controller/userController")
const { authentication } = require("../middleware/middleware")
const router = express.Router()


router.post('/signup', createUser)                      // Sign up API endpoint
router.post('/signin', login)                           // Sign in API endpoint
router.put('/user/:id',authentication,updateUser)       // Update user API endpoint
router.get('/user/:id',authentication,getUserProfile)   // Get user API endpoint




module.exports = router