const userModel = require("../model/userModel")
const { isValid } = require("../validator/validator")
const aws = require("../aws/aws")
const bcrypt = require('bcrypt')
const moment = require("moment")
const jwt = require("jsonwebtoken")

//******************************************** Sign Up API ***************************************************

const createUser = async (req, res) => {
    try {
        let data = req.body;
        if (Object.keys(data) == 0) { return res.status(400).send({ status: false, msg: "Bad request, No data provided." }) };

        let { firstName, lastName, email, phone, password, profileImage } = data

        // Validation for Name :
        if (!isValid(firstName)) { return res.status(400).send({ status: false, msg: "firstName is required" }) }
        if (!isValid(lastName)) { return res.status(400).send({ status: false, msg: "lastName is required" }) }

        // Create Profile Image link using aws s3:
        let files = req.files;
        if (Object.keys(files).length == 0) { return res.status(400).send({ status: false, msg: "ProfileImage is required" }) }
        const fileRes = await aws.uploadFile(files[0]);
        data.profileImage = fileRes.Location;

        // Email validation :
        if (!isValid(email)) { return res.status(400).send({ status: false, msg: "email is required" }) }
        if (!(/^\w+([\.-]?\w+)@\w+([\. -]?\w+)(\.\w{2,3})+$/.test(email.trim()))) { return res.status(400).send({ status: false, msg: "Please provide a valid email" }) };

        // Duplicate email check :
        let duplicateEmail = await userModel.findOne({ email: email })
        if (duplicateEmail) return res.status(400).send({ status: false, msg: 'Email is already exist' })

        // Phone number Validation :
        if (!isValid(phone)) { return res.status(400).send({ status: false, msg: "phone is required" }) }
        if (!(/^(\+91[\-\s]?)?[0]?(91)?[789]\d{9}$/.test(phone.trim()))) { return res.status(400).send({ status: false, msg: "please provide a valid moblie Number" }) }

        // Duplicate number check :
        let duplicateNumber = await userModel.findOne({ phone: phone })
        if (duplicateNumber) return res.status(400).send({ status: false, msg: 'Phone number is already exist' })

        // Password Validation :
        if (!isValid(password)) { return res.status(400).send({ status: false, msg: "password is required" }) }
        if (!(password.length >= 8 && password.length <= 15)) { return res.status(400).send({ status: false, message: "Password length should be 8 to 15 characters" }) }
        if (!(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,15}$/.test(password.trim()))) { return res.status(400).send({ status: false, msg: "please provide atleast one uppercase letter ,one lowercase, one character and one number " }) }

        // Hashing the password before storing in the database :
        let securePassword = await bcrypt.hash(password, 4)
        data.password = securePassword

        // Created At time generate using moment :
        data.createdAt = moment(new Date).format("Do MMMM,YYYY, h:mm a");

        // create a user after checking all the validation :
        let userCreated = await userModel.create(data);
        res.status(201).send({ status: true, message: "User created successfully", data: userCreated })
    }
    catch (error) {
        return res.status(500).send({ status: false, msg: error.message })
    }
}





//******************************************** Sign in API ***************************************************

const login = async function (req, res) {
    try {
        // Getting data from user :
        const data = req.body
        const {email, password} = data

        // Input Validation :
        if (Object.keys(data) == 0) return res.status(400).send({ status: false, msg: "Bad Request, No data provided" })

        // Email Validation :
        if (!isValid(email)) { return res.status(400).send({ status: false, msg: "Email is required" }) }
        if (!(/^\w+([\.-]?\w+)@\w+([\. -]?\w+)(\.\w{2,3})+$/.test(data.email.trim()))) { return res.status(400).send({ status: false, msg: "Please enter a valid Email." }) };

        // Password Validation :
        if (!isValid(password)) { return res.status(400).send({ status: false, msg: "Password is required" }) };
        if (!(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,15}$/.test(data.password))) { return res.status(400).send({ status: false, msg: "Email or Password is incorrect" }) }

        // Searching provided email in database :
        let user = await userModel.findOne({ email: email })
        if (!user) { return res.status(400).send({ status: false, msg: "Email or Password is incorrect" }) }
        console.log(user)

        // Compare the provided paasword using bcrypt : 
        let checkPass = user.password
        let checkUser = await bcrypt.compare(password, checkPass)
        if (checkUser == false) return res.status(400).send({ status: false, msg: "Email or Password is incorrect" })

        // Token generate using JWT :
        const token = jwt.sign({
            userId: user._id,
        }, "secret-key", { expiresIn: "120m" })
        return res.status(200).send({ status: true, msg: "You are successfully logged in", userId: user._id, token })
    }
    catch (error) {
        return res.status(500).send({ msg: error.message })
    }
}




//******************************************** Update User API ***************************************************

const updateUser = async (req, res) => {
    try {
        // Taking user id from url or params :
        let userId = req.params.id;

        // Authorisation :
        if (req.userId != userId) { return res.status(403).send({ status: false, msg: "You are not Authorised to update this user" }) }

        // Data to update, getting from user :
        let data = req.body
        let { firstName, lastName, email, phone, password } = data

        // ProfileImage to be Update :
        let files = req.files
        if (files) {
            if (Object.keys(files).length != 0) {
                const fileRes = await aws.uploadFile(files[0]);
                data.profileImage = fileRes.Location;
            }
        }

        // Validation, Cannot update with empty data :
        if (Object.keys(data) == 0) { 
            let files = req.files
            if(!files){
                return res.status(400).send({ status: false, msg: "Pls, provide some data to update." })
            }
        }
            
        // First name and Last name Validation :
        if (firstName == 0) { return res.status(400).send({ status: false, msg: "First name cannot be empty" }) }
        if (lastName == 0) { return res.status(400).send({ status: false, msg: "Last name cannot be empty" }) }

        // Password Validation :
        if (password == 0) { return res.status(400).send({ status: false, msg: "Password Cannot be empty" }) }
        if (password) if (!(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,15}$/.test(password.trim()))) { return res.status(400).send({ status: false, msg: "Please provide a valid password,   Example :Abcd@452" }) }
        if (password) { password = await bcrypt.hash(password, 4) }

        // Email Validation and cannot update duplicate email :
        if (email == 0) { return res.status(400).send({ status: false, msg: "Email Cannot be empty" }) };
        if (email) if (!(/^\w+([\.-]?\w+)@\w+([\. -]?\w+)(\.\w{2,3})+$/.test(email.trim()))) { return res.status(400).send({ status: false, msg: "Please provide a valid email to update" }) };
        let emailDup = await userModel.findOne({ email: email })
        if (emailDup) { return res.status(400).send({ status: false, msg: "Email cannot be duplicate" }) }

        // Phone Number Validation and cannot update duplicate phone number :
        if (phone == 0) { return res.status(400).send({ status: false, msg: "Mobile Number Cannot be empty" }) };
        if (phone) if (!(/^(\+91[\-\s]?)?[0]?(91)?[6789]\d{9}$/.test(phone.trim()))) { return res.status(400).send({ status: false, msg: "please provide a valid moblie Number to update" }) };
        let phoneDup = await userModel.findOne({ phone: phone })
        if (phoneDup) { return res.status(400).send({ status: false, msg: "Phone number cannot be duplicate" }) }

        // Update User :
        let updatedUser = await userModel.findOneAndUpdate({ _id: userId },
            {
                $set:
                {
                    firstName: firstName,
                    lastName: lastName,
                    email: email,
                    phone: phone,
                    password: password,
                    profileImage: data.profileImage,
                    updatedAt : moment(new Date).format("Do MMMM,YYYY, h:mm a")
                }
            }, { new: true })
        return res.status(201).send({ status: true, msg: "User Updated Succesfully", updatedUser: updatedUser })
    }
    catch (error) {
        return res.status(500).send({ status: false, msg: error.message })
    }
}



//****************************************  Get User Details API *************************************************

const getUserProfile = async (req, res) => {
    try {
        // Getting Details from URL or params
        let userId = req.params.id;

        // Authorisation
        if (req.userId != userId) { return res.status(403).send({ status: false, msg: "You are not Authorised to fetch the data" }) }

        // User Validation with fetch the Data
        let user = await userModel.findOne({ _id: userId, isDeleted: false })
        if (!user) return res.status(404).send({ status: false, message: "No user found according to your search" })

        // Fetch Data
        let getUser = await userModel.findOne({ _id: userId })
        return res.status(200).send({ status: true, message: "User Profile Details", data: getUser });
    }
    catch (error) {
        return res.status(500).send({ status: false, msg: error.message })
    }
}



module.exports = {
    createUser,
    login,
    updateUser,
    getUserProfile
}