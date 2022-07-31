const jwt = require("jsonwebtoken");

const authentication = async function (req, res, next) {
    try {
        // Getting jwt token from header :
        let token = req.headers["tokenkey"];
        if (!token) return res.status(400).send({ status: false, msg: "login is required, Set a header" })

        // Decoding the token using jwt.verify :
        let decodedtoken = jwt.verify(token, "secret-key")
        if (!decodedtoken) return res.status(400).send({ status: false, msg: "token is invalid" })

        // Storing the user id inside the global object(req), It will help to do authorisation : 
        req.userId = decodedtoken.userId
        next();
    }
    catch (error) {
        return res.status(500).send({ status: false, msg: error.message })
    }
}

module.exports = {
    authentication
}