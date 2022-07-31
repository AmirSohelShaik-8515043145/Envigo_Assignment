const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer')
const { default: mongoose } = require('mongoose');

const route = require('./route/route.js');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(multer().any())

mongoose.connect("mongodb+srv://amir-thorium:NSE7ZdUlu4no9WRF@cluster0.gchuo.mongodb.net/Envigo_Assignment?authSource=admin&replicaSet=atlas-cw2o95-shard-0&w=majority&readPreference=primary&appname=MongoDB%20Compass&retryWrites=true&ssl=true", {
    useNewUrlParser: true
})
.then(() => console.log("MongoDb is connected"))
.catch(err => console.log(err))

app.use('/', route);

app.listen(3000, function () {
    console.log('Express app running on port 3000')
});