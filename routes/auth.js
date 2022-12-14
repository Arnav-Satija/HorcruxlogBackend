const router = require("express").Router();
const User = require("../models/user");
const bcrypt = require("bcrypt");
const joi = require('joi');

const regSchema = joi.object({
    username : joi.string().required(),
    email : joi.string().required().email(),
    password : joi.string().required().min(8)
})

const logSchema = joi.object({
    username : joi.string().required(),
    password : joi.string().required().min(8)
})

//REGISTER
router.post("/register", async (req, res) => {
    const userExits = await User.findOne({username : req.body.username})

    if(userExits){
        res.status(400).json("Username already exists")
        return
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPass = await bcrypt.hash(req.body.password, salt);
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPass,
        });

        const {error} = await regSchema.validateAsync(req.body);
        const user = await newUser.save();
        res.status(200).json(user);
    } catch (err) {
        res.status(500).json(err);
    }
});

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const {error} = await logSchema.validateAsync(req.body);
    const user = await User.findOne({ username: req.body.username });
    !user && res.status(400).json("Wrong Username!");

    const validated = await bcrypt.compare(req.body.password, user.password);
    !validated && res.status(400).json("Wrong Password!");

    const { password, ...others } = user._doc;
    res.status(200).json(others);
  } catch (error) {
    res.status(400).json(error);
  }
});

module.exports = router;
