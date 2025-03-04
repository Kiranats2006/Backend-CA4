const express=require('express');
const app=express();
app.use(express.json());
require("dotenv").config();
const mongoose=require('mongoose');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const cookie=require('cookie-parser');
app.use(cookie());

const userSchema= new mongoose.Schema({
    email:{
        type: String,
        required: true,
    },
    password:{
        type: String,
        required: true,
    }
});
const User=mongoose.model("User", userSchema);

app.post('/auth', async (req, res)=>{
    const {email, password}= req.body;
    if(!email || !password){
        return res.json({message: "Please enter valid email and password"});
    }
    let user= await User.findOne({email});
    if(user){
        const verifyUser= await bcrypt.compare(password, user.password);
        if(!verifyUser) return res.json({message: 'Wrong credentials'});
    }
    else{
        const hashedPassword=await bcrypt.hash(password, 10);
        user=new User({email, password: hashedPassword});
        await user.save();
    }
    const token=jwt.sign({userId: user._id}, "secret", {expiresIn: '15m'});
    res.cookie("token", token, {httpOnly: true});
    res.json({token});
})

const authMiddleware=async (req,res,next)=>{
    const token=req.cookies.token;
    jwt.verify(token, "secret", (err, user)=>{
        try {
            
            if(err) return res.json({message: err});
            req.user=user;
            if(!user) return res.json({message: "Invalid authentication"})
            next();
        } catch (error) {
            console.error(error);
        }
    })
}

app.get('/profile', authMiddleware, async (req,res)=>{
    const user= await User.findById(req.user.userId).select("-password");
    res.json(user);
})


const MONGO_URI=process.env.MONGO_URI
mongoose.connect(MONGO_URI).then(()=>console.log('MongoDb database is connected'))
.catch(err=>console.error(err));

app.listen(8080,()=>{
    console.log('app is running on http://localhost:8080');
})
