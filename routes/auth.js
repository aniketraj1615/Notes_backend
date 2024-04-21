const express = require('express');
const { body,validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const User=require('../models/User');
const router = express.Router();
var jwt = require('jsonwebtoken');
var fetchuser =require('../middleware/fetchuser')
//this is used to check that someone is changed the token or not
const JWT_SECRET="Golu@Devloper";
// ROUTE 1: Create a user using:POST "/api/auth/createuser".No login required
router.post('/createuser',[
   body('name',"Enter a valid name").isLength({min:3}),
   body('email',"Enter a valid email").isEmail(),
   body('password',"Password must be atleast 5 characters").isLength({min:5}),
], async(req, res) => {
   let success=false;
   //if there are errors,return bad request and the error

const errors=validationResult(req);

if(!errors.isEmpty()){
   return res.status(400).json({errors:errors.array()});
}
//check if user already exits with this email
try {
   

let user= await User.findOne({email:req.body.email});
console.log(user)
if(user){
   return res.status(400).json({success,error:"sorry user with this email already exits"})
}
const salt=await bcrypt.genSalt(10);
const secPass=await bcrypt.hash(req.body.password,salt);
 user=await User.create({
   name:req.body.name,
   email:req.body.email,
   password:secPass,
})
const data={
user:{
   id:user.id
}
}
const authtoken=jwt.sign(data,JWT_SECRET);

// res.json(user)
success=true;
res.json({success,authtoken})
} catch (error) {
   console.log(error.message);
   res.status(500).send("Internal server error occured");
}
});



//ROUTE 2: Authenticate a user using:POST "/api/auth/login".No login required
router.post('/login',[
   
   body('email',"Enter a valid email").isEmail(),
   body('password',"password can't be blank").exists(),
   
], async(req, res) => {
   let success=false;
   //if there are errors,return bad request and the error

const errors=validationResult(req);
if(!errors.isEmpty()){
   return res.status(400).json({errors:errors.array()});
}
const {email,password}=req.body;
try{
let user=await User.findOne({email});
if(!user){
   return res.status(400).json({error:"Please try to login with correct credentials"});
}

const passwordCompare=await bcrypt.compare(password,user.password);
if(!passwordCompare){
   
   return res.status(400).json({success,error:"Please try to login with correct credentials"});
}
const data={
   user:{
      id:user.id
   }
   }
   const authtoken=jwt.sign(data,JWT_SECRET);

success=true;
res.json({success,authtoken})
}
catch (error) {
   console.log(error.message);
   res.status(500).send("Internal server error occured");
}
})



// ROUTE 3:Get details of logged users using :POST "/api/auth/getuser" .Login Required

router.post('/getuser',fetchuser,async(req, res) => {
try {
  const userId=req.user.id;
   const user=await User.findById(userId).select("-password")
res.send(user)
   
} catch (error) {
   console.log(error.message);
   res.status(500).send("Internal server error occured");
}
})
module.exports = router;
