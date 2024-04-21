const express=require('express');
const router =express.Router();
const { body,validationResult } = require('express-validator');
var fetchuser =require('../middleware/fetchuser');
const Note=require('../models/Note');
// ROUTE 1:Get all notes of  logged users using :GET "/api/notes/getallnotes" .Login Required
router.get(('/getallnotes'),fetchuser,async(req,res)=>{
    try {
        const notes=await Note.find({user:req.user.id});
    res.json(notes);

    } catch (error) {
   console.log(error.message);
   res.status(500).send("Internal server error occured");
}
    

})

// ROUTE 2:Add a new note of logged users using :POST "/api/notes/addnote" .Login Required
router.post(('/addnote'),fetchuser,[
    body('title',"Enter a valid title").isLength({min:3}),
   body('description',"Description must be atleast 5 characters").isLength({min:5}),
],async(req,res)=>{
    try {
        
    

    const{title,description,tag}=req.body;
    //if there are errors,return bad request and the error

const errors=validationResult(req);

if(!errors.isEmpty()){
   return res.status(400).json({errors:errors.array()});
}
const note=new Note({
title,description,tag,user:req.user.id
})
const savedNote=await note.save();
    res.json(savedNote);
} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server error occured");
 }

})



// ROUTE 3:Update an existing note of logged users using :PUT "/api/notes/updatenote" .Login Required
router.put(('/updatenote/:id'),fetchuser,async(req,res)=>{
const {title,description,tag}=req.body;
try {
    

//create a newNote object
const newNote={};
if(title){newNote.title=title};
if(description){newNote.description=description};
if(tag){newNote.tag=tag};

//find note to be updated()

let note= await Note.findById(req.params.id);
if(!note){return res.status(404).send("Not found")}
if(note.user.toString()!==req.user.id){
    return res.ststus(401).send("not allowed");
}
note=await Note.findByIdAndUpdate(req.params.id,{$set:newNote},{new:true})
res.json({note});
} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server error occured");
 }

})




// ROUTE 4:Delete an existing note of logged users using :DELETE "/api/notes/deletenote" .Login Required
router.delete(('/deletenote/:id'),fetchuser,async(req,res)=>{
    
    const {title,description,tag}=req.body;
    
    
      try {
        
        
    
    //find note to be deleted and delete it
    
    let note= await Note.findById(req.params.id);
    if(!note){return res.status(404).send("Not found")}
    //allow deletion only if user owns this note
    if(note.user.toString()!==req.user.id){
        return res.ststus(401).send("not allowed");
    }

    note=await Note.findByIdAndDelete(req.params.id)
    res.json({"success":"note has been deleted",note:note});

} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server error occured");
 }

    })
    
module.exports=router