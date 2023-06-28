const express=require("express")
const bodyParser=require("body-parser")
const ejs=require("ejs")
const mongoose=require("mongoose")

const app=express()

app.use(express.static("public"))
app.set('view engine','ejs')
app.use(bodyParser.urlencoded({extended:true}))

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true, useUnifiedTopology: true})

const userSchema=mongoose.Schema({
    username:String,
    password:String
})

const User=mongoose.model('User',userSchema)

app.get("/",(req,res)=>{
    res.render("home")
})

app.get("/login",(req,res)=>{
    res.render("login")
})

app.get("/register",(req,res)=>{
    res.render("register")
})

app.post("/register",(req,res)=>{
    const newUser=new User({
        username:req.body.username,
        password:req.body.password
    })
    newUser.save().then(()=>{
        console.log("User added successfully")
        res.render("secrets")
    }).catch((err)=>{
        console.log("User insertion failed => "+err)
    })})

app.post("/login",(req,res)=>{
    User.findOne({username:req.body.username}).then((found)=>{
        if(found.password===req.body.password){
            res.render("secrets")
        }else{
            console.log("Incorrect Password")}
            // res.redirect("/")
    }).catch((err)=>{
        console.log("User not found.")
    })
})


app.listen(3000,()=>{
    console.log("Server started on port 3000")
})