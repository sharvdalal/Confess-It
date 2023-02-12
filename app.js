

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');

const session = require('express-session');
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose'); 
const app = express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const PORT = process.env.PORT || 8000;
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use("/public",express.static(__dirname+"/public"));



app.use(session({
    secret: "Our Little Secret.",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());
const userName = process.env.MONGOATLAS_USERNAME
const password = process.env.MONGOATLAS_PASSWORD

const url = "mongodb+srv://"+userName+":"+password+"@cluster0.4fcsemj.mongodb.net/?retryWrites=true&w=majority"
mongoose.set('strictQuery', true);
mongoose.connect(url, {useNewUrlParser: true});
const userSchema = new mongoose.Schema(
    {
        email:String,
        password:String,
        googleId:String,
        secret:String
    }
);  

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
  

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get('/', (req,res)=>{
    res.render("home.ejs")
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/login', (req,res)=>{
    res.render("login.ejs")
});

app.get('/register', (req,res)=>{
    res.render("register.ejs")
});

app.get('/secrets', (req,res)=>{
    User.find({"secret":{$ne: null}}, (err, foundUser)=>{
         if(err){
            console.log(err);
         }else{
            if(foundUser){
                res.render("secrets.ejs",{usersWithSecrets: foundUser})
            }
         }
    })
});
app.get('/logout',(req,res)=>{
    req.logOut((err)=>{
        if(err){
            console.log(err);
        }
        else{
            res.redirect('/');
        }
    });
    
});

app.get('/submit', (req,res)=>{

     if(req.isAuthenticated()){
        res.render('submit.ejs')
    }else{
        res.redirect('/login'); 
    }
})

app.post('/register',(req,res)=>{

User.register({username: req.body.username}, req.body.password, (err, user)=>{
    if(err){
        console.log(err);
        res.redirect('/register');
    }else{
        passport.authenticate('local')(req, res, ()=>{
            res.redirect('/secrets')
        })
    }
})    
   
});


app.post('/login', (req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate('local')(req, res, ()=>{
                res.redirect('/secrets')
            })
        }
    });
    
});


app.post('/submit', (req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                console.log(foundUser);
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect('/secrets');
                })
            }
        }
    })

})


app.listen(PORT, function() {
  console.log("Server started on port" + PORT);
});