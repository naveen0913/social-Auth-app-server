import express from 'express';
import mongoose from 'mongoose';
import dotenv from "dotenv"
import cors from "cors"
import passport from 'passport';
import mysql from 'mysql'
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';
import { Strategy as TwitterStrategy } from 'passport-twitter';
import session from 'express-session';
import multer from 'multer'
import path from 'path';
import MongoStore from 'connect-mongo';
import bodyParser from 'body-parser';
import OAuth from 'oauth-1.0a';
import crypto from 'crypto'
import axios from 'axios'
const PORT=process.env.PORT | 5000

dotenv.config()
const app=express();

mongoose.connect(process.env.MONGODB_URL,{
  useNewUrlParser:true,
  useUnifiedTopology:true
})
.then(()=>app.listen(4000,()=>console.log("database connected")))
.catch((e)=>console.log(e));

const profileSchema= new mongoose.Schema({
  name:{
    type:String,
    
  },
  email:{
      type:String,
      
  },
  phone:{
      type:Number,
      minLength:10,
  },
  address:{
      type:String,
  },
  career:{
    type:String,
  },
  work:{
      type:String,
  },
  skills:[{
      type:String,
  }
  ],
  photo:{
      type:String,
  },
})

const Profile=mongoose.model('Profile',profileSchema)

const storage=multer.diskStorage({
  destination:function(req,file,cb){
    //cb(null, path.join(__dirname, 'uploads'));
    cb(null,'./uploads/')
  },
  filename:function(req,file,cb){
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    //cb(null, file.originalname);
  }
})

const sessionSecret=process.env.SESSION_SECRET
const upload1 = multer({ dest: 'uploads/' });
app.use(express.json());

app.use(cors({origin:"http://social-auth-app-client.vercel.app",credentials:true})); 
app.use(bodyParser.json())
app.use(session({ 
  secret:sessionSecret,
  resave:true,
  saveUninitialized:true,
  store:MongoStore.create({
    mongoUrl:process.env.MONGODB_URL,
    autoRemove:'native'
  })
}))

app.post('/add', upload1.single('photo'),(req,res)=>{
 
  const {name,email,phone,address,career,work,skills}=req.body;
  const photoURL = req.file.path; 

  console.log('Received user details:', req.body);
  console.log('Received file:', req.file);
  
  const newdata= new Profile({name,email,phone,address,career,work,skills,photo:photoURL})
  newdata.save()
  .then(()=>{
    res.status(201).json({ message: 'User details saved successfully' });
  })
  .catch((err)=>{
    console.error(err);
    res.status(500).json({ error: 'Failed to save user details' });
  })

})
const db=mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'signup'
})

//sql query 
app.post('/signup',(req,res)=>{
    const sql="INSERT INTO login(`username`,`firstname`,`lastname`,`email`,`password`,`phone`) Values(?)"
    const values=[
        req.body.username,
        req.body.firstname,
        req.body.lastname,
        req.body.email,
        req.body.password,
        req.body.phone
    ]
    db.query(sql,[values],(err,data)=>{
        if(err) return res.json(err);   
        return res.json(data);

    })
})
app.post('/login',(req,res)=>{
    const sql="SELECT * FROM login WHERE `email`= ? AND `password` = ? "
    
    db.query(sql,[req.body.email,req.body.password],(err,data)=>{
        if(err) return res.json(err); 

        if(data.length>0){
            return res.json("success");
        }else{
            return res.json("Failed")
        }

    })
})

//Passport strategy using linkedin 
const userSchemaLinkedin = new mongoose.Schema({
  accessToken:{
    type:String
  },
  refreshToken:{
    type:String
  },
  profile:{
    type:String
  }
});
const UserLinkedin = mongoose.model('UserLinkedin', userSchemaLinkedin);
//Middle wares
app.use(passport.initialize());
app.use(passport.session())

passport.serializeUser((user, done)=>{
    return done(null,user)
});

passport.deserializeUser((user,done)=>{
    return done(null,user)
})

passport.use(new LinkedInStrategy({
    clientID: process.env.CLIENT_ID,         
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "/auth/linkedin/callback",
    scope: ['r_emailaddress', 'r_liteprofile'],
  }, function(accessToken, refreshToken, profile, cb,req,res) {
    // asynchronous verification, for effect...
    const Userdata=new UserLinkedin({accessToken:accessToken,refreshToken:refreshToken,profile:profile.username})
    Userdata.save()
    .then((saveduser)=>{
      //res.status(200).json({ message: 'User details saved successfully' });
      console.log(saveduser);
    })
    .catch((err)=>{
      console.error(err);
      //res.status(400).json({ error: 'Failed to save user details' });
    })

    process.nextTick(function () {});
    //let user = { accessToken, profile };
    cb(null,profile)
      // To keep the example simple, the user's LinkedIn profile is returned to
      // represent the logged-in user. In a typical application, you would want
      // to associate the LinkedIn account with a user record in your database,
      // and return that user instead.
      //return done(null, profile);
    console.log(profile);
  }));

  //routes for linkedin authentication
  app.get('/auth/linkedin',
  passport.authenticate('linkedin', { state: ['profile'] }),
  );

  app.get('/auth/linkedin/callback', 
    passport.authenticate('linkedin', {failureRedirect: '/login'}),

    function(req,res){
      //successful authentication
      res.redirect(`http://social-auth-app-client.vercel.app/home`);
      
  });

//passport strategy using twitter application
const userSchema = new mongoose.Schema({
  token:{
    type:String
  },
  tokenSecret:{
    type:String
  },
  profile:{
    type:String
  }
});
const User = mongoose.model('User', userSchema);
passport.use(new TwitterStrategy({
    consumerKey: process.env.CONSUMER_KEY,                                
    consumerSecret: process.env.CONSUMER_SECRET,    
    callbackURL: "/auth/twitter/callback"
  },
  function (token,tokenSecret,profile, cb, req,res) {
    //called on successfull authentication
    //Inserting the profile into database
    const userdata=new User({token:token, tokenSecret:tokenSecret ,profile:profile.username})
    userdata.save()
    .then((saveduser)=>{
      //res.status(200).json({ message: 'User details saved successfully' });
      console.log(saveduser);
    })
    .catch((err)=>{
      console.error(err);
      //res.status(400).json({ error: 'Failed to save user details' });
    })

  cb(null,profile)
  console.log(profile);
  }
)); 

// Keys regarding API developer Account
const consumer_key=process.env.CONSUMER_KEY
const consumer_secret=process.env.CONSUMER_SECRET
const access_token=process.env.ACCESS_TOKEN
const access_token_secret=process.env.ACCESS_TOKEN_SECRET;
//routes with twitter authentication
app.get('/auth/twitter',
  passport.authenticate('twitter',{scope:['profile']}));

app.get('/auth/twitter/callback', 
  passport.authenticate('twitter', { failureRedirect: '/login'}),
  function(req, res) {
    //Successful authentication, redirect home page.
    res.redirect(`http://social-auth-app-client.vercel.app/home?token=${access_token}&tokensecret=${access_token_secret}`);
    
});
app.get("http://social-auth-app-server.vercel.app/user",(req,res)=>{
  res.send(req.user)
});

const upload = multer({ dest: 'uploads/' });

const oauth = OAuth({
  consumer: { key: consumer_key, secret: consumer_secret },
  signature_method: 'HMAC-SHA1',
  hash_function(base_string, key) {
    return crypto.createHmac('sha1', key).update(base_string).digest('base64');
  },
});

app.post('/update-profile-picture',upload.single('profilePicture'),async (req,res)=>{

  try{
    const image = req.file;
    if (!image) {
      return res.status(400).json({ error: 'No file provided' });
    }
    const token={
      key:access_token,
      secret:access_token_secret
    }

    const url='https://api.twitter.com/1.1/account/update_profile_image.json';

    const requestData = {
      url,
      method: 'POST',
      data: { image: image.buffer.toString('base64') },
    };

    const headers = oauth.toHeader(oauth.authorize(requestData, token));
    const response = await axios.post(url, requestData.data, { headers });
    if (response.status === 200) {
      return res.status(200).json({ message: 'Profile picture updated successfully' });
    } else {
      return res.status(response.status).json({ error: response.data.errors[0].message });
    }

  }catch(error){
    return res.status(500).json({ error: 'Internal Server Error' });
  }
})

app.listen(PORT,()=>{
    console.log("server connected");
})
