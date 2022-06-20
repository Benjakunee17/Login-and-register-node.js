const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({extended:false}));

// SET OUR VIEWS AND VIEW ENGINE
app.set('views', path.join(__dirname,'views'));
app.set('view engine','ejs');

// APPLY COOKIE SESSION MIDDLEWARE
app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge:  3600 * 1000 // 1hr
}));

app.listen(8889, () => console.log("Server is Running..."));


//declaring custum middleware
const ifNotLoggedIn = (req,res,next) => {
    if (!req.session.isLoggedIn) {
        return res.render('login-register');
    }
    next();
}

const ifLoggedIn = (req,res,next) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/home');
    }
    next();
}

//root page
app.get('/',ifNotLoggedIn,(req,res,next)=>{
    dbConnection.execute("SELECT name FROM users WHERE id = ?",[req.session.userID])
    .then(([rows]) => {
        res.render('home', {
            name:rows[0].name
        })
    })
})

//register page
app.post('/register', ifLoggedIn, 

[
    body('user_email','Invalid email address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `users` WHERE `email`=?', [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('This E-mail already in use!');
            }
            return true;
        });
    }),
    body('user_name','Username is Empty!').trim().not().isEmpty(),
    body('user_pass','The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
],// end of post data validation

(req,res,next) => {
    
    const validation_result = validationResult(req);
    const{user_name,user_pass,user_email, user_tel} = req.body;

    if(validation_result.isEmpty()) {
        bcrypt.hash(user_pass,12).then((hash_pass)=>{
            dbConnection.execute("INSERT INTO users(name,email,password, tel)VALUES(?,?,?,?)",[user_name,user_email,hash_pass,user_tel])
            .then(result =>{
                res.send(`Your account has been created successfully,Now you can <a href="/">Login</a>`);
            }).catch(err =>{
                if(err) throw err;
            })
        
        })
        .catch(err => {
            if(err) throw err;
        })
    } 
    else {
        let allErrors = validation_result.errors.map((error) =>{
                return error.msg;
        })
        // REDERING login-register PAGE WITH VALIDATION ERRORS
        res.render('login-register',{
            register_error:allErrors,
            old_data:req.body
        });

    }
})

app.get("/info", async (req, res) => {
    console.log(66);
    try {
        const dddd = await dbConnection.execute('SELECT * FROM users');
        return res.status(500).json(dddd[0])
    } catch (error) {
        console.log(error);
        return res.status(500).send()
    }
})

//login page
app.post('/', ifLoggedIn, [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT email FROM users WHERE email=?', [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true;
                
            }
            return Promise.reject('Invalid Email Address!');
            
        });
    }),
    body('user_pass','Password is empty!').trim().not().isEmpty(),
],  (req,res) => {
    const validation_result = validationResult(req);
    const {user_pass , user_email } = req.body;
    if (validation_result.isEmpty ()) {
        dbConnection.execute("SELECT * FROM users WHERE email = ?" ,[user_email])
        .then(([rows]) => {
            bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                if (compare_result === true) {
                    req.session.isLoggedIn = true ;
                    req.session.userID = rows[0].id;
                    res.redirect('/');
                }else{
                    res.render('login-register', {
                        login_errors: ['Invalid Password']
                    })
                }
            }).catch(err => {
                if (err) throw err;
            }) 
        }).catch(err => {
            if (err) throw err;
        }) 
    }else {
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        })
        res.render('login-register', {
            login_errors: allErrors
        })
    }
})

//logout
app.get('/logout',(req,res) => {
    //session destroy
    req.session = null ;
    res.redirect('/') ;
})

app.use('/',(req,res) => {
    res.status(404).send('<h1>404 Page not found! </h1>')
})