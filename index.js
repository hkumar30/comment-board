/*
Author: Harsh Kumar
Date: November 20th, 2023
Description: A message board/forum application created using Express, SQLite and JavaScript.
*/

//Importing required libraries for the project.
import express from 'express';
import { engine } from 'express-handlebars';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';
import { v4 } from 'uuid';
import cookieParser from 'cookie-parser';

//Promise function for opening the database.
const dbPromise = open({
    filename: './data.db',
    driver: sqlite3.Database
})


//Initializing the constants for hashing and port.
const saltRounds = 10;
const port = 8080;


//Initializing app to use express.
const app = express();

//app.use functions which use the middleware initialized in this function.
app.use (express.urlencoded({ extended: false }));
app.use (cookieParser());

//Using the .set and engine functions from the express-handlebar to provide the folder locations to render the given views.
app.engine('handlebars', engine())
app.set("view engine", "handlebars")
app.set("views", "./views")

app.use (express.static('static'));

//Lookup function which checks if a person is logged in using its authentication token, if present in the database, pulls the messages from it and displays it to the webpage. Else, redirects to the same page.
app.use(async (req, res, next) => {
    console.log('cookies', req.cookies);
    if(!req.cookies.authToken){
        return next();
    }

    const db = await dbPromise;
    const authToken = await db.get('SELECT * FROM AuthTokens WHERE token = ?', req.cookies.authToken);

    //If authentication token does not exist, return next.
    if(!authToken){
        return next();
    }

    const user = await db.get('SELECT id FROM Users WHERE id = ?', authToken.userId);

    //If the user does not exist in the database, return next.
    if(!user){
        return next();
    }

    //Store the user's id as a request.
    req.user = user.id;

    next();
})

//Default GET function which checks the authentication of the user. If yes, allow the user to write messages. Else, redirect back to home.
app.get('/', async (req, res) => {
    try{
        const db = await dbPromise;

        //Pull the messages from the database.
        const messages = await db.all(
            `SELECT Messages.id, Messages.message, Users.username as author 
            FROM Messages LEFT JOIN Users WHERE Messages.authorId = Users.id;`);
        console.log('messages', messages);
        const user = req.user;
        
        //If the user creates another message, render the same.
        res.render('home', { messages, user });
    }

    catch(err){
        console.log(err)
        res.render("home", { error: "Something went wrong. Try again."});
    }
})

//Default GET function for the register page.
app.get('/register', (req, res) => {
    if(req.user) {
        res.redirect('/');
        return;
    }

    res.render('register')
})

//Default GET function for the login page.
app.get('/login', (req, res) => {
    if(req.user) {
        res.redirect('/');
        return;
    }

    res.render('login')
})

//Default GET function for the logout page.
app.get('/logout', async (req, res) => {
    if(!req.user || !req.cookies.authToken) {
        return res.redirect('/');
    }

    const db = await dbPromise;
    
    //Reset the auth tokens for the logged user.
    await db.run('DELETE FROM AuthTokens WHERE token = ?', req.cookies.authToken);

    //Expire the cookies. Auth tokens only lasts till you close the browser.
    res.cookie('authToken', '', {
        expires: new Date() //Expires now, browser checks that.

        // expires: new Date(Date.now() + 90000000) allows the authentication token to expire after a set time. 90000000ms here is 25 hours.
    }); 

    res.redirect('/');
})

app.post('/messages', async (req, res) => {
    const db = await dbPromise;
    
    //Add the message written by the user to the database.
    await db.run('INSERT INTO Messages (message, authorId) VALUES (?, ?);', req.body.message, req.user)
    res.redirect('/')
})

//POST Function for registration.
app.post('/register', async (req, res) => {
    //If fields are blank, prompt the user.
    if(
        !req.body.username || 
        !req.body.password || 
        req.body.username.length === 0 || 
        req.body.password.length === 0
        ) {
        return res.render('register', {error: "All Fields Required."});
    }

    const db = await dbPromise;

    //Hash the input ten times to encrypt the password.
    const passwordHash = await bcrypt.hash(req.body.password, saltRounds);

    //Insert the hashed password into the database.
    let result;
    try{
        result = await db.run(
            'INSERT INTO Users (username, passwordHash) VALUES (?, ?);', 
            req.body.username, 
            passwordHash
        );
    }

    //Throw an error should something go wrong.
    catch(e){
        console.log(e);
        return res.render('register', {
            error: 
                e.code === 'SQLITE_CONSTRAINT' 
                ? "Username taken" 
                : "Something went wrong"
        });
    }
    console.log('result', result)

    //Generate a token linked to the user and insert it to the database.
    const token = v4();
    await db.run(
        'INSERT INTO AuthTokens (token, userId) VALUES (?, ?);',
        token,
        result.lastID
    );

    //Set the expiry of the token to last till the end of the session.
    res.cookie('authToken', token, {
        expires: new Date(Date.now() + 70000000000)
    });

    res.redirect('/')
})

//POST Function for login.
app.post('/login', async (req, res) => {
    //If fields are blank, prompt the user.
    if(
        !req.body.username || 
        !req.body.password || 
        req.body.username.length === 0 || 
        req.body.password.length === 0
        ) {
        return res.render('login', {error: "Invalid Parameters"});
    }
     

    const db = await dbPromise;


    const user = await db.get('SELECT * FROM Users WHERE username = ?', req.body.username)

    //If the user is not found, throw an error.
    if(!user){
        return res.render('login', { error: "Username or password is incorrect." })
    }

    const passwordMatch = await bcrypt.compare(req.body.password, user.passwordHash);

    //If passwords do not match, throw an error.
    if(!passwordMatch){
        return res.render('login', { error: "Username or password is incorrect." })
    }

    //Generate a token linked to the user and insert it to the database.
    const token = v4();
    await db.run(
        'INSERT INTO AuthTokens (token, userId) VALUES (?, ?);',
        token,
        user.id
    );

    //Set the expiry of the token to last till the end of the session.
    res.cookie('authToken', token, {
        expires: new Date(Date.now() + 70000000000)
    });

    res.redirect('/')
})

//Migration function which maintains the database and initiaties the listener which confirms that the website is hosted.
async function setup(){
    const db = await dbPromise;

    //Create data.db using the initial schema written. force: true drops the tables and clean-slates the database.
    await db.migrate({ force: false })
    app.listen(port, () => {
        console.log(`Listening on port ${port}`)
    })
}

setup()