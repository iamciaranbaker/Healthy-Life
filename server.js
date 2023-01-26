const express = require('express')
const app = express()
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const path = require('path')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const sessions = require('express-session')
const mongoSessions = require('connect-mongodb-session')(sessions)
const twoFactor = require("node-2fa")
const sanitize = require('mongo-sanitize')
var csrf = require('csurf')

// The port this app will run on
const port = 3000
// The amount of salt rounds bCrypt will perform on a password
const saltRounds = 10

// MongoDB credentials
const dbUrl = 'mongodb://localhost:27017/app'

const sessionStore = new mongoSessions({
    uri: dbUrl,
    collection: 'sessions'
})

sessionStore.on('error', function(error) {
    console.log(error);
})

// Use body-parser to parse the request body and extract the data from the form
app.use(bodyParser.urlencoded({ extended: true }))
// Use the ejs view engine which allows variables to be passed to the templates
app.set('view engine', 'ejs')
// Define the directory where templates are located
app.set('views', path.join(__dirname, 'views'))
// Define the directory where static files are located
app.use(express.static(path.join(__dirname, 'static')))
// Utilize sessions to allow logins to remain
app.use(sessions({
    secret: 'super_secret_token',
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
    },
    store: sessionStore,
    resave: true
}))
// Use cookie-parser to sace, read and access cookies
app.use(cookieParser())

// Use csrf protection to protect against cross-site request forgery attacks
var csrfProtection = csrf({cookie: true})

// Connect to the MongoDB database
mongoose.connect(dbUrl, {
    useNewUrlParser: true
})

// Create a MongoDB schema for the user
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    twoFactor: Boolean,
    twoFactorSecret: String
})

const stepCountSchema = new mongoose.Schema({
    email: String,
    date: Date,
    count: Number
})

// Create a MongoDB model for the user
const User = mongoose.model('User', userSchema)
const StepCount = mongoose.model('StepCount', stepCountSchema)

app.get('/', (req, res) => {
    res.render('index')
})

// Serve the login page at the /login path - GET
app.get('/login', csrfProtection, (req, res) => {
    if (req.session.email) {
        res.redirect('/dashboard')
    } else {
        res.render('login', {csrfToken: req.csrfToken()})
    }
})

// Handle the login form submission - POST
app.post('/login', csrfProtection, (req, res) => {
    var email = sanitize(req.body.email.toLowerCase())
    var password = sanitize(req.body.password)

    // Use the User model to find a user with the given email
    User.findOne({email: email}, (err, user) => {
        if (!user) {
            res.render('login', {csrfToken: req.csrfToken(), error: 'Your email address or password is incorrect!'})
        } else {
            if (!bcrypt.compareSync(password, user.password)) {
                return res.render('login', {csrfToken: req.csrfToken(), error: 'Your email address or password is incorrect!'})
            }

            if (user.twoFactor == true) {
                req.session.potentialEmail = user.email
                return res.redirect('/login/two-factor')
            }

            req.session.firstName = user.firstName
            req.session.lastName = user.lastName
            req.session.email = user.email
            res.redirect('/dashboard')
        }
    })
})

// Serve the two-factor page at the /login/two-factor path - GET
app.get('/login/two-factor', (req, res) => {
    if (req.session.email) {
        res.redirect('/dashboard')
    } else if (!req.session.potentialEmail) {
        res.redirect('/login')
    } else {
        res.render('two-factor')
    }
})

// Handle the two-factor form submission - POST
app.post('/login/two-factor', (req, res) => {
    var code = sanitize(req.body.code)

    User.findOne({email: req.session.potentialEmail}, (err, user) => {
        if (twoFactor.verifyToken(user.twoFactorSecret, code) == null) {
            return res.render('two-factor', {error: 'The code you entered is invalid!'})
        }

        req.session.firstName = user.firstName
        req.session.lastName = user.lastName
        req.session.email = user.email
        res.redirect('/dashboard')
    })
})

// Serve the register page at the /register path - GET
app.get('/register', (req, res) => {
    if (req.session.email) {
        res.redirect('/dashboard')
    } else {
        res.render('register')
    }
})

// Handle the register form submission - POST
app.post('/register', (req, res) => {
    var firstName = sanitize(req.body.firstName)
    var lastName = sanitize(req.body.lastName)
    var email = sanitize(req.body.email.toLowerCase())
    var password = sanitize(req.body.password)
    var confirmPassword = sanitize(req.body.confirmPassword)

    User.findOne({email: email}, (err, user) => {
        if (user) {
            res.render('register', {error: 'That email address is already taken!'})
        } else {
            if (password != confirmPassword) {
                res.render('register', {error: 'Your passwords do not match!'})
            } else {
                const hashedPassword = bcrypt.hashSync(password, saltRounds)

                const user = new User({
                    firstName: firstName,
                    lastName: lastName,
                    email: email,
                    password: hashedPassword,
                    twoFactor: false,
                    twoFactorSecret: ''
                })

                user.save((err) => {
                    req.session.firstName = user.firstName
                    req.session.lastName = user.lastName
                    req.session.email = user.email
                    res.redirect('/dashboard')
                })
            }
        }
    })
})

// Handle user logout at the /logout path - GET
app.get('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/')
})

// Handle the dashboard page at the /dashboard path - GET
app.get('/dashboard', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }
    
    var now = new Date()
    var startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate())
    
    StepCount.findOne({email: req.session.email, date: {$gte: startOfToday}}, (err, stepCount) => {
        if (stepCount) {
            res.render('dashboard', {session: req.session, hasDoneStepCount: true})
        } else {
            res.render('dashboard', {session: req.session, hasDoneStepCount: false})
        }
    })
})

// Handle the profile page at the /profile path - GET
app.get('/profile', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }

    User.findOne({email: req.session.email}, (err, user) => {
        res.render('profile', {session: req.session, hasTwoFactor: user.twoFactor})
    })
})

app.post('/api/addStepCount', (req, res) => {
    if (req.session.email) {
        var now = new Date()
        var startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate())
        var count = sanitize(req.body.stepCount)

        StepCount.findOne({date: {$gte: startOfToday}}, (err, stepCount) => {
            if (!stepCount) {
                const stepCount = new StepCount({
                    email: req.session.email,
                    date: new Date(),
                    count: count
                })
        
                stepCount.save((err) => {})
            }

            // Send empty JSON response
            res.json({})
        })
    } else {
        res.redirect('/')
    }
})

app.get('/api/getStepCounts', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }

    StepCount.find({email: req.session.email, date: {$gte: new Date(new Date() - 7 * 60 * 60 * 24 * 1000)}}, '-_id date count', {sort: '-date', limit: 7}, (err, stepCounts) => {
        res.json(stepCounts)
    })
})

app.get('/api/getNewTwoFactorSecret', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }

    User.findOne({email: req.session.email}, (err, user) => {
        if (user.twoFactor == true) {
            return res.redirect('/login')
        }

        var newTwoFactor = twoFactor.generateSecret({
            name: 'Healthy Life',
            account: req.session.email
        })

        user.twoFactorSecret = newTwoFactor.secret
        user.save((err) => {})

        res.json({
            'secret': newTwoFactor.secret,
            'qr': newTwoFactor.qr
        })
    })
})

app.post('/api/enableTwoFactor', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }

    var code = sanitize(req.body.code)

    User.findOne({email: req.session.email}, (err, user) => {
        if (twoFactor.verifyToken(user.twoFactorSecret, code) == null) {
            return res.json({'done': false})
        }

        user.twoFactor = true
        user.save((err) => {})
        
        res.json({'done': true})
    })
})

app.post('/api/disableTwoFactor', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/login')
    }

    var code = sanitize(req.body.code)

    User.findOne({email: req.session.email}, (err, user) => {
        if (twoFactor.verifyToken(user.twoFactorSecret, code) == null) {
            return res.json({'done': false})
        }

        user.twoFactor = false
        user.twoFactorSecret = ''
        user.save((err) => {})

        res.json({'done': true})
    })
})

// Run the app
app.listen(port, () => {
    console.log(`Listening on port ${port}`)
})