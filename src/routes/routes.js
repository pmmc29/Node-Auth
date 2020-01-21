const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt-nodejs')
const passport = require('passport')
const pool = require('../database')
const multer = require('multer')
const path = require('path')
const upload = multer()

//-------------ROUTES-------------------
router.get('/', function (req, res, next) {
    if (req.isAuthenticated()) {
        res.redirect('/profile');
    } else {
        res.render('index', {
            title: "Home",
            userData: req.user,
            messages: {
                danger: req.flash('danger'),
                warning: req.flash('warning'),
                success: req.flash('success')
            }
        });
    }
});
//-------------UPLOAD PHOTOS------------------
//Set Storage Engine
const storage = multer.diskStorage({
    destination: path.join(__dirname, '../photos'),
    filename: function (req, file, cb) {
        const user = req.body
        // console.log(user.email)
        cb(null, user.email + '.jpg')
    }
})

const uploadPhoto = multer({
    storage: storage,
    limits: {
        fileSize: 1000000
    },
    fileFilter: function (req, file, cb) {
        checkFileType(file, cb)
    }
}).single('myPhoto')

function checkFileType(file, cb) {
    //extenciones permitidas
    const filetypes = /jpeg|jpg|png|gif/
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase())
    //check mime type
    const mimetype = filetypes.test(file.mimetype)

    if (mimetype && extname) {
        return cb(null, true)
    } else {
        cb('Error: Images Only!')
    }
}
//----------------------------------------------
router.get('/signup', function (req, res, next) {
    if (req.isAuthenticated()) {
        res.redirect('/profile');
    } else {
        res.render('signup', {
            title: "Sign Up",
            user: req.user,
            messages: {
                danger: req.flash('danger'),
                warning: req.flash('warning'),
                success: req.flash('success')
            }
        });
    }
});

router.post('/signup', async function (req, res) {

    try {
        console.log('1:', req.body, req.body.password)
        const client = await pool.connect()
        await client.query('BEGIN')
        await JSON.stringify(client.query('SELECT id FROM usuarios WHERE email=$1', [req.body.email], function (err, result) {
            console.log('2:', req.body.email, req.body.password)
            if (result.rows[0]) {
                console.log('warning', "This email address is already registered. <a href='/login'>Log in!</a>");
                res.redirect('/signup');
            } else {
                uploadPhoto(req, res, (err) => {
                    if (err) {
                        res.render('signup', {
                            msg: err
                        })
                    } else {
                        if (req.file == undefined) {
                            res.render('signup', {
                                msg: 'No File Selected!!!'
                            })
                        } else {
                            console.log('3:', req.body.email, req.body.password)
                            var pwd = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
                            client.query('INSERT INTO usuarios (email, pass) VALUES ($1, $2)', [req.body.email, pwd], function (err, result) {
                                if (err) {
                                    console.log('ERROR: ', err);
                                } else {

                                    client.query('COMMIT')
                                    console.log('AQUI ', result)
                                    res.render('signup', {
                                        msg: 'Usuario Creado!!!'
                                    })
                                    // res.redirect('/login');
                                    return;
                                }
                            });
                            // console.log('success', 'User created.')
                        }
                    }
                })
            }
        }));
        client.release();

    } catch (e) {
        throw (e)
    }
});

//----------------------------------------------
router.get('/login', function (req, res, next) {
    if (req.isAuthenticated()) {
        res.redirect('/profile');
    } else {
        res.render('login', {
            title: "Sign In",
            user: req.user,
            messages: {
                danger: req.flash('danger'),
                warning: req.flash('warning'),
                success: req.flash('success')
            }
        });
    }

});

router.post('/login', passport.authenticate('local', {
    failureRedirect: '/login'
}), function (req, res) {
    if (req.body.remember) {
        console.log('remember')
        req.session.cookie.expires = false; // Cookie expires at end of session
    } else {
        req.session.cookie.maxAge = 5000; // Cookie expires after 5 seconds
    }

    res.redirect('/');
});
//----------------------------------------------
router.get('/logout', function (req, res) {

    console.log(req.isAuthenticated());
    req.logout();
    console.log(req.isAuthenticated());
    req.flash('success', "Logged out. See you soon!");
    res.redirect('/');
});
//----------------------------------------------
router.get('/profile', async function (req, res, next) {
    if (req.isAuthenticated()) {
        res.render('profile', {
            title: "Profile",
            user: req.user,
            file: `photos/${req.user.email}.jpg`
        });
        console.log(req.user.id)
    } else {
        res.redirect('/login');
    }
});


//----------------API---------------------------
let json = {}

router.get('/api/getUsers', async (req, res, next) => {
    let all = await pool.query('Select * from usuarios')
    json = all.rows
    // console.log(json)
    res.json(all.rows)
})


module.exports = router, json