const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const bcrypt = require('bcrypt-nodejs')

const pool = require('../database')


// async function test() {
//     return await pool.query('insert into usuarios (email, pass) values ($1, $2)', ['test@test.com', bcrypt.hashSync('pedro123', bcrypt.genSaltSync(10))], function (err, result) {
//         if (err) {
//             console.log('el email existe')
//         } else {
//             console.log(result, 'exitoso')
//         }
//     })
// }
// test()


// console.log(bcrypt.hashSync('pedro123', bcrypt.genSaltSync(10)))

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

passport.use('local', new LocalStrategy({
    usernameField: 'email', //campos name
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {

    const client = await pool.connect()
    try {
        if (req.body.password == '' | req.body.email == '') {
            console.log('Ingrese datos validos! LOGIN')
        } else {
            await client.query('BEGIN')
            var currentAccountsData = await JSON.stringify(client.query('SELECT id,email,pass FROM usuarios WHERE email=$1', [username], function (err, result) {
                if (err) {
                    return done(err)
                }
                if (result.rows[0] == null) {
                    console.log('danger', "Oops. Incorrect login details.");
                    return done(null, false);
                } else {
                    bcrypt.compare(password, result.rows[0].pass, function (err, check) {
                        if (err) {
                            console.log('Error while checking password');
                            return done();
                        } else if (check) {
                            return done(null, { //DATOS DEL USUARIO QUE SE MANDA A LA VISTA
                                id: result.rows[0].id,
                                email: result.rows[0].email
                                // pass: result.rows[0].pass
                            });
                        } else {
                            console.log('danger', "Oops. Incorrect login details.");
                            return done(null, false);
                        }
                    });
                }
            }))
        }
    } catch (e) {
        console.log(e)
        throw (e);
    }
}))