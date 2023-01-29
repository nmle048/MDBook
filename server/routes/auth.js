const express = require('express');
const authRoutes = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local');
const crypto = require('crypto');
const dbo = require('../db/conn');
//const db = require('../db');


/* Configure password authentication strategy.
 *
 * The `LocalStrategy` authenticates users by verifying a username and password.
 * The strategy parses the username and password from the request and calls the
 * `verify` function.
 *
 * The `verify` function queries the database for the user record and verifies
 * the password by hashing the password supplied by the user and comparing it to
 * the hashed password stored in the database.  If the comparison succeeds, the
 * user is authenticated; otherwise, not.
 */
passport.use(new LocalStrategy(function verify(username, password, cb) {
    let db_connect = dbo.getDb('bookshop');
    db_connect.collection('users').findOne({username: username}, function (err, result) {
        if (err) { return cb(err); };
        if (!result) { return cb(null, false, {message: 'Sai tên đăng nhập hoặc mật khẩu.'}); }

        crypto.pbkdf2(password, result.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
            if (err) { return cb(err); }
            if (!crypto.timingSafeEqual(result.hashed_password, hashedPassword)) {
                return cb(null, false, {message: 'Sai tên đăng nhập hoặc mật khẩu.'});
            }
            return cb(null, result);
        });
    });
    
//   db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
//     if (err) { return cb(err); }
//     if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
    
//     crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
//       if (err) { return cb(err); }
//       if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
//         return cb(null, false, { message: 'Incorrect username or password.' });
//       }
//       return cb(null, row);
//     });
//   });
}));

/* Configure session management.
 *
 * When a login session is established, information about the user will be
 * stored in the session.  This information is supplied by the `serializeUser`
 * function, which is yielding the user ID and username.
 *
 * As the user interacts with the app, subsequent requests will be authenticated
 * by verifying the session.  The same user information that was serialized at
 * session establishment will be restored when the session is authenticated by
 * the `deserializeUser` function.
 *
 * Since every request to the app needs the user ID and username, in order to
 * fetch todo records and render the user element in the navigation bar, that
 * information is stored in the session.
 */
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user._id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


/* GET /login
 *
 * This route prompts the user to log in.
 *
 * The 'login' view renders an HTML form, into which the user enters their
 * username and password.  When the user submits the form, a request will be
 * sent to the `POST /login/password` route.
 */
authRoutes.get('/login', function(req, res, next) {
  res.render('login');
});

/* POST /login/password
 *
 * This route authenticates the user by verifying a username and password.
 *
 * A username and password are submitted to this route via an HTML form, which
 * was rendered by the `GET /login` route.  The username and password is
 * authenticated using the `local` strategy.  The strategy will parse the
 * username and password from the request and call the `verify` function.
 *
 * Upon successful authentication, a login session will be established.  As the
 * user interacts with the app, by clicking links and submitting forms, the
 * subsequent requests will be authenticated by verifying the session.
 *
 * When authentication fails, the user will be re-prompted to login and shown
 * a message informing them of what went wrong.
 */
authRoutes.post('/login/password', passport.authenticate('local', {
  successReturnToOrRedirect: '/',
  failureRedirect: '/login',
  failureMessage: true
}));

/* POST /logout
 *
 * This route logs the user out.
 */
authRoutes.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.json('Loged out.')
    //res.redirect('/');
  });
});

/* GET /signup
 *
 * This route prompts the user to sign up.
 *
 * The 'signup' view renders an HTML form, into which the user enters their
 * desired username and password.  When the user submits the form, a request
 * will be sent to the `POST /signup` route.
 */
authRoutes.get('/signup', function(req, res, next) {
  res.render('signup');
});

/* POST /signup
 *
 * This route creates a new user account.
 *
 * A desired username and password are submitted to this route via an HTML form,
 * which was rendered by the `GET /signup` route.  The password is hashed and
 * then a new user record is inserted into the database.  If the record is
 * successfully created, the user is logged in.
 */
authRoutes.post('/signup', function(req, res, next) {
    let salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
    if (err) { return next(err); }
    let db_connect = dbo.getDb('bookshop');
    let user_object = {
        username: req.body.username,
        password: hashedPassword,
        salt: salt
    };
    db_connect.collection('users').insertOne(user_object, function (err, result) {
        if (err) { return next(err); }
        let user = {
            id: result._id,
            username: req.body.username
        };
        req.login(user, function(err) {
            if (err) { return next(err); }
            res.json('User created and loged in.')
            //res.redirect('/');
        });
    });
    // db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
    //   req.body.username,
    //   hashedPassword,
    //   salt
    // ], function(err) {
    //   if (err) { return next(err); }
    //   var user = {
    //     id: this.lastID,
    //     username: req.body.username
    //   };
    //   req.login(user, function(err) {
    //     if (err) { return next(err); }
    //     res.redirect('/');
    //   });
    // });
  });
});

module.exports = authRoutes;