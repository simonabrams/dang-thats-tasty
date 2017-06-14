const passport = require('passport');
const crypto = require('crypto'); // generates a secure token
const mongoose = require('mongoose');
const User = mongoose.model('User');
const promisify = require('es6-promisify');

const mail = require('../handlers/mail.js');

exports.login = passport.authenticate('local', {
	failureRedirect: '/login',
	failureFlash: 'Failed Login!',
	successRedirect: '/',
	successFlash: 'You logged in!'
});

exports.logout = (req, res) => {
	req.logout();
	req.flash('success', 'You are now logged out.');
	res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
	// check if authenticated
	if(req.isAuthenticated()) {
		next(); // go forth
		return;
	}

	req.flash('error', 'Ooops - you must be logged in to do that!');
	res.redirect('/login');
};

// password reset
exports.forgot = async (req, res) => {
	// 1. check if user exists - searches the database for a user with the given email address
	const user = await User.findOne( { email: req.body.email });
	// email address is not in the database
	if (!user) {
		req.flash('error', 'No account with that email address exists.');
		return res.redirect('/login'); // redirect to the login page
	}
	// 2. set reset tokens and expiry on their account
	user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
	user.resetPasswordExpires = Date.now() + 3600000;
	await user.save(); // adds the reset password token and expiration to the user in the database

	// 3. send an email with a token
	const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
	await mail.send({
		user,
		subject: 'Password Reset',
		resetURL,
		filename: 'password-reset' // the pug file that we render in the generateHTML function
	});
	req.flash('success', `You have been emailed a password reset link.`);
	
	// 4. redirect to login page
	res.redirect('/login');
};

exports.reset = async (req, res) => {
	// find the user with the given reset token
	const user = await User.findOne({
		resetPasswordToken: req.params.token,
		resetPasswordExpires: { $gt: Date.now() } // checks that the token isn't expired
	});
	// if that user token is expired or doesn't exist
	if (!user) {
		req.flash('error', 'Password reset is invalid or has expired');
		return res.redirect('/login'); // redirect to the login page
	}
	// if there is a user
	res.render('reset', { title: 'Reset your password' });
};

// checks to see if the passwords match
exports.confirmedPasswords = (req, res, next) => {
	if (req.body.password === req.body['password-confirm']){
		next(); // passwords match, keep going
		return;
	}
	req.flash('error', 'Passwords do not match');
	res.redirect('back');
};

// update user with new passwords
exports.update = async (req, res) => {

	const user = await User.findOne({
		resetPasswordToken: req.params.token,
		resetPasswordExpires: { $gt: Date.now() }
	});
	if (!user) {
		req.flash('error', 'Password reset is invalid or has expired');
		return res.redirect('/login');
	}
	// update the user's password
	const setPassword = promisify(user.setPassword, user);
	await setPassword(req.body.password);
	// clear out the reset token and expiry date
	user.resetPasswordToken = undefined;
	user.resetPasswordExpires = undefined;
	// save the user's info and actually update the database
	const updatedUser = await user.save();
	// log them in automatically
	await req.login(updatedUser);
	// flash success message, and return to the home page
	req.flash('success', '🕺 Nice! Your password has been reset!');
	res.redirect('/');

};









