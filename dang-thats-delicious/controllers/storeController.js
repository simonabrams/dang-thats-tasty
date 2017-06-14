const mongoose = require('mongoose');
const Store = mongoose.model('Store');
const multer = require('multer');
const jimp = require('jimp');
const uuid = require('uuid');

const multerOptions = {
	storage: multer.memoryStorage(),
	fileFilter(req, file, next) {
		const isPhoto = file.mimetype.startsWith('image/');
		if(isPhoto) {
			next(null, true);
		} else {
			next({message: 'That filetype isn\'t allowed'}, false);
		}
	}
};


exports.homePage = (req, res) => {
	res.render('index');
};

exports.addStore = (req, res) => {
	res.render('editStore', { title: 'Add Store' });
};

exports.upload = multer(multerOptions).single('photo');
exports.resize = async (req, res, next) => {
	// check if there is no new file to reqsize
	if(!req.file) {
		next(); // skips to the next middleware
		return;
	}
	const extension = req.file.mimetype.split('/')[1];
	req.body.photo = `${uuid.v4()}.${extension}`;
	// resize
	const photo = await jimp.read(req.file.buffer);
	await photo.resize(800, jimp.AUTO);
	await photo.write(`./public/uploads/${req.body.photo}`);
	// once we have written the photo to our filesystem, keep going!
	next();
};

exports.createStore = async (req, res) => {
	req.body.author = req.user._id;
	const store = await (new Store(req.body)).save();
	await store.save();
	req.flash('success', `Successfully created ${store.name}. Care to leave a review?`);
	res.redirect(`/store/${store.slug}`);
};

exports.getStores = async (req, res) => {
	// query the database for a list of all stores
	const stores = await Store.find();

	res.render('stores', { title: 'Stores', stores });
};

const confirmOwner = (store, user) => {
	if(!store.author.equals(user._id)) {
		throw Error('You must own a store in order to edit it!');
	}
};

exports.editStore = async(req, res) => {
	// 1. find the store given the id
	const store = await Store.findOne({ _id: req.params.id });

	//2. confirm that they are the owner of the store
	confirmOwner(store, req.user);
	//3. render out the edit form so the user can update the store
	res.render('editStore', {title: `Edit ${store.name}`, store})
};

exports.updateStore = async (req, res) => {
	// set location data to be a point
	req.body.location.type = 'Point';

	// find and update store
	const store = await Store.findOneAndUpdate({ _id: req.params.id }, req.body, {
		new: true, // return the new store instead of the old one
		runValidators: true,
	}).exec();
	req.flash('success', `Successfully updated <strong>${store.name}</strong>. <a href="/stores/${store.slug}">View Store</a>`);

	// redirect to store and tell them it worked
	res.redirect(`/stores/${store.id}/edit`);
};

exports.getStoreBySlug = async (req, res, next) => {
	const store = await Store.findOne({ slug: req.params.slug }).populate('author');
	if (!store) return next();
	res.render('store', { store, title: store.name });
};

exports.getStoresByTag = async (req, res) => {
	const tag = req.params.tag;
	const tagQuery = tag || { $exists: true }
	const tagsPromise = Store.getTagsList();
	const storesPromise = Store.find({ tags: tagQuery });

	const [tags, stores] = await Promise.all([tagsPromise, storesPromise]);

	res.render ('tags', { tags, title: 'Tags', tag, stores} );
};



/*
	API
*/


exports.searchStores = async (req, res) => {
	const stores = await Store
	// find stores that match
	.find({
		$text: {
			$search: req.query.q
		}
	}, {
		score: { $meta: 'textScore' }
	})
	// sort results
	.sort({
		score: { $meta: 'textScore' }
	})
	//  limit to 5 results
	.limit(5);

	res.json(stores);
}










