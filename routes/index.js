var express = require('express');
var router = express.Router();
const authorization = require("../middleware/authorization");

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

module.exports = routesr;
