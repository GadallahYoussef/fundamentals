const express = require('express');
const router = express.Router();
const logParserController = require('../controllers/logParserController');

router.post('/upload', logParserController.uploadLog);
router.post('/detect', logParserController.detectThreatsFromLog);

module.exports = router;
