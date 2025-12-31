const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');

router.get('/pdf', reportController.generatePDF);
router.get('/excel', reportController.generateExcel);
router.get('/json', reportController.generateJSON);

module.exports = router;
