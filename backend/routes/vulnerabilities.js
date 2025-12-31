const express = require('express');
const router = express.Router();
const vulnerabilityController = require('../controllers/vulnerabilityController');

router.get('/', vulnerabilityController.getAllVulnerabilities);
router.get('/:id', vulnerabilityController.getVulnerabilityById);
router.post('/', vulnerabilityController.createVulnerability);
router.put('/:id', vulnerabilityController.updateVulnerability);
router.delete('/:id', vulnerabilityController.deleteVulnerability);

module.exports = router;
