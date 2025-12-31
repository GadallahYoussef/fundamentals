const express = require('express');
const router = express.Router();
const threatController = require('../controllers/threatController');

router.get('/', threatController.getAllThreats);
router.get('/:id', threatController.getThreatById);
router.post('/', threatController.createThreat);
router.put('/:id', threatController.updateThreat);
router.delete('/:id', threatController.deleteThreat);

module.exports = router;
