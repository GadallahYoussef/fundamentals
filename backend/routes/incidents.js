const express = require('express');
const router = express.Router();
const incidentController = require('../controllers/incidentController');

router.get('/', incidentController.getAllIncidents);
router.get('/stats', incidentController.getIncidentStats);
router.get('/:id', incidentController.getIncidentById);
router.post('/', incidentController.createIncident);
router.put('/:id', incidentController.updateIncident);
router.delete('/:id', incidentController.deleteIncident);
router.post('/:id/analyze', incidentController.analyzeIncident);
router.put('/:id/link-asset', incidentController.linkIncidentToAsset);
router.put('/:id/link-risk', incidentController.linkIncidentToRisk);

module.exports = router;
