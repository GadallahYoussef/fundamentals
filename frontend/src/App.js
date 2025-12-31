import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/common/Navbar';
import Sidebar from './components/common/Sidebar';
import Footer from './components/common/Footer';
import Dashboard from './components/Dashboard/Dashboard';
import Assets from './components/RiskManagement/Assets';
import Threats from './components/RiskManagement/Threats';
import Vulnerabilities from './components/RiskManagement/Vulnerabilities';
import Risks from './components/RiskManagement/Risks';
import RiskMatrix from './components/RiskManagement/RiskMatrix';
import Treatments from './components/RiskManagement/Treatments';
import Incidents from './components/IncidentResponse/Incidents';
import LogUpload from './components/IncidentResponse/LogUpload';
import Reports from './components/Reports/Reports';
import './styles/App.css';

function App() {
    return (
        <Router>
            <div className="app">
                <Sidebar />
                <div className="app-content">
                    <Navbar />
                    <div className="main-content">
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/assets" element={<Assets />} />
                            <Route path="/threats" element={<Threats />} />
                            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                            <Route path="/risks" element={<Risks />} />
                            <Route path="/risk-matrix" element={<RiskMatrix />} />
                            <Route path="/treatments" element={<Treatments />} />
                            <Route path="/incidents" element={<Incidents />} />
                            <Route path="/log-upload" element={<LogUpload />} />
                            <Route path="/reports" element={<Reports />} />
                        </Routes>
                    </div>
                    <Footer />
                </div>
            </div>
        </Router>
    );
}

export default App;
