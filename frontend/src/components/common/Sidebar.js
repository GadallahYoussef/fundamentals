import React from 'react';
import { Link, useLocation } from 'react-router-dom';

function Sidebar() {
    const location = useLocation();

    const menuItems = [
        { path: '/', label: '📊 Dashboard', exact: true },
        { path: '/assets', label: '💼 Assets' },
        { path: '/threats', label: '⚠️ Threats' },
        { path: '/vulnerabilities', label: '🔓 Vulnerabilities' },
        { path: '/risks', label: '🎯 Risks' },
        { path: '/risk-matrix', label: '📈 Risk Matrix' },
        { path: '/treatments', label: '🛠️ Treatments' },
        { path: '/incidents', label: '🚨 Incidents' },
        { path: '/log-upload', label: '📄 Log Upload' },
        { path: '/reports', label: '📑 Reports' },
    ];

    return (
        <div className="sidebar">
            <div className="sidebar-header">
                SecureOps
            </div>
            <ul className="sidebar-menu">
                {menuItems.map((item) => (
                    <li
                        key={item.path}
                        className={`sidebar-menu-item ${
                            item.exact
                                ? location.pathname === item.path
                                    ? 'active'
                                    : ''
                                : location.pathname.startsWith(item.path)
                                ? 'active'
                                : ''
                        }`}
                    >
                        <Link to={item.path}>{item.label}</Link>
                    </li>
                ))}
            </ul>
        </div>
    );
}

export default Sidebar;
