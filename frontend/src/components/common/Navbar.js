import React from 'react';

function Navbar() {
    return (
        <div className="navbar">
            <div className="navbar-brand">
                <span>🛡️</span>
                <span>SecureOps Platform</span>
            </div>
            <div className="navbar-actions">
                <div className="navbar-user">
                    <span>Security Admin</span>
                </div>
            </div>
        </div>
    );
}

export default Navbar;
