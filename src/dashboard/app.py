"""
Streamlit Dashboard
===================
Interactive web dashboard for viewing and managing security incidents.

Features:
- View all incidents with filtering and sorting
- Detailed incident view with all information
- Trigger AI analysis for unanalyzed incidents
- Export reports in JSON and PDF formats
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
import sys
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.database import IncidentDatabase, Incident, get_database
from src.ai.analyzer import AIAnalyzer, MockAIAnalyzer, analyze_incident
from src.core.export import export_incidents_json, export_incidents_pdf, export_single_incident_pdf

# Page configuration
st.set_page_config(
    page_title="Incident Response Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .severity-critical { color: #FF0000; font-weight: bold; }
    .severity-high { color: #FF6600; font-weight: bold; }
    .severity-medium { color: #FFCC00; font-weight: bold; }
    .severity-low { color: #00CC00; font-weight: bold; }
    
    .status-new { background-color: #FFE0E0; padding: 2px 8px; border-radius: 4px; }
    .status-investigating { background-color: #FFF0E0; padding: 2px 8px; border-radius: 4px; }
    .status-resolved { background-color: #E0FFE0; padding: 2px 8px; border-radius: 4px; }
    .status-false_positive { background-color: #E0E0E0; padding: 2px 8px; border-radius: 4px; }
    
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    
    .incident-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
        background-color: #fafafa;
    }
    
    .log-snippet {
        background-color: #1e1e1e;
        color: #d4d4d4;
        padding: 10px;
        border-radius: 5px;
        font-family: monospace;
        font-size: 12px;
        overflow-x: auto;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)


def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        'critical': '#FF0000',
        'high': '#FF6600',
        'medium': '#FFCC00',
        'low': '#00CC00'
    }
    return colors.get(severity.lower(), '#808080')


def get_status_emoji(status: str) -> str:
    """Get emoji for status."""
    emojis = {
        'new': '🆕',
        'investigating': '🔍',
        'resolved': '✅',
        'false_positive': '❌'
    }
    return emojis.get(status.lower(), '❓')


def initialize_session_state():
    """Initialize session state variables."""
    if 'db' not in st.session_state:
        db_path = Path(__file__).parent.parent.parent / "data" / "incidents.db"
        st.session_state.db = get_database(db_path)
    
    if 'ai_analyzer' not in st.session_state:
        st.session_state.ai_analyzer = None
    
    if 'use_mock_ai' not in st.session_state:
        st.session_state.use_mock_ai = True
    
    if 'selected_incident_id' not in st.session_state:
        st.session_state.selected_incident_id = None


def render_sidebar():
    """Render the sidebar navigation and filters."""
    st.sidebar.title("🛡️ IR Dashboard")
    st.sidebar.markdown("---")
    
    # Navigation
    page = st.sidebar.radio(
        "Navigation",
        ["📊 Overview", "📋 All Incidents", "🔍 Incident Details", "⚙️ Settings"],
        index=0
    )
    
    st.sidebar.markdown("---")
    
    # Quick stats
    db = st.session_state.db
    stats = db.get_statistics()
    
    st.sidebar.subheader("📈 Quick Stats")
    st.sidebar.metric("Total Incidents", stats.get('total', 0))
    st.sidebar.metric("Pending Analysis", stats.get('pending_ai_analysis', 0))
    st.sidebar.metric("Last 24h", stats.get('last_24h', 0))
    
    return page


def render_overview():
    """Render the overview page with statistics and recent incidents."""
    st.title("📊 Incident Response Overview")
    st.markdown("---")
    
    db = st.session_state.db
    stats = db.get_statistics()
    
    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Incidents",
            stats.get('total', 0),
            delta=stats.get('last_24h', 0),
            delta_color="inverse"
        )
    
    with col2:
        critical_count = stats.get('by_severity', {}).get('critical', 0)
        high_count = stats.get('by_severity', {}).get('high', 0)
        st.metric(
            "Critical/High",
            f"{critical_count + high_count}",
            help="Critical and high severity incidents"
        )
    
    with col3:
        new_count = stats.get('by_status', {}).get('new', 0)
        st.metric(
            "New (Unreviewed)",
            new_count,
            delta_color="inverse"
        )
    
    with col4:
        st.metric(
            "Pending AI Analysis",
            stats.get('pending_ai_analysis', 0)
        )
    
    st.markdown("---")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 By Severity")
        severity_data = stats.get('by_severity', {})
        if severity_data:
            df_severity = pd.DataFrame(
                list(severity_data.items()),
                columns=['Severity', 'Count']
            )
            st.bar_chart(df_severity.set_index('Severity'))
        else:
            st.info("No incident data available")
    
    with col2:
        st.subheader("📊 By Status")
        status_data = stats.get('by_status', {})
        if status_data:
            df_status = pd.DataFrame(
                list(status_data.items()),
                columns=['Status', 'Count']
            )
            st.bar_chart(df_status.set_index('Status'))
        else:
            st.info("No incident data available")
    
    st.markdown("---")
    
    # Recent incidents
    st.subheader("🕐 Recent Incidents")
    
    recent_incidents = db.get_all_incidents()[:10]
    
    if recent_incidents:
        for incident in recent_incidents:
            severity_color = get_severity_color(incident.severity)
            status_emoji = get_status_emoji(incident.status)
            
            with st.expander(
                f"{status_emoji} [{incident.severity.upper()}] {incident.alert[:80]}...",
                expanded=False
            ):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.write(f"**ID:** {incident.id}")
                    st.write(f"**Type:** {incident.detection_type}")
                    st.write(f"**Time:** {incident.timestamp}")
                
                with col2:
                    st.write(f"**Severity:** {incident.severity}")
                    st.write(f"**Status:** {incident.status}")
                
                with col3:
                    if st.button("View Details", key=f"view_{incident.id}"):
                        st.session_state.selected_incident_id = incident.id
                        st.rerun()
    else:
        st.info("No incidents recorded yet. Run the detection pipeline to analyze logs.")


def render_all_incidents():
    """Render the all incidents page with filtering and sorting."""
    st.title("📋 All Incidents")
    st.markdown("---")
    
    db = st.session_state.db
    
    # Filters row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "critical", "high", "medium", "low"]
        )
    
    with col2:
        status_filter = st.selectbox(
            "Status",
            ["All", "new", "investigating", "resolved", "false_positive"]
        )
    
    with col3:
        detection_types = ["All"] + list(set(
            i.detection_type for i in db.get_all_incidents() if i.detection_type
        ))
        type_filter = st.selectbox("Detection Type", detection_types)
    
    with col4:
        search_term = st.text_input("Search", placeholder="Search alerts, IPs...")
    
    # Get and filter incidents
    if search_term:
        incidents = db.search_incidents(search_term)
    elif severity_filter != "All":
        incidents = db.get_incidents_by_severity(severity_filter)
    elif status_filter != "All":
        incidents = db.get_incidents_by_status(status_filter)
    elif type_filter != "All":
        incidents = db.get_incidents_by_detection_type(type_filter)
    else:
        incidents = db.get_all_incidents()
    
    # Apply additional filters
    if severity_filter != "All":
        incidents = [i for i in incidents if i.severity == severity_filter]
    if status_filter != "All":
        incidents = [i for i in incidents if i.status == status_filter]
    if type_filter != "All":
        incidents = [i for i in incidents if i.detection_type == type_filter]
    
    st.markdown(f"**Showing {len(incidents)} incidents**")
    st.markdown("---")
    
    # Display incidents as table
    if incidents:
        # Create DataFrame for display
        df_data = []
        for incident in incidents:
            df_data.append({
                'ID': incident.id,
                'Alert': incident.alert[:60] + '...' if len(incident.alert) > 60 else incident.alert,
                'Severity': incident.severity,
                'Status': incident.status,
                'Type': incident.detection_type,
                'Time': incident.timestamp.strftime('%Y-%m-%d %H:%M') if incident.timestamp else '',
                'AI Analyzed': '✅' if incident.ai_summary else '❌'
            })
        
        df = pd.DataFrame(df_data)
        
        # Display with selection
        selected_rows = st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                'ID': st.column_config.NumberColumn('ID', width='small'),
                'Severity': st.column_config.TextColumn('Severity', width='small'),
                'Status': st.column_config.TextColumn('Status', width='small'),
            }
        )
        
        # Incident selection
        st.markdown("---")
        col1, col2 = st.columns([1, 3])
        
        with col1:
            incident_id = st.number_input(
                "Enter Incident ID to view",
                min_value=1,
                step=1,
                value=incidents[0].id if incidents else 1
            )
        
        with col2:
            if st.button("View Selected Incident", type="primary"):
                st.session_state.selected_incident_id = incident_id
                st.rerun()
        
        # Export section
        st.markdown("---")
        st.subheader("📤 Export Incidents")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Export to JSON"):
                reports_dir = Path(__file__).parent.parent.parent / "reports"
                reports_dir.mkdir(exist_ok=True)
                
                filename = f"incidents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                filepath = reports_dir / filename
                
                export_incidents_json(incidents, filepath)
                st.success(f"Exported to {filepath}")
        
        with col2:
            if st.button("Export to PDF"):
                reports_dir = Path(__file__).parent.parent.parent / "reports"
                reports_dir.mkdir(exist_ok=True)
                
                filename = f"incidents_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                filepath = reports_dir / filename
                
                export_incidents_pdf(incidents, filepath)
                st.success(f"Exported to {filepath}")
    
    else:
        st.info("No incidents match the current filters.")


def render_incident_details():
    """Render the incident details page."""
    st.title("🔍 Incident Details")
    st.markdown("---")
    
    db = st.session_state.db
    
    # Incident ID input
    col1, col2 = st.columns([1, 3])
    
    with col1:
        incident_id = st.number_input(
            "Incident ID",
            min_value=1,
            step=1,
            value=st.session_state.selected_incident_id or 1
        )
    
    with col2:
        st.write("")  # Spacer
        if st.button("Load Incident"):
            st.session_state.selected_incident_id = incident_id
    
    # Load incident
    incident = db.get_incident(incident_id)
    
    if not incident:
        st.warning(f"No incident found with ID {incident_id}")
        return
    
    st.markdown("---")
    
    # Incident header
    severity_color = get_severity_color(incident.severity)
    status_emoji = get_status_emoji(incident.status)
    
    st.markdown(f"""
    ### {status_emoji} Incident #{incident.id}
    <span style="color: {severity_color}; font-size: 1.2em; font-weight: bold;">
        [{incident.severity.upper()}]
    </span>
    """, unsafe_allow_html=True)
    
    st.markdown(f"**{incident.alert}**")
    
    # Details columns
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Detection Type:**")
        st.write(incident.detection_type)
        
        st.markdown("**Timestamp:**")
        st.write(incident.timestamp)
    
    with col2:
        st.markdown("**Status:**")
        new_status = st.selectbox(
            "Update Status",
            ["new", "investigating", "resolved", "false_positive"],
            index=["new", "investigating", "resolved", "false_positive"].index(incident.status),
            key="status_select"
        )
        
        if new_status != incident.status:
            if st.button("Update Status"):
                db.update_status(incident.id, new_status)
                st.success("Status updated!")
                st.rerun()
    
    with col3:
        st.markdown("**Source IPs:**")
        st.write(incident.source_ips or "N/A")
        
        st.markdown("**Users:**")
        st.write(incident.users or "N/A")
    
    st.markdown("---")
    
    # IOCs
    st.subheader("🎯 Indicators of Compromise")
    if incident.ioc:
        st.code(incident.ioc, language="text")
    else:
        st.info("No IOCs recorded")
    
    # Log snippet
    st.subheader("📜 Log Snippet")
    if incident.log_snippet:
        st.markdown(f'<div class="log-snippet">{incident.log_snippet}</div>', unsafe_allow_html=True)
    else:
        st.info("No log snippet available")
    
    st.markdown("---")
    
    # AI Analysis Section
    st.subheader("🤖 AI Analysis")
    
    if incident.ai_summary:
        st.markdown(incident.ai_summary)
    else:
        st.warning("This incident has not been analyzed by AI yet.")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            use_mock = st.checkbox(
                "Use Mock AI (for testing)",
                value=st.session_state.use_mock_ai
            )
            st.session_state.use_mock_ai = use_mock
        
        with col2:
            if st.button("🔮 Run AI Analysis", type="primary"):
                with st.spinner("Analyzing incident..."):
                    try:
                        if use_mock:
                            analyzer = MockAIAnalyzer()
                        else:
                            if st.session_state.ai_analyzer is None:
                                st.session_state.ai_analyzer = AIAnalyzer(load_model=True)
                            analyzer = st.session_state.ai_analyzer
                        
                        result = analyzer.analyze_incident(
                            alert_description=incident.alert,
                            ioc_details=incident.ioc,
                            log_snippet=incident.log_snippet
                        )
                        
                        # Format and save the result
                        ai_summary = result.to_formatted_string()
                        db.update_ai_summary(incident.id, ai_summary)
                        
                        st.success("Analysis complete!")
                        st.rerun()
                        
                    except Exception as e:
                        st.error(f"Analysis failed: {str(e)}")
    
    st.markdown("---")
    
    # Export single incident
    st.subheader("📤 Export This Incident")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Export to JSON"):
            reports_dir = Path(__file__).parent.parent.parent / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            filename = f"incident_{incident.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = reports_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(incident.to_dict(), f, indent=2, default=str)
            
            st.success(f"Exported to {filepath}")
    
    with col2:
        if st.button("Export to PDF"):
            reports_dir = Path(__file__).parent.parent.parent / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            filename = f"incident_{incident.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = reports_dir / filename
            
            export_single_incident_pdf(incident, filepath)
            st.success(f"Exported to {filepath}")


def render_settings():
    """Render the settings page."""
    st.title("⚙️ Settings")
    st.markdown("---")
    
    # AI Settings
    st.subheader("🤖 AI Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**AI Model:**")
        st.code("fdtn-ai/Foundation-Sec-8B")
        
        use_mock = st.checkbox(
            "Use Mock AI for Testing",
            value=st.session_state.use_mock_ai,
            help="Enable this to test without loading the full AI model"
        )
        st.session_state.use_mock_ai = use_mock
    
    with col2:
        st.markdown("**Model Status:**")
        if st.session_state.ai_analyzer and st.session_state.ai_analyzer._model_loaded:
            st.success("Model loaded ✅")
        else:
            st.info("Model not loaded (will load on first analysis)")
        
        if st.button("Pre-load AI Model"):
            if not st.session_state.use_mock_ai:
                with st.spinner("Loading AI model... This may take several minutes."):
                    try:
                        st.session_state.ai_analyzer = AIAnalyzer(load_model=True)
                        st.success("Model loaded successfully!")
                    except Exception as e:
                        st.error(f"Failed to load model: {e}")
            else:
                st.warning("Mock AI is enabled. Disable it to load the real model.")
    
    st.markdown("---")
    
    # Database Settings
    st.subheader("💾 Database")
    
    db_path = Path(__file__).parent.parent.parent / "data" / "incidents.db"
    st.markdown(f"**Database Path:** `{db_path}`")
    
    db = st.session_state.db
    stats = db.get_statistics()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Total Incidents", stats.get('total', 0))
        st.metric("Pending AI Analysis", stats.get('pending_ai_analysis', 0))
    
    with col2:
        if st.button("Analyze All Pending", type="primary"):
            pending = db.get_incidents_without_ai_summary()
            
            if not pending:
                st.info("No incidents pending AI analysis")
            else:
                progress = st.progress(0)
                status_text = st.empty()
                
                analyzer = MockAIAnalyzer() if st.session_state.use_mock_ai else AIAnalyzer(load_model=True)
                
                for i, incident in enumerate(pending):
                    status_text.text(f"Analyzing incident {incident.id}...")
                    
                    result = analyzer.analyze_incident(
                        alert_description=incident.alert,
                        ioc_details=incident.ioc,
                        log_snippet=incident.log_snippet
                    )
                    
                    db.update_ai_summary(incident.id, result.to_formatted_string())
                    progress.progress((i + 1) / len(pending))
                
                st.success(f"Analyzed {len(pending)} incidents!")
    
    st.markdown("---")
    
    # About
    st.subheader("ℹ️ About")
    st.markdown("""
    **Incident Response Automation Tool v1.0**
    
    This tool provides:
    - 📜 Log parsing for Linux auth.log and Windows event logs
    - 🔍 Detection of brute force attacks, suspicious logins, and IOC matches
    - 🤖 AI-powered incident analysis using Foundation-Sec-8B
    - 📊 Interactive dashboard for incident management
    - 📤 Export capabilities for JSON and PDF reports
    
    For more information, see the README.md file.
    """)


def main():
    """Main application entry point."""
    initialize_session_state()
    
    # Render sidebar and get current page
    page = render_sidebar()
    
    # Render selected page
    if page == "📊 Overview":
        render_overview()
    elif page == "📋 All Incidents":
        render_all_incidents()
    elif page == "🔍 Incident Details":
        render_incident_details()
    elif page == "⚙️ Settings":
        render_settings()


if __name__ == "__main__":
    main()
