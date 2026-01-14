"""
AI Security Posture Scanner - Streamlit Dashboard
Interactive dashboard for visualizing AI security findings
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
from datetime import datetime
import sys

# Import the scanner (assumes ai_security_scanner.py is in same directory)
try:
    from ai_security_scanner import AISecurityScanner, Severity, AssetType
except ImportError:
    st.error("Please ensure ai_security_scanner.py is in the same directory")
    st.stop()


# Page configuration
st.set_page_config(
    page_title="AI Security Posture Scanner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .critical-badge {
        background-color: #ff4b4b;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .high-badge {
        background-color: #ffa500;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .medium-badge {
        background-color: #ffeb3b;
        color: black;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
    .low-badge {
        background-color: #4caf50;
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def initialize_session_state():
    """Initialize session state variables"""
    if 'scanner' not in st.session_state:
        st.session_state.scanner = AISecurityScanner()
    if 'findings' not in st.session_state:
        st.session_state.findings = []
    if 'scan_complete' not in st.session_state:
        st.session_state.scan_complete = False


def create_severity_chart(findings_df):
    """Create severity distribution chart"""
    if findings_df.empty:
        return None
    
    severity_counts = findings_df['severity'].value_counts()
    
    # Define colors for each severity
    colors = {
        'CRITICAL': '#ff4b4b',
        'HIGH': '#ffa500',
        'MEDIUM': '#ffeb3b',
        'LOW': '#4caf50',
        'INFO': '#2196f3'
    }
    
    fig = go.Figure(data=[
        go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            marker_color=[colors.get(s, '#999999') for s in severity_counts.index],
            text=severity_counts.values,
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Findings by Severity",
        xaxis_title="Severity Level",
        yaxis_title="Number of Findings",
        height=400,
        showlegend=False
    )
    
    return fig


def create_asset_type_chart(findings_df):
    """Create asset type distribution pie chart"""
    if findings_df.empty:
        return None
    
    asset_counts = findings_df['asset_type'].value_counts()
    
    fig = px.pie(
        values=asset_counts.values,
        names=asset_counts.index,
        title="Findings by Asset Type",
        hole=0.4
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    
    return fig


def create_risk_score_histogram(findings_df):
    """Create risk score distribution histogram"""
    if findings_df.empty:
        return None
    
    fig = px.histogram(
        findings_df,
        x='risk_score',
        nbins=20,
        title="Risk Score Distribution",
        labels={'risk_score': 'Risk Score', 'count': 'Number of Findings'},
        color_discrete_sequence=['#1f77b4']
    )
    
    fig.update_layout(height=400, showlegend=False)
    
    return fig


def create_timeline_chart(findings_df):
    """Create findings timeline (if timestamp available)"""
    if findings_df.empty or 'timestamp' not in findings_df.columns:
        return None
    
    findings_df['timestamp'] = pd.to_datetime(findings_df['timestamp'])
    findings_df['hour'] = findings_df['timestamp'].dt.hour
    
    hourly_counts = findings_df.groupby('hour').size().reset_index(name='count')
    
    fig = px.line(
        hourly_counts,
        x='hour',
        y='count',
        title="Findings Discovery Timeline",
        labels={'hour': 'Hour', 'count': 'Findings Discovered'}
    )
    
    fig.update_layout(height=300)
    
    return fig


def display_finding_details(finding):
    """Display detailed information about a specific finding"""
    severity_colors = {
        'CRITICAL': 'critical-badge',
        'HIGH': 'high-badge',
        'MEDIUM': 'medium-badge',
        'LOW': 'low-badge',
        'INFO': 'low-badge'
    }
    
    with st.expander(f"🔍 {finding['title']} - {finding['file_path']}", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"**Severity:** <span class='{severity_colors.get(finding['severity'], 'low-badge')}'>{finding['severity']}</span>", unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"**Risk Score:** {finding['risk_score']}/100")
        
        with col3:
            st.markdown(f"**Asset Type:** {finding['asset_type']}")
        
        st.markdown("---")
        
        st.markdown(f"**Description:** {finding['description']}")
        st.markdown(f"**File:** `{finding['file_path']}`")
        st.markdown(f"**Line:** {finding['line_number']}")
        st.code(finding['matched_content'], language='text')
        
        st.markdown("**🛡️ Recommendation:**")
        st.info(finding['recommendation'])
        
        st.markdown(f"**Finding ID:** `{finding['id']}`")
        st.markdown(f"**Detected:** {finding['timestamp']}")


def main():
    """Main dashboard application"""
    initialize_session_state()
    
    # Header
    st.title("🔐 AI Security Posture Scanner")
    st.markdown("**Discover and assess AI/LLM assets and security misconfigurations**")
    st.markdown("---")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Scan Configuration")
        
        # Directory selection
        scan_path = st.text_input(
            "Directory to Scan",
            value=".",
            help="Enter the path to scan (. for current directory)"
        )
        
        # Advanced options
        with st.expander("Advanced Options"):
            max_files = st.number_input(
                "Max Files to Scan",
                min_value=10,
                max_value=10000,
                value=1000,
                step=100,
                help="Limit the number of files to scan"
            )
            
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            )
            
            asset_filter = st.multiselect(
                "Filter by Asset Type",
                options=['API_KEY', 'ENDPOINT', 'MODEL_REFERENCE', 'CONFIG_FILE', 
                        'PROMPT_TEMPLATE', 'EMBEDDING_STORE'],
                default=['API_KEY', 'ENDPOINT', 'MODEL_REFERENCE', 'CONFIG_FILE', 
                        'PROMPT_TEMPLATE', 'EMBEDDING_STORE']
            )
        
        # Scan button
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            with st.spinner("Scanning... This may take a few moments"):
                try:
                    scanner = st.session_state.scanner
                    findings = scanner.scan_directory(scan_path, max_files=max_files)
                    st.session_state.findings = findings
                    st.session_state.scan_complete = True
                    st.success(f"✅ Scan complete! Found {len(findings)} issues")
                except Exception as e:
                    st.error(f"❌ Scan failed: {str(e)}")
        
        # Export options
        if st.session_state.scan_complete and st.session_state.findings:
            st.markdown("---")
            st.subheader("📥 Export Results")
            
            export_format = st.selectbox("Format", ["JSON", "CSV"])
            
            if st.button("Export", use_container_width=True):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"ai_security_scan_{timestamp}.{export_format.lower()}"
                
                try:
                    if export_format == "JSON":
                        st.session_state.scanner.export_findings(filename, format='json')
                    
                    st.success(f"✅ Exported to {filename}")
                except Exception as e:
                    st.error(f"Export failed: {str(e)}")
        
        # About section
        st.markdown("---")
        st.markdown("### About")
        st.markdown("""
        This tool scans for:
        - 🔑 Exposed API keys
        - 🌐 AI service endpoints
        - 🤖 Model references
        - ⚙️ Misconfigurations
        - 💉 Prompt injection risks
        """)
    
    # Main content area
    if not st.session_state.scan_complete:
        # Show welcome message
        st.info("👈 Configure scan settings in the sidebar and click 'Start Scan' to begin")
        
        # Show features
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### 🔍 Asset Discovery")
            st.markdown("""
            - OpenAI API keys
            - Anthropic credentials
            - Google AI keys
            - AWS Bedrock access
            - Azure OpenAI keys
            """)
        
        with col2:
            st.markdown("### 📊 Risk Assessment")
            st.markdown("""
            - Severity scoring
            - Risk calculation
            - Exposure analysis
            - Context awareness
            - Priority ranking
            """)
        
        with col3:
            st.markdown("### 🛡️ Recommendations")
            st.markdown("""
            - Security fixes
            - Best practices
            - Remediation steps
            - Compliance checks
            - Audit trails
            """)
    
    else:
        # Display scan results
        findings = st.session_state.findings
        
        # Convert to DataFrame for filtering
        if findings:
            findings_data = [
                {
                    'id': f.id,
                    'severity': f.severity.value,
                    'asset_type': f.asset_type.value,
                    'title': f.title,
                    'description': f.description,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'matched_content': f.matched_content,
                    'recommendation': f.recommendation,
                    'timestamp': f.timestamp,
                    'risk_score': f.risk_score
                }
                for f in findings
            ]
            findings_df = pd.DataFrame(findings_data)
            
            # Apply filters
            filtered_df = findings_df[
                (findings_df['severity'].isin(severity_filter)) &
                (findings_df['asset_type'].isin(asset_filter))
            ]
        else:
            filtered_df = pd.DataFrame()
        
        # Summary metrics
        st.header("📊 Scan Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Findings",
                len(filtered_df) if not filtered_df.empty else 0,
                delta=None
            )
        
        with col2:
            critical_count = len(filtered_df[filtered_df['severity'] == 'CRITICAL']) if not filtered_df.empty else 0
            st.metric(
                "Critical Issues",
                critical_count,
                delta=None,
                delta_color="inverse"
            )
        
        with col3:
            high_count = len(filtered_df[filtered_df['severity'] == 'HIGH']) if not filtered_df.empty else 0
            st.metric(
                "High Priority",
                high_count,
                delta=None,
                delta_color="inverse"
            )
        
        with col4:
            avg_risk = filtered_df['risk_score'].mean() if not filtered_df.empty else 0
            st.metric(
                "Avg Risk Score",
                f"{avg_risk:.1f}/100",
                delta=None
            )
        
        st.markdown("---")
        
        # Visualizations
        if not filtered_df.empty:
            st.header("📈 Visual Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                severity_chart = create_severity_chart(filtered_df)
                if severity_chart:
                    st.plotly_chart(severity_chart, use_container_width=True)
            
            with col2:
                asset_chart = create_asset_type_chart(filtered_df)
                if asset_chart:
                    st.plotly_chart(asset_chart, use_container_width=True)
            
            # Risk score distribution
            risk_histogram = create_risk_score_histogram(filtered_df)
            if risk_histogram:
                st.plotly_chart(risk_histogram, use_container_width=True)
            
            st.markdown("---")
            
            # Detailed findings
            st.header("🔍 Detailed Findings")
            
            # Sort options
            sort_col1, sort_col2 = st.columns([3, 1])
            with sort_col1:
                sort_by = st.selectbox(
                    "Sort by",
                    options=['risk_score', 'severity', 'asset_type', 'file_path'],
                    index=0
                )
            with sort_col2:
                sort_order = st.selectbox("Order", options=['Descending', 'Ascending'])
            
            # Sort DataFrame
            sorted_df = filtered_df.sort_values(
                by=sort_by,
                ascending=(sort_order == 'Ascending')
            )
            
            # Display findings
            for _, finding in sorted_df.iterrows():
                display_finding_details(finding.to_dict())
        
        else:
            st.success("🎉 No security issues found matching your filters!")
            st.balloons()


if __name__ == "__main__":
    main()
