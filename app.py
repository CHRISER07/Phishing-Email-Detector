"""
Phishing Email Detector - Main Streamlit Application
A comprehensive email security analyzer that detects phishing attempts and malicious content.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import time
import concurrent.futures

from src.services import (
    fetch_emails,
    check_url_virustotal,
    check_ip_virustotal,
    send_security_alert,
    format_alert_body
)
from src.utils import save_history, load_history, generate_report_data, generate_word_report


def main():
    st.set_page_config(
        page_title="Email Security Analyzer",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Email Security Analyzer")

    # Sidebar navigation
    page = st.sidebar.selectbox(
        "Navigate",
        ["Analyze Emails", "Malicious History", "Detailed Reports", "Dashboard"]
    )

    if page == "Analyze Emails":
        analyze_emails_page()
    elif page == "Malicious History":
        malicious_history_page()
    elif page == "Detailed Reports":
        detailed_reports_page()
    elif page == "Dashboard":
        dashboard_page()


def analyze_emails_page():
    """Page for analyzing emails and detecting threats."""
    st.header("📧 Email Security Scanning")

    # Email input fields
    col1, col2 = st.columns(2)
    with col1:
        email_user = st.text_input("📩 Enter Your Email")
        provider = st.selectbox("🌐 Select Email Provider", ["Gmail", "Outlook", "Yahoo"])
    with col2:
        app_password = st.text_input("🔑 Enter App Password", type="password")
        num_emails = st.slider("📌 Number of Emails to Fetch", 1, 10, 5)

    st.info("💡 **Tip**: For Gmail, you need to generate an App Password. [Learn how](https://support.google.com/accounts/answer/185833)")

    if st.button("🔍 Fetch & Deep Scan Emails", type="primary"):
        if email_user and app_password and provider:
            with st.spinner("Fetching emails..."):
                emails = fetch_emails(email_user, app_password, provider, num_emails=num_emails)
                
                if isinstance(emails, list):
                    st.success(f"✅ Fetched {len(emails)} emails successfully!")
                    
                    # Scan URLs and IPs concurrently
                    with st.spinner("Scanning for threats with VirusTotal..."):
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            # Collect all URLs and IPs
                            all_urls = [url for email_data in emails for url in email_data['URLs']]
                            all_ips = [ip for email_data in emails for ip in email_data['IPs']]
                            
                            # Scan URLs
                            url_futures = {executor.submit(check_url_virustotal, url): url for url in all_urls}
                            url_scan_results = {}
                            for future in concurrent.futures.as_completed(url_futures):
                                url = url_futures[future]
                                url_scan_results[url] = future.result()
                            
                            # Scan IPs
                            ip_futures = {executor.submit(check_ip_virustotal, ip): ip for ip in all_ips}
                            ip_scan_results = {}
                            for future in concurrent.futures.as_completed(ip_futures):
                                ip = ip_futures[future]
                                ip_scan_results[ip] = future.result()

                    # Process results and save malicious emails
                    for email_data in emails:
                        malicious_urls = [
                            url for url in email_data['URLs']
                            if url_scan_results.get(url, {}).get('malicious', 0) > 0
                        ]
                        malicious_ips = [
                            ip for ip in email_data['IPs']
                            if ip_scan_results.get(ip, {}).get('malicious', 0) > 0
                        ]

                        if malicious_urls or malicious_ips:
                            # Save to history
                            history = load_history()
                            history.append({
                                "Subject": email_data["Subject"],
                                "From": email_data["From"],
                                "Body": email_data["Body"],
                                "URLs": malicious_urls,
                                "IPs": malicious_ips,
                                "URL Scan Results": {url: url_scan_results[url] for url in malicious_urls},
                                "IP Scan Results": {ip: ip_scan_results[ip] for ip in malicious_ips},
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                            })
                            save_history(history)

                    # Display results
                    st.subheader("📊 Scan Results")
                    results_df = pd.DataFrame([{
                        "DateTime": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "Subject": e["Subject"],
                        "From": e["From"],
                        "Total URLs": len(e["URLs"]),
                        "Malicious URLs": len([u for u in e["URLs"] if url_scan_results.get(u, {}).get('malicious', 0) > 0]),
                        "Total IPs": len(e["IPs"]),
                        "Malicious IPs": len([ip for ip in e["IPs"] if ip_scan_results.get(ip, {}).get('malicious', 0) > 0])
                    } for e in emails])

                    # Color code the dataframe
                    def highlight_malicious(row):
                        if row['Malicious URLs'] > 0 or row['Malicious IPs'] > 0:
                            return ['background-color: #ffcccc'] * len(row)
                        return [''] * len(row)

                    st.dataframe(
                        results_df.style.apply(highlight_malicious, axis=1),
                        use_container_width=True
                    )
                    
                    # Show alert options for malicious emails
                    malicious_count = sum(1 for _, row in results_df.iterrows() 
                                        if row['Malicious URLs'] > 0 or row['Malicious IPs'] > 0)
                    if malicious_count > 0:
                        st.warning(f"⚠️ {malicious_count} potentially malicious email(s) detected!")
                else:
                    st.error(f"❌ Error: {emails}")
        else:
            st.warning("⚠️ Please fill all required fields")


def malicious_history_page():
    """Page showing history of detected malicious emails."""
    st.header("📜 Malicious Links & IPs History")

    history = load_history()
    if not history:
        st.info("No malicious history found.")
        return

    # Create table data
    table_data = []
    for record in history:
        subject = record.get("Subject", "N/A")
        sender = record.get("From", "N/A")
        timestamp = record.get("timestamp", "N/A")
        malicious_urls = record.get("URLs", [])
        malicious_ips = record.get("IPs", [])

        # Add URLs
        for url in malicious_urls:
            table_data.append({
                "Type": "URL",
                "Value": url,
                "Subject": subject,
                "Sender": sender,
                "Timestamp": timestamp,
                "Status": "Malicious"
            })

        # Add IPs
        for ip in malicious_ips:
            table_data.append({
                "Type": "IP",
                "Value": ip,
                "Subject": subject,
                "Sender": sender,
                "Timestamp": timestamp,
                "Status": "Malicious"
            })

    if table_data:
        df = pd.DataFrame(table_data)
        df = df[["Timestamp", "Sender", "Subject", "Type", "Value", "Status"]]

        st.dataframe(df, use_container_width=True)

        # Download button
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Malicious History as CSV",
            data=csv,
            file_name="malicious_history.csv",
            mime="text/csv"
        )
    else:
        st.info("No malicious URLs or IPs detected in history.")


def detailed_reports_page():
    """Page showing detailed analysis reports."""
    st.header("📋 Detailed Email Analysis Reports")

    history = load_history()
    if not history:
        st.info("No detailed reports available.")
        return

    selected_report = st.selectbox(
        "Select a Report",
        [f"Report {i + 1}: {h.get('Subject', 'N/A')}" for i, h in enumerate(history)]
    )

    report_index = int(selected_report.split(":")[0].split()[-1]) - 1
    selected_history = history[report_index]

    # Display email info
    st.subheader("📧 Email Information")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**From:** {selected_history.get('From', 'N/A')}")
        st.write(f"**Subject:** {selected_history.get('Subject', 'N/A')}")
    with col2:
        st.write(f"**Timestamp:** {selected_history.get('timestamp', 'N/A')}")

    # URLs analysis
    st.subheader("🔗 Links Detailed Analysis")
    for url, result in selected_history.get('URL Scan Results', {}).items():
        with st.expander(f"URL: {url}"):
            if result.get('malicious', 0) > 0:
                st.error("🚨 Malicious URL Detected")
            else:
                st.success("✅ Safe URL")
            st.json(result)

    # IPs analysis
    st.subheader("🌐 IPs Detailed Analysis")
    for ip, result in selected_history.get('IP Scan Results', {}).items():
        with st.expander(f"IP: {ip}"):
            if result.get('malicious', 0) > 0:
                st.error("🚨 Malicious IP Detected")
            else:
                st.success("✅ Safe IP")
            st.json(result)


def dashboard_page():
    """Dashboard page with statistics and visualizations."""
    st.header("📊 Security Dashboard")

    history = load_history()
    if not history:
        st.info("No data available for the dashboard.")
        return

    # Convert to DataFrame
    df = pd.DataFrame(history)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # Key Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🚨 Total Threats Detected", len(df))
    with col2:
        st.metric("🔗 Unique Malicious URLs", df['URLs'].explode().nunique())
    with col3:
        st.metric("🌐 Unique Malicious IPs", df['IPs'].explode().nunique())

    # Timeline
    st.subheader("📈 Detection Timeline")
    time_df = df.set_index('timestamp').resample('D').size().reset_index(name='count')
    fig = px.line(
        time_df, x='timestamp', y='count',
        title="Malicious Activity Over Time",
        labels={'timestamp': 'Date', 'count': 'Detections'}
    )
    st.plotly_chart(fig, use_container_width=True)

    # Threat Breakdown
    st.subheader("🎯 Threat Composition")
    try:
        url_counts = df['URLs'].explode().value_counts().reset_index()
        url_counts.columns = ['Threat', 'Count']
        url_counts['Type'] = 'URL'

        ip_counts = df['IPs'].explode().value_counts().reset_index()
        ip_counts.columns = ['Threat', 'Count']
        ip_counts['Type'] = 'IP'

        threat_types = pd.concat([url_counts, ip_counts])

        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(
                threat_types.head(10), names='Threat', values='Count',
                title="Top Malicious Threats"
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = px.bar(
                threat_types.head(10), x='Threat', y='Count',
                title="Most Frequent Threats"
            )
            st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        st.error(f"Error generating threat breakdown: {e}")

    # Report Generation
    st.subheader("📄 Generate Report")
    if st.button("📥 Download Comprehensive Report"):
        report_data, status_counts, df_report = generate_report_data(history)

        # Display charts
        col1, col2 = st.columns(2)
        with col1:
            fig = px.bar(
                status_counts, x="Status", y="Count", color="Status",
                title="URL/IP Status Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = px.pie(
                status_counts, names="Status", values="Count",
                title="Proportion of URL/IP Statuses"
            )
            st.plotly_chart(fig, use_container_width=True)

        # Generate downloads
        csv = df_report.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV Report",
            data=csv,
            file_name="email_security_report.csv",
            mime="text/csv"
        )

        word_report = generate_word_report(df_report, status_counts)
        st.download_button(
            label="📥 Download Word Report",
            data=word_report,
            file_name="email_security_report.docx",
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

        st.success("✅ Reports generated successfully!")


if __name__ == "__main__":
    main()
