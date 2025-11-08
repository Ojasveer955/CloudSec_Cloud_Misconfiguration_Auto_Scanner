import streamlit as st
import json
import concurrent.futures
from datetime import datetime
import plotly.express as px
from streamlit_option_menu import option_menu
from st_aggrid import AgGrid, GridOptionsBuilder

# project modules
from scanner.inventory import list_storage_accounts
from scanner.checks_azure import check_storage_public_blob_access
from scanner.check_storage_encryption import check_storage_encryption
from scanner.check_vms import list_vms_with_public_ip
from scanner.check_nsg import check_open_nsg_rules
from scanner.check_function_apps import check_unrestricted_function_apps

# AWS modules
from scanner.utils_aws import aws_creds_ok
from scanner.inventory_aws import list_s3_buckets
from scanner.checks_aws_s3 import check_s3_public_access

from db import dao
from scanner.utils import (
    creds_ok,
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID,
)


# ------------- AWS SCAN (parallel) -------------
def list_s3_buckets_wrapper():
    """Wrapper to handle AWS not configured gracefully"""
    if not aws_creds_ok():
        return []  # Skip AWS if not configured
    try:
        return list_s3_buckets()
    except Exception as e:
        print(f"AWS S3 scan skipped: {e}")
        return []


def validate_azure_credentials():
    """Validate Azure credentials by attempting a lightweight API call.

    Returns:
        (bool, str): (is_valid, message)
    """
    if not creds_ok():
        return (
            False,
            "Azure credentials missing. Please set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, and AZURE_SUBSCRIPTION_ID in your .env or environment.",
        )
    try:
        # Import here to avoid failing when azure libs are not installed for other flows
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import SubscriptionClient

        cred = ClientSecretCredential(
            tenant_id=AZURE_TENANT_ID,
            client_id=AZURE_CLIENT_ID,
            client_secret=AZURE_CLIENT_SECRET,
        )
        sub_client = SubscriptionClient(cred)
        # Attempt a small call to validate credentials
        _ = next(sub_client.subscriptions.list())
        return True, "Azure credentials appear valid."
    except StopIteration:
        # Account has no subscriptions but auth succeeded
        return True, "Azure authentication successful (no subscriptions found)."
    except Exception as e:
        return False, f"Azure authentication failed: {e}"


def validate_aws_credentials():
    """Validate AWS credentials by calling STS GetCallerIdentity.

    Returns:
        (bool, str): (is_valid, message)
    """
    if not aws_creds_ok():
        return (
            False,
            "AWS credentials missing. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env or environment.",
        )
    try:
        # Use existing utility to get a client
        sts = None
        try:
            sts = __import__(
                "scanner.utils_aws", fromlist=["get_aws_client"]
            ).get_aws_client("sts")
        except Exception:
            # fallback to boto3 directly
            import boto3

            sts = boto3.client("sts")
        sts.get_caller_identity()
        return True, "AWS credentials appear valid."
    except Exception as e:
        return False, f"AWS authentication failed: {e}"


def run_all_checks(scan_azure: bool = True, scan_aws: bool = False):
    """Run selected scans in parallel.

    Args:
        scan_azure: whether to include Azure scans (storage, vms, nsgs, functionapps)
        scan_aws: whether to include AWS scans (s3)

    Returns:
        list of findings
    """
    findings = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}

        # Schedule Azure checks only if requested
        if scan_azure:
            futures[executor.submit(list_storage_accounts)] = "storage"
            futures[executor.submit(list_vms_with_public_ip)] = "vms"
            futures[executor.submit(check_open_nsg_rules)] = "nsgs"
            futures[executor.submit(check_unrestricted_function_apps)] = "functionapps"

        # Schedule AWS checks only if requested
        if scan_aws:
            futures[executor.submit(list_s3_buckets_wrapper)] = "aws_s3"

        # If nothing selected, return empty findings
        if not futures:
            return findings

        for future in concurrent.futures.as_completed(futures):
            service = futures[future]
            try:
                result = future.result()
                if service == "storage":
                    findings += check_storage_public_blob_access(result)
                    findings += check_storage_encryption(result)
                elif service == "aws_s3":
                    if result:  # Only check if buckets were returned
                        findings += check_s3_public_access(result)
                else:
                    findings += result
            except Exception as e:
                findings.append(
                    {
                        "rule_id": "ERROR",
                        "service": service,
                        "title": f"Error scanning {service}",
                        "severity": "Low",
                        "resource_id": "-",
                        "evidence": str(e),
                        "remediation": [],
                    }
                )
    return findings


# ------------- UI PAGES -----------------
def landing_page():
    st.title("☁️ Multi-Cloud Misconfiguration Auto Scanner")
    st.markdown(
        """
    ## 🔐 Welcome!
    A **next-gen CSPM-lite tool** to automatically detect misconfigurations in your Azure and AWS cloud environments.
    
    ### 🚀 Features:
    - Fast **parallel scans** across Azure and AWS resources
    - **Azure**: Storage Accounts, VMs, NSGs, Function Apps
    - **AWS**: S3 Buckets (public access detection)
    - Smart **SQLite persistence** (trend history)
    - Intuitive **Findings Explorer** with filters & search
    - Beautiful **charts** & KPIs for risk posture
    - 📂 **Database browser** for raw evidence
    - 📝 **Exportable Reports** (HTML/PDF, coming soon)
    - 🤖 **GenAI Assistant** (explain findings in plain English, coming soon)

    ---
    """
    )
    # Let user choose which cloud(s) to scan
    col_a, col_b = st.columns(2)
    with col_a:
        scan_azure = st.checkbox("Scan Azure", value=True)
    with col_b:
        scan_aws = st.checkbox("Scan AWS", value=False)

    if st.button("🔥 Run Quick Scan Now"):
        if not scan_azure and not scan_aws:
            st.warning("No cloud selected. Please select at least one cloud to scan.")
        else:
            # Validate credentials for selected clouds and show UI messages if missing/invalid
            invalid = False
            if scan_azure:
                ok, msg = validate_azure_credentials()
                if not ok:
                    st.error(f"Azure credential error: {msg}")
                    invalid = True
            if scan_aws:
                ok, msg = validate_aws_credentials()
                if not ok:
                    st.error(f"AWS credential error: {msg}")
                    invalid = True

            if invalid:
                st.info(
                    "Fix credentials or uncheck the cloud you don't want to scan, then try again."
                )
            else:
                run_id = dao.start_run()
                clouds = []
                if scan_azure:
                    clouds.append("Azure")
                if scan_aws:
                    clouds.append("AWS")
                spinner_msg = f"Running parallel scan for: {', '.join(clouds)}..."
                with st.spinner(spinner_msg):
                    findings = run_all_checks(scan_azure=scan_azure, scan_aws=scan_aws)
                    dao.save_findings(run_id, findings)
                    dao.finish_run(run_id)
                st.success(f"Scan finished with {len(findings)} findings.")
                st.json(findings)


def dashboard_page():
    import pandas as pd
    import plotly.express as px

    st.header("📊 Security Dashboard")
    findings = dao.get_all_findings()
    if not findings:
        st.warning("No findings yet. Run a scan first.")
        return

    # KPI metrics
    total = len(findings)
    highs = sum(1 for f in findings if f["severity"] == "High")
    meds = sum(1 for f in findings if f["severity"] == "Medium")
    lows = sum(1 for f in findings if f["severity"] == "Low")

    # Highlight storage encryption findings
    encryption_findings = [
        f for f in findings if f["rule_id"] == "AZ-Storage-Encryption-001"
    ]
    if encryption_findings:
        st.info(f"🔒 {len(encryption_findings)} Storage Accounts missing encryption!")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Findings", total)
    col2.metric("High", highs, delta=f"{int((highs/total)*100)}%")
    col3.metric("Medium", meds, delta=f"{int((meds/total)*100)}%")
    col4.metric("Low", lows, delta=f"{int((lows/total)*100)}%")

    # Pie chart
    fig = px.pie(
        names=["High", "Medium", "Low"],
        values=[highs, meds, lows],
        title="Findings by Severity",
        color=["High", "Medium", "Low"],
        color_discrete_map={"High": "red", "Medium": "orange", "Low": "green"},
    )
    st.plotly_chart(fig)

    # Trendline chart (new)
    st.subheader("📈 Findings Trend over Runs")
    trend = dao.get_findings_trend()
    if trend:
        df_trend = pd.DataFrame(trend)
        df_trend["started_at"] = pd.to_datetime(df_trend["started_at"])

        line = px.line(
            df_trend,
            x="started_at",
            y="findings",
            text="findings",
            markers=True,
            title="Findings per Run Over Time",
        )
        st.plotly_chart(line)
    else:
        st.info("No runs recorded yet.")


def findings_page():
    import pandas as pd

    st.header("📑 Findings Explorer")
    findings = dao.get_all_findings()
    if not findings:
        st.info("No findings yet. Run a scan first.")
        return

    # Convert to DataFrame
    df = pd.DataFrame(findings)

    # Apply color styles for severity (using Streamlit dataframe styling, not AgGrid)
    def color_severity(val):
        if val == "High":
            return "background-color: red; color: white"
        elif val == "Medium":
            return "background-color: orange; color: white"
        elif val == "Low":
            return "background-color: green; color: white"
        return ""

    st.write("### Filter Findings")
    severity = st.multiselect("Filter by Severity", ["High", "Medium", "Low"])
    service = st.multiselect("Filter by Service", list(df["service"].unique()))
    rule = st.multiselect("Filter by Rule ID", list(df["rule_id"].unique()))

    filtered = df
    if severity:
        filtered = filtered[filtered["severity"].isin(severity)]
    if service:
        filtered = filtered[filtered["service"].isin(service)]
    if rule:
        filtered = filtered[filtered["rule_id"].isin(rule)]

    st.write(f"Showing {len(filtered)} findings")

    # Show evidence details for encryption findings
    if not filtered.empty:
        st.write("### Evidence Preview for Encryption Findings")
        enc_findings = filtered[filtered["rule_id"] == "AZ-Storage-Encryption-001"]
        for _, row in enc_findings.iterrows():
            st.info(f"Resource: {row['resource_name']} | Evidence: {row['evidence']}")

    # Show a full-width table with wrapped evidence and remediation
    if not filtered.empty:
        import html

        def format_evidence(ev):
            if isinstance(ev, dict):
                return html.escape(json.dumps(ev, indent=2, ensure_ascii=False))
            return html.escape(str(ev))

        def format_remediation(rem):
            if isinstance(rem, list):
                return (
                    "<ul>"
                    + "".join(f"<li>{html.escape(str(r))}</li>" for r in rem)
                    + "</ul>"
                )
            return html.escape(str(rem))

        # Build HTML table
        table_html = (
            "<table style='width:100%;table-layout:fixed;word-break:break-word;'>"
        )
        table_html += (
            "<tr>"
            + "".join(
                f"<th>{col}</th>"
                for col in [
                    "Rule ID",
                    "Service",
                    "Title",
                    "Severity",
                    "Resource",
                    "Evidence",
                    "Remediation",
                ]
            )
            + "</tr>"
        )
        for _, row in filtered.iterrows():
            table_html += "<tr>"
            table_html += f"<td>{html.escape(str(row['rule_id']))}</td>"
            table_html += f"<td>{html.escape(str(row['service']))}</td>"
            table_html += f"<td>{html.escape(str(row['title']))}</td>"
            table_html += f"<td>{html.escape(str(row['severity']))}</td>"
            table_html += f"<td>{html.escape(str(row.get('resource_name', row.get('resource_id'))))}</td>"
            table_html += f"<td><pre style='white-space:pre-wrap;'>{format_evidence(row['evidence'])}</pre></td>"
            table_html += f"<td>{format_remediation(row['remediation'])}</td>"
            table_html += "</tr>"
        table_html += "</table>"
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.info("No findings to display.")


def database_page():
    st.header("🗄 Database Browser")
    findings = dao.get_all_findings()
    st.write("Raw DB contents:")
    st.json(findings)


from reports.generate_report import generate_report
import os


def reports_page():
    st.header("📝 Reports")

    # List available runs
    runs = dao.get_all_runs()  # we’ll add this helper
    run_ids = [r["id"] for r in runs]

    st.write("Select which run to generate a report for:")
    run_choice = st.selectbox("Run ID", ["All Runs"] + run_ids)

    if st.button("Generate Report PDF"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"azure_report_{timestamp}.pdf"

        if run_choice == "All Runs":
            pdf_path = generate_report(filename)
        else:
            pdf_path = generate_report(filename, run_id=run_choice)

        st.success(f"Report generated: {pdf_path}")
        with open(pdf_path, "rb") as f:
            st.download_button("⬇️ Download Report", f, file_name=filename)


# ------------- NAVIGATION ----------------
def main():
    with st.sidebar:
        selected = option_menu(
            "Navigation",
            [
                "Landing Page",
                "Dashboard",
                "Findings Explorer",
                "Database Browser",
                "Reports",
            ],
            icons=["house", "bar-chart", "search", "database", "file-earmark-text"],
            menu_icon="cast",
            default_index=0,
        )
    if selected == "Landing Page":
        landing_page()
    elif selected == "Dashboard":
        dashboard_page()
    elif selected == "Findings Explorer":
        findings_page()
    elif selected == "Database Browser":
        database_page()
    elif selected == "Reports":
        reports_page()


if __name__ == "__main__":
    main()
