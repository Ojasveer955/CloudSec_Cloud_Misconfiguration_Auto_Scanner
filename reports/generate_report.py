from jinja2 import Environment, FileSystemLoader
import pdfkit
from db import dao
from datetime import datetime
import os


def generate_report(output_name="azure_report.pdf", run_id=None):
    # Ensure export folder exists
    export_dir = os.path.join("reports", "exports")
    os.makedirs(export_dir, exist_ok=True)

    # Get findings (all or specific run)
    if run_id:
        findings = dao.get_findings_by_run(run_id)
    else:
        findings = dao.get_all_findings()

    total = len(findings)
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    env = Environment(loader=FileSystemLoader("reports"))
    template = env.get_template("template.html")

    html_content = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        run_id=run_id if run_id else "All Runs",
        total=total,
        high=high,
        medium=medium,
        low=low,
        findings=findings,
    )

    # Save HTML for debugging
    html_path = os.path.join(export_dir, output_name.replace(".pdf", ".html"))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Save PDF
    pdf_path = os.path.join(export_dir, output_name)
    pdfkit.from_file(html_path, pdf_path)

    return pdf_path


if __name__ == "__main__":
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generate_report(f"azure_report_{timestamp}.pdf")
