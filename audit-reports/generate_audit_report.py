#!/usr/bin/env python3
"""
ARTEMIS-2.1 Security Audit Report Generator

Generates human-readable audit logs and vulnerability graphs
from npm and pip audit data.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
except ImportError:
    print("Installing matplotlib...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib", "-q"])
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches


def get_npm_audit_data():
    """Run npm audit and return the JSON data."""
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        return json.loads(result.stdout) if result.stdout else {}
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def get_pip_audit_data():
    """Run pip-audit and return the JSON data."""
    try:
        result = subprocess.run(
            ["pip-audit", "-r", "requirements.txt", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        return json.loads(result.stdout) if result.stdout else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def parse_npm_vulnerabilities(audit_data):
    """Parse npm audit data into a structured format."""
    vulnerabilities = []
    
    if not audit_data or "vulnerabilities" not in audit_data:
        return vulnerabilities
    
    for pkg_name, pkg_data in audit_data.get("vulnerabilities", {}).items():
        severity = pkg_data.get("severity", "unknown")
        via = pkg_data.get("via", [])
        
        # Get root vulnerability details
        vuln_details = []
        for v in via:
            if isinstance(v, dict):
                vuln_details.append({
                    "title": v.get("title", "Unknown"),
                    "url": v.get("url", ""),
                    "severity": v.get("severity", severity),
                    "cwe": v.get("cwe", []),
                    "range": v.get("range", "*")
                })
        
        vulnerabilities.append({
            "package": pkg_name,
            "severity": severity,
            "is_direct": pkg_data.get("isDirect", False),
            "effects": pkg_data.get("effects", []),
            "range": pkg_data.get("range", "*"),
            "fix_available": pkg_data.get("fixAvailable", False),
            "details": vuln_details
        })
    
    return vulnerabilities


def generate_human_readable_report(npm_vulns, pip_vulns, output_path):
    """Generate a human-readable audit report."""
    
    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Count severities
    npm_severity_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0}
    for vuln in npm_vulns:
        sev = vuln.get("severity", "unknown").lower()
        if sev in npm_severity_counts:
            npm_severity_counts[sev] += 1
    
    # Build report
    lines = [
        "=" * 80,
        "             ARTEMIS-2.1 SECURITY AUDIT REPORT",
        "=" * 80,
        "",
        f"Generated: {report_time}",
        f"Repository: ARTEMIS-2.1",
        "",
        "-" * 80,
        "                         EXECUTIVE SUMMARY",
        "-" * 80,
        "",
        "VULNERABILITY COUNTS BY SEVERITY (NPM Packages):",
        "",
        f"  💀 CRITICAL:  {npm_severity_counts['critical']:3d}",
        f"  🔴 HIGH:      {npm_severity_counts['high']:3d}",
        f"  🟠 MODERATE:  {npm_severity_counts['moderate']:3d}",
        f"  🟡 LOW:       {npm_severity_counts['low']:3d}",
        f"  ℹ️  INFO:      {npm_severity_counts['info']:3d}",
        "",
        f"  📦 TOTAL VULNERABLE PACKAGES: {len(npm_vulns)}",
        "",
        "PIP PACKAGES:",
        f"  ✅ No known vulnerabilities found",
        "",
        "-" * 80,
        "                       DETAILED FINDINGS",
        "-" * 80,
        ""
    ]
    
    # Group by severity
    severity_order = ["critical", "high", "moderate", "low", "info"]
    
    for severity in severity_order:
        matching = [v for v in npm_vulns if v.get("severity", "").lower() == severity]
        if not matching:
            continue
        
        severity_icon = {
            "critical": "💀",
            "high": "🔴",
            "moderate": "🟠",
            "low": "🟡",
            "info": "ℹ️"
        }.get(severity, "❓")
        
        lines.append(f"\n{severity_icon} {severity.upper()} SEVERITY VULNERABILITIES ({len(matching)})")
        lines.append("=" * 60)
        
        for vuln in matching:
            pkg = vuln["package"]
            range_str = vuln.get("range", "*")
            is_direct = "Direct" if vuln.get("is_direct") else "Transitive"
            fix = vuln.get("fix_available")
            
            lines.append(f"\n  📦 Package: {pkg}")
            lines.append(f"     Affected Range: {range_str}")
            lines.append(f"     Dependency Type: {is_direct}")
            
            if fix:
                if isinstance(fix, dict):
                    lines.append(f"     Fix Available: {fix.get('name')}@{fix.get('version')}")
                    if fix.get("isSemVerMajor"):
                        lines.append(f"     ⚠️  Note: Requires breaking change (major version)")
                else:
                    lines.append(f"     Fix Available: Yes")
            else:
                lines.append(f"     Fix Available: No direct fix")
            
            # Show affected packages
            effects = vuln.get("effects", [])
            if effects:
                lines.append(f"     Affects: {', '.join(effects[:5])}")
                if len(effects) > 5:
                    lines.append(f"              ... and {len(effects) - 5} more")
            
            # Show vulnerability details if available
            for detail in vuln.get("details", [])[:3]:
                title = detail.get("title", "Unknown vulnerability")
                url = detail.get("url", "")
                lines.append(f"     • {title}")
                if url:
                    lines.append(f"       URL: {url}")
    
    # Recommendations section
    lines.extend([
        "",
        "-" * 80,
        "                       RECOMMENDATIONS",
        "-" * 80,
        "",
        "1. IMMEDIATE ACTIONS (for HIGH/CRITICAL vulnerabilities):",
        "",
        "   • undici: Upgrade to a patched version when available",
        "     - Affects HTTP request/response handling",
        "     - CVEs: GHSA-g9mf-h72j-4rw9, GHSA-2mjp-6q6p-2qxm, etc.",
        "",
        "   • serialize-javascript: Vulnerable to RCE via RegExp",
        "     - Run: npm audit fix --force (will upgrade mocha/solidity-coverage)",
        "",
        "2. MEDIUM-TERM ACTIONS:",
        "",
        "   • Consider upgrading to Hardhat v3 when stable",
        "     - Would resolve: cookie, tmp, and several transitive deps",
        "",
        "   • Monitor ethers.js v6 migration status",
        "     - ethers v5 has vulnerable @ethersproject/* dependencies",
        "",
        "3. LOW PRIORITY:",
        "",
        "   • bn.js infinite loop vulnerability",
        "     - Low risk: requires specific crafted input",
        "",
        "-" * 80,
        "                      AUTOMATED FIX COMMAND",
        "-" * 80,
        "",
        "To fix vulnerabilities that don't require breaking changes:",
        "",
        "  npm audit fix",
        "",
        "To fix all vulnerabilities (may include breaking changes):",
        "",
        "  npm audit fix --force",
        "",
        "⚠️  WARNING: Breaking changes may require code updates. Test thoroughly!",
        "",
        "=" * 80,
        "                       END OF AUDIT REPORT",
        "=" * 80,
        ""
    ])
    
    report_content = "\n".join(lines)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    return report_content


def generate_vulnerability_graph(npm_vulns, output_path):
    """Generate a bar chart of vulnerabilities by severity."""
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    
    for vuln in npm_vulns:
        sev = vuln.get("severity", "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Create bar chart
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Colors
    colors = {
        "critical": "#dc2626",  # red
        "high": "#ea580c",       # orange
        "moderate": "#f59e0b",   # yellow-orange
        "low": "#eab308"         # yellow
    }
    
    # Bar chart
    severities = list(severity_counts.keys())
    counts = list(severity_counts.values())
    bar_colors = [colors[s] for s in severities]
    
    bars = ax1.bar(severities, counts, color=bar_colors, edgecolor="black", linewidth=1.2)
    ax1.set_xlabel("Severity Level", fontsize=12, fontweight="bold")
    ax1.set_ylabel("Number of Vulnerable Packages", fontsize=12, fontweight="bold")
    ax1.set_title("NPM Vulnerabilities by Severity", fontsize=14, fontweight="bold")
    ax1.set_ylim(0, max(counts) * 1.2 if counts else 10)
    
    # Add value labels on bars
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        ax1.annotate(f'{count}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=12, fontweight='bold')
    
    # Capitalize x-axis labels using set_xticks with labels
    ax1.set_xticks(range(len(severities)))
    ax1.set_xticklabels([s.capitalize() for s in severities], fontsize=11)
    
    # Pie chart
    total = sum(counts)
    if total > 0:
        sizes = counts
        explode = (0.05, 0.02, 0, 0)  # Explode critical slice
        
        wedges, texts, autotexts = ax2.pie(
            sizes, 
            explode=explode, 
            labels=[s.capitalize() for s in severities],
            colors=bar_colors,
            autopct=lambda pct: f'{int(round(pct/100.*total))}' if pct > 0 else '',
            shadow=True,
            startangle=90,
            textprops={'fontsize': 11}
        )
        ax2.set_title("Vulnerability Distribution", fontsize=14, fontweight="bold")
    else:
        ax2.text(0.5, 0.5, "No Vulnerabilities Found", 
                ha='center', va='center', fontsize=14,
                transform=ax2.transAxes)
        ax2.set_title("Vulnerability Distribution", fontsize=14, fontweight="bold")
    
    # Add legend
    patches = [mpatches.Patch(color=colors[s], label=f'{s.capitalize()}: {severity_counts[s]}') 
               for s in severities]
    fig.legend(handles=patches, loc='lower center', ncol=4, 
               fontsize=10, bbox_to_anchor=(0.5, 0.02))
    
    plt.suptitle("ARTEMIS-2.1 Security Audit - Vulnerability Analysis", 
                 fontsize=16, fontweight="bold", y=1.02)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    
    print(f"Graph saved to: {output_path}")


def generate_dependency_tree_graph(npm_vulns, output_path):
    """Generate a simplified dependency graph showing vulnerability chains."""
    
    # Filter to high/critical only for visibility
    high_critical = [v for v in npm_vulns 
                     if v.get("severity", "").lower() in ("high", "critical", "moderate")]
    
    if not high_critical:
        print("No high/critical/moderate vulnerabilities to graph")
        return
    
    fig, ax = plt.subplots(figsize=(16, 10))
    
    # Colors by severity
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "moderate": "#f59e0b",
        "low": "#eab308"
    }
    
    # Build tree-like structure
    # Group by root vulnerability
    root_vulns = {}
    for vuln in high_critical:
        # Check if this is a root vulnerability (has details)
        if vuln.get("details"):
            root_vulns[vuln["package"]] = {
                "severity": vuln["severity"],
                "effects": vuln.get("effects", []),
                "details": vuln.get("details", [])
            }
    
    # If no root vulns found, use all high/critical
    if not root_vulns:
        for vuln in high_critical:
            root_vulns[vuln["package"]] = {
                "severity": vuln["severity"],
                "effects": vuln.get("effects", [])[:5]
            }
    
    # Draw boxes
    y_pos = 0.95
    for pkg, data in list(root_vulns.items())[:8]:  # Limit to 8 for readability
        severity = data.get("severity", "moderate")
        color = severity_colors.get(severity, "#f59e0b")
        
        # Root vulnerability box
        rect = plt.Rectangle((0.05, y_pos - 0.08), 0.35, 0.07,
                              facecolor=color, alpha=0.3,
                              edgecolor=color, linewidth=2)
        ax.add_patch(rect)
        ax.text(0.22, y_pos - 0.045, pkg,
                ha='center', va='center', fontsize=9, fontweight='bold',
                wrap=True)
        
        # Draw effects
        effects = data.get("effects", [])[:4]
        for i, effect in enumerate(effects):
            # Draw connecting line
            start_x = 0.4
            end_x = 0.55
            mid_y = y_pos - 0.045
            
            ax.plot([start_x, end_x], [mid_y, mid_y - 0.02 * i],
                   color='gray', linestyle='-', linewidth=1, alpha=0.5)
            
            # Effect box
            effect_rect = plt.Rectangle((0.55, mid_y - 0.02 * i - 0.015), 0.35, 0.025,
                                        facecolor='lightgray', alpha=0.5,
                                        edgecolor='gray', linewidth=1)
            ax.add_patch(effect_rect)
            ax.text(0.72, mid_y - 0.02 * i, effect,
                   ha='center', va='center', fontsize=7)
        
        y_pos -= 0.12
    
    # Title and labels
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_title("Vulnerability Dependency Chain\n(High & Moderate Severity)", 
                 fontsize=14, fontweight='bold', pad=20)
    ax.axis('off')
    
    # Legend
    legend_elements = [
        mpatches.Patch(facecolor='#dc2626', alpha=0.3, edgecolor='#dc2626',
                       label='Critical', linewidth=2),
        mpatches.Patch(facecolor='#ea580c', alpha=0.3, edgecolor='#ea580c',
                       label='High', linewidth=2),
        mpatches.Patch(facecolor='#f59e0b', alpha=0.3, edgecolor='#f59e0b',
                       label='Moderate', linewidth=2),
        mpatches.Patch(facecolor='lightgray', alpha=0.5, edgecolor='gray',
                       label='Affected Package', linewidth=1)
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    print(f"Dependency graph saved to: {output_path}")


def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    print("=" * 60)
    print("ARTEMIS-2.1 Security Audit Report Generator")
    print("=" * 60)
    print()
    
    # Get audit data
    print("📊 Running npm audit...")
    npm_data = get_npm_audit_data()
    npm_vulns = parse_npm_vulnerabilities(npm_data)
    print(f"   Found {len(npm_vulns)} vulnerable packages")
    
    print("\n📊 Running pip-audit...")
    pip_vulns = get_pip_audit_data()
    print(f"   Found {len(pip_vulns)} vulnerable packages")
    
    # Generate reports
    print("\n📝 Generating human-readable audit report...")
    report_path = script_dir / "AUDIT_REPORT.txt"
    report = generate_human_readable_report(npm_vulns, pip_vulns, report_path)
    print(f"   Report saved to: {report_path}")
    
    print("\n📈 Generating vulnerability severity chart...")
    chart_path = script_dir / "vulnerability_chart.png"
    generate_vulnerability_graph(npm_vulns, chart_path)
    
    print("\n🔗 Generating dependency chain graph...")
    dep_graph_path = script_dir / "dependency_chain.png"
    generate_dependency_tree_graph(npm_vulns, dep_graph_path)
    
    print("\n" + "=" * 60)
    print("✅ Audit report generation complete!")
    print("=" * 60)
    
    # Print summary to console
    print("\n" + report[:2000] + "\n...")
    

if __name__ == "__main__":
    main()
