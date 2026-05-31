"""
Network Security ROI Analysis — Consulting Business Case
=========================================================
Author  : Harsha Narayan
Project : Consulting Resume — Project 2
Frame   : Problem Statement → Risk Quantification → Solution Options → ROI → Recommendation

Consulting Narrative
--------------------
A mid-size enterprise (500 employees, ₹200Cr revenue) faces Man-in-the-Middle
(MITM) attack exposure on its internal LAN.

Lab-validated finding: ARP spoofing attack completes in <90 seconds on an
unprotected network. Plaintext HTTP credentials intercepted via Wireshark
TCP stream inspection — zero detection by current controls.

This script delivers a Big 4-style structured recommendation:
    Issue → Data → Impact → Options → ROI → Recommendation → Implementation Plan
"""

import json
import os
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

warnings.filterwarnings("ignore")
os.makedirs("output", exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. CLIENT PROFILE
# ═══════════════════════════════════════════════════════════════════════════════
CLIENT = {
    "name"              : "EnterpriseX India (Simulated)",
    "employees"         : 500,
    "annual_revenue_cr" : 200,
    "lan_nodes"         : 120,
    "sensitive_systems" : ["POS Terminal", "HR Portal", "ERP", "Finance DB", "Customer DB"],
    "current_controls"  : "None — flat LAN, no VLAN segmentation, no IDS",
    "compliance_req"    : "PCI-DSS (pending), ISO 27001 (target)",
}

# ═══════════════════════════════════════════════════════════════════════════════
# 2. THREAT MODEL & RISK QUANTIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
"""
Data Sources:
- IBM Cost of a Data Breach Report 2023 (India figures)
- CERT-In Annual Report 2023
- IT (Amendment) Act 2008 penalty schedule
- RBI Cybersecurity Framework fine estimates
"""
RISK_MODEL = {
    # Probability
    "annual_breach_probability_pct"   : 34,     # IBM: 34% of orgs experience breach p.a.
    "mitm_as_pct_of_breaches"         : 22,     # MITM accounts for 22% of network breaches
    "effective_mitm_probability_pct"  : 34,     # Given no controls, full exposure assumed

    # Cost components (₹ Lakh)
    "direct_breach_cost_lakh"         : 450,    # IBM India avg: ~$550K ≈ ₹450L
    "credential_leak_impact_lakh"     : 80,     # POS/ERP credential exposure
    "regulatory_fine_lakh"            : 50,     # IT Act + RBI penalty estimate
    "reputational_loss_lakh"          : 120,    # Customer churn + brand damage
    "business_disruption_lakh"        : 35,     # Downtime, incident response

    # Time metrics
    "mean_detection_days"             : 204,    # IBM: avg 204 days to detect
    "mean_containment_days"           : 73,     # IBM: avg 73 days to contain
}

RISK_MODEL["total_breach_cost_lakh"] = (
    RISK_MODEL["direct_breach_cost_lakh"]
    + RISK_MODEL["credential_leak_impact_lakh"]
    + RISK_MODEL["regulatory_fine_lakh"]
    + RISK_MODEL["reputational_loss_lakh"]
    + RISK_MODEL["business_disruption_lakh"]
)
RISK_MODEL["expected_annual_loss_lakh"] = round(
    RISK_MODEL["total_breach_cost_lakh"]
    * RISK_MODEL["effective_mitm_probability_pct"] / 100, 1
)

# ═══════════════════════════════════════════════════════════════════════════════
# 3. ATTACK SURFACE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
ATTACK_VECTORS = {
    "ARP Spoofing (Primary)": {
        "technique"        : "Gratuitous ARP replies poison LAN ARP cache",
        "tool_used"        : "Custom Python script (lab-simulated)",
        "time_to_execute"  : "<90 seconds on unprotected flat LAN",
        "data_exposed"     : "HTTP credentials, session tokens, unencrypted traffic",
        "lab_validated"    : True,
        "severity"         : "CRITICAL",
        "cvss_score"       : 8.1,
    },
    "HTTP Credential Interception": {
        "technique"        : "Wireshark TCP stream inspection post ARP poisoning",
        "tool_used"        : "Wireshark 4.x",
        "time_to_execute"  : "Real-time during session",
        "data_exposed"     : "Plaintext username/password from legacy HTTP endpoints",
        "lab_validated"    : True,
        "severity"         : "CRITICAL",
        "cvss_score"       : 9.1,
    },
    "Lateral Movement": {
        "technique"        : "Use intercepted credentials to pivot to ERP/Finance DB",
        "tool_used"        : "N/A (manual credential reuse)",
        "time_to_execute"  : "Minutes to hours post-compromise",
        "data_exposed"     : "Financial records, payroll data, customer PII",
        "lab_validated"    : False,
        "severity"         : "HIGH",
        "cvss_score"       : 7.5,
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# 4. DEFENCE STRATEGY OPTIONS
# ═══════════════════════════════════════════════════════════════════════════════
STRATEGIES = {
    "Status Quo": {
        "description"             : "No controls — full exposure to all 3 attack vectors.",
        "capex_lakh"              : 0,
        "opex_per_year_lakh"      : 0,
        "risk_reduction_pct"      : 0,
        "implementation_weeks"    : 0,
        "complexity"              : "N/A",
        "pci_dss_compliance"      : False,
        "iso_27001_contribution"  : "None",
    },
    "Strategy A: Port Security + Static ARP": {
        "description"             : (
            "Enable Port Security on all managed switches (MAC binding per port). "
            "Deploy Static ARP entries for all critical hosts (POS, Finance DB, ERP). "
            "Eliminates primary ARP spoofing vector. Lab-validated: spoofed ARP "
            "replies blocked within 2 seconds of attack initiation."
        ),
        "capex_lakh"              : 8,
        "opex_per_year_lakh"      : 2,
        "risk_reduction_pct"      : 72,
        "implementation_weeks"    : 3,
        "complexity"              : "Low",
        "pci_dss_compliance"      : False,    # partial
        "iso_27001_contribution"  : "Moderate (A.13.1 Network Controls)",
    },
    "Strategy B: VLAN Segmentation + ACL + IDS": {
        "description"             : (
            "Implement VLAN-based micro-segmentation (Finance / Operations / Guest / DMZ). "
            "Deploy strict ACL rules blocking unauthorised cross-segment traffic. "
            "Install IDS (Snort/Suricata) for real-time anomaly detection and alerting. "
            "Achieves 91% attack surface reduction and satisfies PCI-DSS network controls."
        ),
        "capex_lakh"              : 28,
        "opex_per_year_lakh"      : 7,
        "risk_reduction_pct"      : 91,
        "implementation_weeks"    : 10,
        "complexity"              : "High",
        "pci_dss_compliance"      : True,
        "iso_27001_contribution"  : "Strong (A.13.1, A.12.4, A.16.1)",
    },
}

DISCOUNT_RATE = 0.10

def compute_roi(strategy: dict, years: int = 5) -> dict:
    p   = RISK_MODEL["effective_mitm_probability_pct"] / 100
    tc  = RISK_MODEL["total_breach_cost_lakh"]
    rr  = strategy["risk_reduction_pct"] / 100
    ann_saving = tc * p * rr
    ann_net    = ann_saving - strategy["opex_per_year_lakh"]
    capex      = strategy["capex_lakh"]
    cashflows  = [-capex] + [ann_net] * years
    npv        = sum(cf / (1 + DISCOUNT_RATE) ** t for t, cf in enumerate(cashflows))

    cum, payback = -capex, None
    for yr in range(1, years + 1):
        cum += ann_net
        if cum >= 0 and payback is None:
            prev = cum - ann_net
            payback = round(yr - 1 + (-prev) / (ann_net + 1e-9), 1)

    return {
        "annual_risk_saving_lakh" : round(ann_saving, 1),
        "annual_net_lakh"         : round(ann_net, 1),
        "5yr_npv_lakh"            : round(npv, 1),
        "payback_years"           : payback,
        "roi_pct"                 : round((npv / (capex + 1e-9)) * 100, 0),
    }

# ═══════════════════════════════════════════════════════════════════════════════
# 5. PRINT EXECUTIVE BUSINESS CASE
# ═══════════════════════════════════════════════════════════════════════════════
def print_business_case():
    print("\n" + "═"*68)
    print("  NETWORK SECURITY ROI — EXECUTIVE BUSINESS CASE")
    print(f"  Client : {CLIENT['name']}  |  Revenue: ₹{CLIENT['annual_revenue_cr']}Cr")
    print("═"*68)

    print("\n📌 PROBLEM STATEMENT")
    print(f"   {len(CLIENT['sensitive_systems'])} critical systems exposed on flat, unsegmented LAN.")
    print(f"   Lab-validated: MITM attack via ARP spoofing completes in <90 seconds.")
    print(f"   Plaintext credentials intercepted — 0 detection by current controls.")
    print(f"   Mean time to detect (industry): {RISK_MODEL['mean_detection_days']} days.")

    print("\n⚠️  RISK QUANTIFICATION")
    rc = RISK_MODEL
    print(f"   Annual breach probability   : {rc['effective_mitm_probability_pct']}%")
    print(f"   Total cost of breach        : ₹{rc['total_breach_cost_lakh']}L")
    print(f"     ├─ Direct breach cost     : ₹{rc['direct_breach_cost_lakh']}L")
    print(f"     ├─ Credential leak impact : ₹{rc['credential_leak_impact_lakh']}L")
    print(f"     ├─ Regulatory fines       : ₹{rc['regulatory_fine_lakh']}L")
    print(f"     ├─ Reputational damage    : ₹{rc['reputational_loss_lakh']}L")
    print(f"     └─ Business disruption    : ₹{rc['business_disruption_lakh']}L")
    print(f"   Expected Annual Loss        : ₹{rc['expected_annual_loss_lakh']}L")

    print("\n🔍 ATTACK SURFACE ANALYSIS")
    for vec, d in ATTACK_VECTORS.items():
        validated = "✅ Lab-validated" if d["lab_validated"] else "⚠️  Theoretical"
        print(f"   [{d['severity']}] {vec} | CVSS: {d['cvss_score']} | {validated}")
        print(f"            Time to execute : {d['time_to_execute']}")
        print(f"            Data exposed    : {d['data_exposed']}")

    print("\n🏗  SOLUTION OPTIONS — FINANCIAL COMPARISON")
    print(f"  {'Strategy':<44} {'CapEx':>7} {'OpEx/yr':>8} {'Risk▼':>7} {'Payback':>9} {'5yr NPV':>10} {'ROI':>7}")
    print("  " + "-"*97)

    roi_data = {}
    for name, s in STRATEGIES.items():
        roi = compute_roi(s)
        roi_data[name] = roi
        pb = f"{roi['payback_years']}yr" if roi["payback_years"] else "Never"
        short = name if len(name) < 44 else name[:41] + "..."
        print(f"  {short:<44} ₹{s['capex_lakh']:>4}L  ₹{s['opex_per_year_lakh']:>4}L/yr"
              f"  {s['risk_reduction_pct']:>4}%  {pb:>9}  ₹{roi['5yr_npv_lakh']:>6}L  {roi['roi_pct']:>5}%")

    print("\n✅ RECOMMENDATION")
    ra = roi_data["Strategy A: Port Security + Static ARP"]
    rb = roi_data["Strategy B: VLAN Segmentation + ACL + IDS"]
    print(f"   Phase 1 (Immediate): Strategy A — ₹8L CapEx, payback {ra['payback_years']}yr, 5yr NPV ₹{ra['5yr_npv_lakh']}L")
    print(f"   Phase 2 (Year 2):   Strategy B — Full PCI-DSS compliance, 91% risk reduction")
    print(f"   Combined 5-yr NPV: ₹{round(ra['5yr_npv_lakh'] + rb['5yr_npv_lakh'], 0)}L")
    print("═"*68)
    return roi_data

# ═══════════════════════════════════════════════════════════════════════════════
# 6. VISUALISATIONS
# ═══════════════════════════════════════════════════════════════════════════════
def generate_charts(roi_data: dict):
    NAVY   = "#1B3A6B"
    COLORS = {"Status Quo": "#E74C3C",
               "Strategy A: Port Security + Static ARP": "#27AE60",
               "Strategy B: VLAN Segmentation + ACL + IDS": "#2E86C1"}
    BG = "#F7F9FC"

    fig = plt.figure(figsize=(18, 11), facecolor=BG)
    gs  = GridSpec(2, 3, figure=fig, hspace=0.50, wspace=0.38)

    names_short = ["Status Quo", "Strategy A", "Strategy B"]
    names_full  = list(STRATEGIES.keys())
    colors      = [COLORS[n] for n in names_full]

    # Chart 1: Residual Annual Risk
    ax1 = fig.add_subplot(gs[0, 0])
    base = RISK_MODEL["expected_annual_loss_lakh"]
    residual = [base * (1 - STRATEGIES[n]["risk_reduction_pct"] / 100) for n in names_full]
    bars = ax1.bar(names_short, residual, color=colors, edgecolor="white", linewidth=1.2)
    ax1.axhline(base, color="#E74C3C", linestyle="--", linewidth=1, alpha=0.6,
                label=f"Baseline ₹{base}L")
    ax1.set_title("Residual Annual Risk (₹L)", fontweight="bold", color=NAVY, fontsize=11)
    ax1.set_ylabel("₹ Lakh", color=NAVY, fontsize=9)
    ax1.legend(fontsize=8)
    for b, v in zip(bars, residual):
        ax1.text(b.get_x() + b.get_width()/2, b.get_height() + 1,
                 f"₹{v:.0f}L", ha="center", fontsize=9, fontweight="bold")
    ax1.set_facecolor(BG)

    # Chart 2: 5-Year NPV
    ax2 = fig.add_subplot(gs[0, 1])
    npvs = [roi_data[n]["5yr_npv_lakh"] for n in names_full]
    bars2 = ax2.bar(names_short, npvs, color=colors, edgecolor="white", linewidth=1.2)
    ax2.axhline(0, color="black", linewidth=0.7)
    ax2.set_title("5-Year NPV (₹L, 10% discount)", fontweight="bold", color=NAVY, fontsize=11)
    ax2.set_ylabel("₹ Lakh", color=NAVY, fontsize=9)
    for b, v in zip(bars2, npvs):
        ax2.text(b.get_x() + b.get_width()/2, v + (2 if v >= 0 else -8),
                 f"₹{v}L", ha="center", fontsize=9, fontweight="bold",
                 color="green" if v >= 0 else "red")
    ax2.set_facecolor(BG)

    # Chart 3: Risk Reduction %
    ax3 = fig.add_subplot(gs[0, 2])
    rr = [STRATEGIES[n]["risk_reduction_pct"] for n in names_full]
    ax3.barh(names_short, rr, color=colors, edgecolor="white", linewidth=1.2)
    ax3.set_title("Attack Surface Reduction (%)", fontweight="bold", color=NAVY, fontsize=11)
    ax3.set_xlabel("% Reduction", color=NAVY, fontsize=9)
    ax3.set_xlim(0, 115)
    for i, v in enumerate(rr):
        ax3.text(v + 1, i, f"{v}%", va="center", fontsize=9, fontweight="bold")
    ax3.set_facecolor(BG)

    # Chart 4: Cumulative cashflow
    ax4 = fig.add_subplot(gs[1, :2])
    years = list(range(6))
    for name, s in STRATEGIES.items():
        roi   = roi_data[name]
        capex = s["capex_lakh"]
        anb   = roi["annual_net_lakh"]
        cum   = [-capex] + [round(-capex + anb * y, 1) for y in range(1, 6)]
        label = name.split(":")[0]
        ax4.plot(years, cum, marker="o", markersize=5, label=label,
                 color=COLORS[name], linewidth=2.2)
    ax4.axhline(0, color="black", linewidth=0.8, linestyle="--", alpha=0.5)
    ax4.set_title("Cumulative Net Benefit — 5 Years (₹L)", fontweight="bold", color=NAVY, fontsize=11)
    ax4.set_xlabel("Year", color=NAVY, fontsize=9)
    ax4.set_ylabel("₹ Lakh", color=NAVY, fontsize=9)
    ax4.legend(fontsize=9)
    ax4.set_xticks(years)
    ax4.set_facecolor(BG)

    # Chart 5: Breach Cost Breakdown
    ax5 = fig.add_subplot(gs[1, 2])
    components = ["Direct Breach", "Credential Leak", "Regulatory Fine",
                  "Reputation", "Disruption"]
    values = [RISK_MODEL["direct_breach_cost_lakh"],
              RISK_MODEL["credential_leak_impact_lakh"],
              RISK_MODEL["regulatory_fine_lakh"],
              RISK_MODEL["reputational_loss_lakh"],
              RISK_MODEL["business_disruption_lakh"]]
    wedge_colors = ["#E74C3C","#E67E22","#F1C40F","#9B59B6","#3498DB"]
    ax5.pie(values, labels=components, colors=wedge_colors, autopct="%1.0f%%",
            textprops={"fontsize": 8}, startangle=90)
    ax5.set_title("Breach Cost Breakdown\n(Total ₹735L)", fontweight="bold", color=NAVY, fontsize=11)

    fig.suptitle(
        f"Network Security Business Case — {CLIENT['name']} | ₹{CLIENT['annual_revenue_cr']}Cr Revenue",
        fontsize=14, fontweight="bold", color=NAVY, y=1.01
    )
    plt.savefig("output/security_roi_analysis.png", dpi=150, bbox_inches="tight", facecolor=BG)
    print("[Chart] Saved → output/security_roi_analysis.png")
    plt.close()

# ═══════════════════════════════════════════════════════════════════════════════
# 7. IMPLEMENTATION ROADMAP
# ═══════════════════════════════════════════════════════════════════════════════
def print_roadmap():
    print("\n📅 PHASED IMPLEMENTATION ROADMAP")
    roadmap = [
        ("Week 1–2",  "Phase 1A", "Audit all 120 LAN nodes; map switch ports to MAC addresses"),
        ("Week 2–3",  "Phase 1B", "Enable Port Security on all managed switches (MAC binding)"),
        ("Week 3",    "Phase 1C", "Deploy Static ARP entries for 5 critical systems"),
        ("Week 3",    "Phase 1D", "Validate: run controlled ARP spoof test — confirm blocked"),
        ("Month 2–4", "Phase 2A", "Design VLAN architecture: Finance / Ops / Guest / DMZ"),
        ("Month 4–6", "Phase 2B", "Configure ACL rules for inter-VLAN traffic"),
        ("Month 6–8", "Phase 2C", "Deploy IDS (Snort) — tune alert thresholds"),
        ("Month 8",   "Phase 2D", "PCI-DSS gap assessment — document compliance evidence"),
    ]
    for period, phase, task in roadmap:
        print(f"   {period:<12} [{phase}] {task}")

# ═══════════════════════════════════════════════════════════════════════════════
# 8. EXPORT
# ═══════════════════════════════════════════════════════════════════════════════
def export_data(roi_data: dict):
    rows = []
    for name, s in STRATEGIES.items():
        roi = roi_data[name]
        rows.append({"strategy": name, **s, **roi,
                     "expected_annual_loss_lakh": RISK_MODEL["expected_annual_loss_lakh"]})
    pd.DataFrame(rows).to_csv("output/roi_comparison.csv", index=False)

    attack_df = pd.DataFrame([
        {"vector": k, **{x: v[x] for x in ["severity","cvss_score","time_to_execute","lab_validated"]}}
        for k, v in ATTACK_VECTORS.items()
    ])
    attack_df.to_csv("output/attack_surface.csv", index=False)
    print("[Export] CSVs saved to output/")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    roi_data = print_business_case()
    print_roadmap()
    generate_charts(roi_data)
    export_data(roi_data)
    print("\n[Done] All outputs in /output/")
