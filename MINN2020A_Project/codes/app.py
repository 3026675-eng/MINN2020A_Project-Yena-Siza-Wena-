
# IMPORTS AND Libraries 

from pathlib import Path
from io import BytesIO
from datetime import date, datetime
from functools import wraps
import os

import pandas as pd
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

FLASK_FOLDER = ROOT.parent / "flask"
app = Flask(
    __name__,
    template_folder=str(FLASK_FOLDER / "templates"),
    static_folder=str(FLASK_FOLDER / "static")
)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24).hex()


# ACCESS CONTROL AND SHARED FIELD SETTINGS

ROLES = [
    "Administrator", "Safety Officer", "Mining Engineer",
    "Maintenance Engineer", "Manager"
]

# Each section lists the roles permitted to access it.
PERMISSIONS = {
    "dashboard": ROLES,
    "workers": ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "incidents": ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "equipment": ["Administrator", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "maintenance": ["Administrator", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "risk": ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "alerts": ROLES,
    "analysis": ROLES,
    "reports": ROLES,
    "users": ["Administrator"]
}

#options shared by the record-entry forms.
CHOICES = {
    "shift": ["Day", "Night"],
    "ppe_compliant": ["Yes", "No"],
    "training_status": ["Valid", "Expired", "Pending"],
    "severity": ["Minor", "Moderate", "Major", "Critical"],
    "status": ["Open", "Under Investigation", "Closed"],
    "maintenance_status": ["Operational", "Under Maintenance", "Out of Service"],
    "brake_status": ["OK", "Worn", "Fault", "N/A"],
    "tyre_status": ["OK", "Worn", "Fault", "N/A"],
    "engine_status": ["OK", "Worn", "Fault", "N/A"],
    "lost_time_injury": ["Yes", "No"]
}

NUMBER_FIELDS = {
    "fatigue_level", "near_misses", "previous_incidents", "likelihood",
    "consequence", "operating_hours", "temperature", "vibration",
    "fuel_consumption", "uptime_hours", "downtime_hours", "alerts_30d"
}
DATE_FIELDS = {"date", "last_service_date", "next_service_due"}

# Required columns are checked whenever a CSV file is loaded.
REQUIRED_COLUMNS = {
    "workers": [
        "worker_id", "department", "job_role", "shift", "ppe_compliant",
        "training_status", "fatigue_level", "safety_observations",
        "near_misses", "previous_incidents", "likelihood", "consequence"
    ],
    "incidents": [
        "incident_id", "date", "time", "shift", "location", "department",
        "incident_type", "severity", "injury_status", "lost_time_injury",
        "cause", "corrective_action", "status"
    ],
    "equipment": [
        "equipment_id", "equipment_type", "manufacturer", "department",
        "operating_hours", "temperature", "vibration", "fuel_consumption",
        "brake_status", "tyre_status", "engine_status", "maintenance_status",
        "uptime_hours", "downtime_hours", "last_service_date",
        "next_service_due", "alerts_30d"
    ],
    "users": ["username", "full_name", "role", "password_hash", "active"]
}


# DATA ACCESS AND VALIDATION HELPERS
def read_data(name):
    if name not in REQUIRED_COLUMNS:
        raise ValueError("Unknown data file.")

    file_path = DATA / f"{name}.csv"
    if not file_path.exists():
        raise ValueError(f"{name}.csv was not found.")

    try:
        table = pd.read_csv(file_path, dtype=str, keep_default_na=False)
    except pd.errors.EmptyDataError as error:
        raise ValueError(f"{name}.csv needs a header row.") from error

    missing = [column for column in REQUIRED_COLUMNS[name] if column not in table.columns]
    if missing:
        raise ValueError(f"{name}.csv is missing: {', '.join(missing)}")

    return table


def save_data(name, table):
    if name not in REQUIRED_COLUMNS:
        raise ValueError("Unknown data file.")
    table.to_csv(DATA / f"{name}.csv", index=False)


def setup_users():
    file_path = DATA / "users.csv"
    if file_path.exists():
        return

# Our login user details
    initial_users = [
        ("admin", "Administrator", "Admin@123"),
        ("safety", "Safety Officer", "Safety@123"),
        ("engineer", "Mining Engineer", "Mining@123"),
        ("maint", "Maintenance Engineer", "Maint@123"),
        ("manager", "Manager", "Manager@123")
    ]

    rows = []
    for username, role, password in initial_users:
        rows.append({
            "username": username,
            "full_name": role,
            "role": role,
            "password_hash": generate_password_hash(password),
            "active": "Yes"
        })

    save_data("users", pd.DataFrame(rows))


def allowed(section):
    return section in PERMISSIONS and session.get("role") in PERMISSIONS[section]


def login_required(section):
    def decorator(function):
        @wraps(function)
        def check(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))

            if not allowed(section):
                flash("You do not have permission to open this page.")
                return redirect(url_for("dashboard"))

            return function(*args, **kwargs)
        return check
    return decorator


def form_values(columns):
    values = {key: request.form.get(key, "").strip() for key in columns}

    if any(not value for value in values.values()):
        raise ValueError("Fill in all fields.")

    for key, value in values.items():
        if key in NUMBER_FIELDS:
            try:
                number = float(value)
            except ValueError as error:
                raise ValueError(f"{key} must be numeric.") from error

            if not 0 <= number <= 10_000_000:
                raise ValueError("Enter valid positive numbers.")

            if key in {"likelihood", "consequence"}:
                if not number.is_integer() or not 1 <= number <= 5:
                    raise ValueError("Likelihood and consequence must be whole numbers from 1 to 5.")

            if key in {"near_misses", "previous_incidents", "alerts_30d", "operating_hours"}:
                if not number.is_integer():
                    raise ValueError("Counts and operating hours must be whole numbers.")

            if key == "fatigue_level":
                if not number.is_integer() or number > 10:
                    raise ValueError("Fatigue must be a whole number from 0 to 10.")

        if key in DATE_FIELDS:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError as error:
                raise ValueError(f"{key} must use YYYY-MM-DD format.") from error

        if key in CHOICES and value not in CHOICES[key]:
            raise ValueError(f"Choose a valid option for {key}.")

    return values


#WORKER HEALTH AND SAFETY MONITORING

def risk_level(score):
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def worker_data():
    workers_table = read_data("workers")

    numeric_columns = [
        "likelihood", "consequence", "fatigue_level",
        "near_misses", "previous_incidents"
    ]
    for column in numeric_columns:
        try:
            workers_table[column] = pd.to_numeric(workers_table[column], errors="raise")
        except (ValueError, TypeError) as error:
            raise ValueError(f"Invalid value in workers.csv: {column}") from error

    workers_table["risk_score"] = (
        workers_table["likelihood"] * workers_table["consequence"]
    )
    workers_table["risk_level"] = workers_table["risk_score"].apply(risk_level)
    return workers_table


def worker_warnings(worker):
    warnings = []

    if worker["ppe_compliant"] != "Yes":
        warnings.append("PPE not compliant")
    if worker["training_status"] == "Expired":
        warnings.append("Training expired")
    if worker["fatigue_level"] >= 7:
        warnings.append("High fatigue")
    if worker["risk_level"] in ["High", "Critical"]:
        warnings.append("High risk")

    return "; ".join(warnings)


@app.route("/workers", methods=["GET", "POST"])
@login_required("workers")
def workers():
    if request.method == "POST":
        table = read_data("workers")
        try:
            values = form_values([column for column in table.columns if column != "worker_id"])
        except (ValueError, TypeError):
            flash("Check the information entered. Dates and numbers must be valid.")
            return redirect(url_for("workers"))

        existing_ids = [
            int(value[1:]) for value in table["worker_id"].astype(str)
            if value.startswith("W") and value[1:].isdigit()
        ]
        values["worker_id"] = "W" + str(max(existing_ids, default=0) + 1).zfill(3)
        updated = pd.concat([table, pd.DataFrame([values])], ignore_index=True)
        save_data("workers", updated)
        flash("Worker saved.")
        return redirect(url_for("workers"))

    table = worker_data()
    search = request.args.get("search", "").lower().strip()
    if search:
        table = table[table.astype(str).apply(
            lambda row: search in " ".join(row).lower(), axis=1
        )]

    department = request.args.get("department", "")
    if department:
        table = table[table["department"] == department]

    filters = {"department": sorted(read_data("workers")["department"].unique())}
    table = table.copy()
    table["warnings"] = [worker_warnings(row) for _, row in table.iterrows()]

    return render_template(
        "page.html",
        title="Worker Health and Safety Monitoring",
        section="workers",
        filter_options=filters,
        table=table,
        fields=[column for column in read_data("workers").columns if column != "worker_id"],
        note=None
    )


#SAFETY INCIDENT DATABASE

@app.route("/incidents", methods=["GET", "POST"])
@login_required("incidents")
def incidents():
    if request.method == "POST":
        table = read_data("incidents")
        try:
            values = form_values([column for column in table.columns if column != "incident_id"])
        except (ValueError, TypeError):
            flash("Check the information entered. Dates and numbers must be valid.")
            return redirect(url_for("incidents"))

        prefix = "INC-" + date.today().strftime("%Y") + "-"
        existing_ids = [
            int(value.rsplit("-", 1)[-1])
            for value in table["incident_id"].astype(str)
            if value.startswith(prefix) and value.rsplit("-", 1)[-1].isdigit()
        ]
        values["incident_id"] = prefix + str(max(existing_ids, default=0) + 1).zfill(4)

        updated = pd.concat([table, pd.DataFrame([values])], ignore_index=True)
        save_data("incidents", updated)
        flash("Incident saved.")
        return redirect(url_for("incidents"))

    table = read_data("incidents")
    search = request.args.get("search", "").lower().strip()
    if search:
        table = table[table.astype(str).apply(
            lambda row: search in " ".join(row).lower(), axis=1
        )]

    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")
    try:
        if start_date and end_date and start_date > end_date:
            raise ValueError

        dates = pd.to_datetime(table["date"], errors="coerce")
        if start_date:
            table = table[dates >= pd.Timestamp(datetime.strptime(start_date, "%Y-%m-%d"))]
            dates = pd.to_datetime(table["date"], errors="coerce")
        if end_date:
            table = table[dates <= pd.Timestamp(datetime.strptime(end_date, "%Y-%m-%d"))]
    except ValueError:
        flash("Choose valid dates, with From before To.")
        return redirect(url_for("incidents"))

    for column in ["department", "shift", "severity", "status", "incident_type"]:
        selected = request.args.get(column, "")
        if selected:
            table = table[table[column] == selected]

    counts = table["severity"].value_counts().to_dict()
    original = read_data("incidents")
    filter_options = {
        column: sorted(original[column].astype(str).unique())
        for column in ["department", "shift", "severity", "status", "incident_type"]
    }

    incident_dates = pd.to_datetime(table["date"], errors="coerce")
    monthly_counts = (
        incident_dates.dt.to_period("M").astype(str).value_counts().sort_index().to_dict()
    )

    return render_template(
        "page.html",
        title="Safety Incident Database",
        section="incidents",
        table=table,
        fields=[column for column in read_data("incidents").columns if column != "incident_id"],
        filter_options=filter_options,
        numbers=[
            ("Filtered incidents", len(table)),
            ("Major", counts.get("Major", 0)),
            ("Critical", counts.get("Critical", 0))
        ],
        dashboard_charts=[
            ("Incident severity", table["severity"].value_counts().to_dict(), "donut"),
            ("Incident types", table["incident_type"].value_counts().head(8).to_dict(), "bar"),
            ("Monthly trend", monthly_counts, "line")
        ],
        note=None
    )


#EQUIPMENT AND EQUIPMENT CONDITION MONITORING DATABASE

def equipment_data():
    equipment_table = read_data("equipment")

    numeric_columns = [
        "temperature", "vibration", "uptime_hours",
        "downtime_hours", "alerts_30d"
    ]
    for column in numeric_columns:
        try:
            equipment_table[column] = pd.to_numeric(equipment_table[column], errors="raise")
        except (ValueError, TypeError) as error:
            raise ValueError(f"Invalid value in equipment.csv: {column}") from error

    # Availability measures the share of recorded uptime in total operating time.
    total_time = equipment_table["uptime_hours"] + equipment_table["downtime_hours"]
    equipment_table["availability"] = (
        equipment_table["uptime_hours"] / total_time.where(total_time != 0, 1) * 100
    ).round(1)

    # Apply the predefined monitoring thresholds.
    equipment_table["temperature_status"] = "NORMAL"
    equipment_table.loc[equipment_table["temperature"] >= 80, "temperature_status"] = "WARNING"
    equipment_table.loc[equipment_table["temperature"] > 100, "temperature_status"] = "CRITICAL"

    equipment_table["vibration_status"] = "NORMAL"
    equipment_table.loc[equipment_table["vibration"] >= 5, "vibration_status"] = "WARNING"
    equipment_table.loc[equipment_table["vibration"] > 8, "vibration_status"] = "CRITICAL"

    conditions = []
    messages = []

    for _, row in equipment_table.iterrows():
        statuses = [row["temperature_status"], row["vibration_status"]]
        findings = []

        for parameter in ["temperature", "vibration"]:
            status = row[f"{parameter}_status"]
            if status != "NORMAL":
                findings.append(f"{parameter.title()}: {status}")

        for component in ["brake_status", "tyre_status", "engine_status"]:
            if row[component] == "Fault":
                statuses.append("CRITICAL")
                findings.append(f"{component.replace('_status', '').title()}: Fault")
            elif row[component] == "Worn":
                statuses.append("WARNING")
                findings.append(f"{component.replace('_status', '').title()}: Worn")

        if "CRITICAL" in statuses:
            condition = "CRITICAL"
        elif "WARNING" in statuses:
            condition = "WARNING"
        else:
            condition = "NORMAL"

        conditions.append(condition)

        if condition == "NORMAL":
            messages.append("Equipment operating within defined monitoring limits.")
        elif condition == "WARNING":
            messages.append("WARNING: " + "; ".join(findings) + ". Inspection recommended.")
        else:
            messages.append("CRITICAL: " + "; ".join(findings) + ". Inspection required.")

    equipment_table["condition"] = conditions
    equipment_table["condition_message"] = messages

    # Compare the next service date with today's date.
    today = pd.Timestamp.today().normalize()
    due_dates = pd.to_datetime(equipment_table["next_service_due"], errors="coerce")
    equipment_table["maintenance_check"] = "OK"
    equipment_table.loc[due_dates.isna(), "maintenance_check"] = "Date Missing"
    equipment_table.loc[due_dates < today, "maintenance_check"] = "Overdue"
    equipment_table.loc[
        (due_dates >= today) & (due_dates <= today + pd.Timedelta(days=14)),
        "maintenance_check"
    ] = "Due Soon"
    equipment_table.loc[
        equipment_table["maintenance_status"] == "Under Maintenance",
        "maintenance_check"
    ] = "Under Maintenance"

    return equipment_table


@app.route("/equipment", methods=["GET", "POST"])
@login_required("equipment")
def equipment():
    if request.method == "POST":
        table = read_data("equipment")
        try:
            values = form_values([column for column in table.columns if column != "equipment_id"])
        except (ValueError, TypeError):
            flash("Check the information entered. Dates and numbers must be valid.")
            return redirect(url_for("equipment"))

        existing_ids = [
            int(value.split("-")[-1]) for value in table["equipment_id"].astype(str)
            if value.split("-")[-1].isdigit()
        ]
        values["equipment_id"] = "EQ-" + str(max(existing_ids, default=0) + 1).zfill(3)
        updated = pd.concat([table, pd.DataFrame([values])], ignore_index=True)
        save_data("equipment", updated)
        flash("Equipment saved.")
        return redirect(url_for("equipment"))

    table = equipment_data()
    search = request.args.get("search", "").lower().strip()
    if search:
        table = table[table.astype(str).apply(
            lambda row: search in " ".join(row).lower(), axis=1
        )]

    condition = request.args.get("condition", "")
    if condition:
        table = table[table["condition"] == condition]

    return render_template(
        "page.html",
        title="Equipment Condition Monitoring",
        section="equipment",
        table=table,
        filter_options={"condition": ["NORMAL", "WARNING", "CRITICAL"]},
        fields=[column for column in read_data("equipment").columns if column != "equipment_id"],
        dashboard_charts=[
            ("Equipment condition", table["condition"].value_counts().to_dict(), "donut"),
            ("Equipment type", table["equipment_type"].value_counts().to_dict(), "bar")
        ]
    )


# EQUIPMENT MAINTENANCE MONITORING

@app.route("/maintenance")
@login_required("maintenance")
def maintenance():
    table = equipment_data()

    def maintenance_reasons(row):
        reasons = []
        if row["maintenance_check"] != "OK":
            reasons.append(row["maintenance_check"])
        if row["availability"] < 80:
            reasons.append("Low availability")
        if row["downtime_hours"] > 100:
            reasons.append("Excessive downtime")
        if row["alerts_30d"] >= 3:
            reasons.append("Repeated alerts")
        if row["condition"] == "CRITICAL":
            reasons.append("Critical condition")
        return "; ".join(reasons)

    table["maintenance_reason"] = table.apply(maintenance_reasons, axis=1)
    table = table[table["maintenance_reason"] != ""]

    return render_template(
        "page.html",
        title="Equipment Maintenance Monitoring",
        section="maintenance",
        table=table
    )


# RISK ASSESSMENT

@app.route("/risk", methods=["GET", "POST"])
@login_required("risk")
def risk():
    result = None

    if request.method == "POST":
        try:
            likelihood = int(request.form.get("likelihood", ""))
            consequence = int(request.form.get("consequence", ""))

            if not (1 <= likelihood <= 5 and 1 <= consequence <= 5):
                raise ValueError

            score = likelihood * consequence
            level = risk_level(score)
            result = f"Risk score: {score} | {level}"

            if level == "High":
                result += " | Review safety controls."
            elif level == "Critical":
                result += " | Stop work and report the risk."

        except ValueError:
            flash("Enter whole numbers from 1 to 5 for likelihood and consequence.")

    return render_template(
        "page.html",
        title="Risk Assessment",
        section="risk",
        result=result,
        note=None
    )


# 9. ALERTS AND NOTIFICATIONS

def make_alerts(workers_table, incidents_table, equipment_table):
    alerts = []

    if len(workers_table):
        ppe_rate = (workers_table["ppe_compliant"] == "Yes").mean() * 100
        if ppe_rate < 90:
            alerts.append([
                "WARNING", "Worker Safety", "All workers", "PPE compliance",
                f"{ppe_rate:.1f}%", "Low PPE compliance (below 90%)",
                "Run PPE checks before each shift."
            ])

    for _, worker in workers_table.iterrows():
        if worker["ppe_compliant"] != "Yes":
            alerts.append([
                "WARNING", "Worker Safety", worker["worker_id"], "PPE", "No",
                "PPE not compliant", "Provide required PPE before work."
            ])
        if worker["training_status"] == "Expired":
            alerts.append([
                "WARNING", "Worker Safety", worker["worker_id"], "Training", "Expired",
                "Safety training expired", "Arrange refresher training."
            ])
        if worker["fatigue_level"] >= 7:
            severity = "CRITICAL" if worker["fatigue_level"] >= 9 else "WARNING"
            alerts.append([
                severity, "Worker Safety", worker["worker_id"], "Fatigue",
                str(worker["fatigue_level"]), "High fatigue",
                "Review fitness for duty and rest periods."
            ])
        if worker["risk_level"] in ["High", "Critical"]:
            severity = "CRITICAL" if worker["risk_level"] == "Critical" else "WARNING"
            alerts.append([
                severity, "Risk", worker["worker_id"], "Risk score",
                str(worker["risk_score"]), "High-risk safety observation",
                "Review risk controls."
            ])

    for _, incident in incidents_table.iterrows():
        if incident["severity"] == "Critical" and incident["status"] != "Closed":
            alerts.append([
                "CRITICAL", "Incident", incident["incident_id"], "Severity",
                "Critical", "Open critical incident",
                "Investigate and implement corrective action."
            ])

    for _, item in equipment_table.iterrows():
        for parameter, reading, status, unit in [
            ("Vibration", item["vibration"], item["vibration_status"], "mm/s"),
            ("Temperature", item["temperature"], item["temperature_status"], "°C")
        ]:
            if status in ["WARNING", "CRITICAL"]:
                alerts.append([
                    status, "Equipment", item["equipment_id"], parameter,
                    f"{reading:.1f} {unit}", "Monitoring threshold exceeded",
                    "Inspect equipment and follow manufacturer procedures."
                ])

        for component in ["brake_status", "tyre_status", "engine_status"]:
            if item[component] in ["Worn", "Fault"]:
                severity = "CRITICAL" if item[component] == "Fault" else "WARNING"
                alerts.append([
                    severity, "Equipment", item["equipment_id"],
                    component.replace("_status", "").title(), item[component],
                    "Fault detected" if severity == "CRITICAL" else "Wear detected",
                    "Inspect equipment and plan appropriate maintenance."
                ])

        if item["maintenance_check"] == "Overdue":
            alerts.append([
                "WARNING", "Maintenance", item["equipment_id"], "Service",
                str(item["next_service_due"]), "Overdue maintenance",
                "Schedule maintenance."
            ])
        if item["downtime_hours"] > 100:
            alerts.append([
                "WARNING", "Maintenance", item["equipment_id"], "Downtime",
                str(item["downtime_hours"]) + " hours", "Excessive downtime",
                "Investigate equipment downtime."
            ])
        if item["availability"] < 80:
            alerts.append([
                "WARNING", "Maintenance", item["equipment_id"], "Availability",
                str(item["availability"]) + "%", "Low availability",
                "Review maintenance performance."
            ])
        if item["alerts_30d"] >= 3:
            alerts.append([
                "WARNING", "Maintenance", item["equipment_id"], "Previous alerts",
                str(item["alerts_30d"]), "Repeated alerts",
                "Inspect equipment history."
            ])

    columns = [
        "Severity", "Category", "ID", "Parameter", "Value", "Status",
        "Recommended Action"
    ]
    return pd.DataFrame(alerts, columns=columns)


def visible_alerts(alert_table):
    section_by_category = {
        "Worker Safety": "workers",
        "Risk": "risk",
        "Incident": "incidents",
        "Equipment": "equipment",
        "Maintenance": "maintenance"
    }
    permitted = alert_table["Category"].map(
        lambda category: category in section_by_category
        and allowed(section_by_category[category])
    )
    return alert_table[permitted].copy()


@app.route("/alerts")
@login_required("alerts")
def alerts():
    table = visible_alerts(
        make_alerts(worker_data(), read_data("incidents"), equipment_data())
    )
    return render_template(
        "page.html",
        title="Alerts and Notifications",
        section="alerts",
        table=table,
        note=None
    )

# 10. MINING MONITORING DASHBOARD

def dashboard_charts(workers_table, incidents_table, equipment_table):
    charts = []

    if allowed("incidents"):
        charts.append((
            "Incidents by severity",
            incidents_table["severity"].value_counts().to_dict(),
            "donut"
        ))
    if allowed("workers"):
        charts.append((
            "Worker risk levels",
            workers_table["risk_level"].value_counts().to_dict(),
            "bar"
        ))
    if allowed("equipment"):
        charts.append((
            "Equipment condition",
            equipment_table["condition"].value_counts().to_dict(),
            "donut"
        ))
    if allowed("maintenance"):
        charts.append((
            "Maintenance status",
            equipment_table["maintenance_check"].value_counts().to_dict(),
            "bar"
        ))

    return charts


def graph(data, kind="bar"):
    from markupsafe import Markup, escape

    if not data:
        return Markup('<p class="muted">No data for this selection.</p>')

    entries = list(data.items())[:15]

    if kind == "list":
        items = "".join(f"<li>{escape(str(label))}</li>" for label, _ in entries)
        return Markup(f"<ol>{items}</ol>")

    if kind == "donut":
        colours = ["#f9a02b", "#3777b8", "#43a990", "#a374cb", "#d56c73", "#b6ca51"]
        total = sum(max(float(value), 0) for _, value in entries) or 1
        slices, legend = [], []
        current = 0

        for index, (label, value) in enumerate(entries):
            amount = max(float(value), 0)
            end = current + amount / total * 100
            colour = colours[index % len(colours)]
            slices.append(f"{colour} {current:.2f}% {end:.2f}%")
            legend.append(
                '<div class="donut-item">'
                f'<span class="dot" style="background:{colour}"></span>'
                f'{escape(str(label))}: {amount:g}</div>'
            )
            current = end

        chart_style = "background:conic-gradient(" + ",".join(slices) + ")"
        legend_html = "".join(legend)
        return Markup(
            '<div class="donut-wrap">'
            f'<div class="donut" role="img" aria-label="Distribution chart" '
            f'style="{chart_style}"></div>'
            f'<div class="donut-list">{legend_html}</div></div>'
        )

    if kind == "line":
        values = [float(value) for _, value in entries]
        highest = max(values + [1])
        width, height = 550, 200
        points = [
            (35 + index * 480 / max(len(values) - 1, 1),
             175 - value / highest * 145)
            for index, value in enumerate(values)
        ]
        coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        dots = "".join(
            f'<circle class="point" cx="{x:.1f}" cy="{y:.1f}" r="4">'
            f'<title>{escape(str(entries[index][0]))}: {values[index]:g}</title></circle>'
            for index, (x, y) in enumerate(points)
        )
        labels = "".join(
            f'<text class="axis" x="{x:.1f}" y="193" text-anchor="middle">'
            f'{escape(str(entries[index][0]))}</text>'
            for index, (x, _) in enumerate(points)
            if index % max(1, len(points) // 6) == 0
        )
        return Markup(
            f'<svg class="chart-line" viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="Trend chart"><polyline class="trend" points="{coordinates}"/>'
            f'{dots}{labels}</svg>'
        )

    peak = max([float(value) for _, value in entries] + [1])
    bars = []

    for label, value in entries:
        amount = max(float(value), 0)
        bars.append(
            '<div class="chart-row">'
            f'<span>{escape(str(label))}</span>'
            '<div class="bar-track">'
            f'<div class="bar-fill" style="width:{amount / peak * 100:.1f}%"></div>'
            '</div>'
            f'<b>{amount:g}</b></div>'
        )

    return Markup("".join(bars))


@app.context_processor
def menu_settings():
    return {
        "permissions": PERMISSIONS,
        "allowed": allowed,
        "choices": CHOICES,
        "number_fields": NUMBER_FIELDS,
        "date_fields": DATE_FIELDS,
        "graph": graph
    }


@app.errorhandler(ValueError)
def data_error(error):
    return render_template("error.html", message=str(error)), 400


@app.route("/dashboard")
@login_required("dashboard")
def dashboard():
    workers_table = worker_data()
    incidents_table = read_data("incidents")
    equipment_table = equipment_data()
    alert_table = visible_alerts(
        make_alerts(workers_table, incidents_table, equipment_table)
    )

    numbers = [
        ("Workers", len(workers_table) if allowed("workers") else "-"),
        ("Incidents", len(incidents_table) if allowed("incidents") else "-"),
        ("Equipment", len(equipment_table) if allowed("equipment") else "-"),
        ("Active alerts", len(alert_table)),
        ("Critical alerts", int((alert_table["Severity"] == "CRITICAL").sum()))
    ]

    if allowed("workers"):
        ppe_rate = (
            (workers_table["ppe_compliant"] == "Yes").mean() * 100
            if len(workers_table) else 0
        )
        numbers.extend([
            ("PPE compliance", f"{ppe_rate:.1f}%"),
            ("High-risk observations",
             int(workers_table["risk_level"].isin(["High", "Critical"]).sum())),
            ("Near misses", int(workers_table["near_misses"].sum()))
        ])

    if allowed("equipment"):
        numbers.extend([
            ("Average availability",
             f"{equipment_table['availability'].mean() if len(equipment_table) else 0:.1f}%"),
            ("Equipment available",
             int((equipment_table["maintenance_status"] == "Operational").sum())),
            ("Equipment alerts", int((alert_table["Category"] == "Equipment").sum())),
            ("Critical equipment alerts", int((
                (alert_table["Category"] == "Equipment")
                & (alert_table["Severity"] == "CRITICAL")
            ).sum()))
        ])

    if allowed("maintenance"):
        numbers.append((
            "Under maintenance",
            int((equipment_table["maintenance_check"] == "Under Maintenance").sum())
        ))

    return render_template(
        "page.html",
        title="Dashboard",
        section="dashboard",
        numbers=numbers,
        table=alert_table.head(12),
        dashboard_charts=dashboard_charts(
            workers_table, incidents_table, equipment_table
        ),
        note=None
    )


# INTERACTIVE DATA ANALYSIS

QUESTIONS = [
    ("Health and Safety", "How many safety incidents occurred during the selected period?", "incidents"),
    ("Health and Safety", "Which department has the highest number of incidents?", "incidents"),
    ("Health and Safety", "Which shift records the most incidents?", "incidents"),
    ("Health and Safety", "What percentage of workers comply with PPE requirements?", "workers"),
    ("Health and Safety", "How many near misses have been recorded?", "workers"),
    ("Health and Safety", "Which incident types occur most frequently?", "incidents"),
    ("Health and Safety", "How many incidents are classified as high or critical?", "incidents"),
    ("Health and Safety", "Which departments have the highest safety risk?", "workers"),
    ("Health and Safety", "Is there an observable difference in incidents between day and night shifts?", "incidents"),
    ("Health and Safety", "Which safety conditions require immediate attention?", "workers"),
    ("Equipment", "Which equipment has the highest downtime?", "equipment"),
    ("Equipment", "Which equipment has the lowest availability?", "equipment"),
    ("Equipment", "Which equipment has the highest vibration?", "equipment"),
    ("Equipment", "Which equipment has the highest operating temperature?", "equipment"),
    ("Equipment", "Which equipment has generated the most alerts?", "equipment"),
    ("Equipment", "Which equipment requires maintenance?", "maintenance"),
    ("Equipment", "Which equipment is overdue for maintenance?", "maintenance"),
    ("Equipment", "What is the average equipment availability?", "equipment"),
    ("Equipment", "Which equipment type has the highest downtime?", "equipment"),
    ("Equipment", "Which equipment requires immediate inspection?", "equipment"),
    ("Integrated Safety and Equipment Analysis", "Are safety incidents associated with particular shifts?", "incidents"),
    ("Integrated Safety and Equipment Analysis", "Which departments have both high safety risk and high equipment downtime?", "workers,equipment"),
    ("Integrated Safety and Equipment Analysis", "Which equipment contributes to the greatest number of alerts?", "equipment"),
    ("Integrated Safety and Equipment Analysis", "Which equipment should receive maintenance priority?", "maintenance"),
    ("Integrated Safety and Equipment Analysis", "What are the most common causes of safety incidents?", "incidents"),
    ("Integrated Safety and Equipment Analysis", "Which safety indicators require management intervention?", "workers,incidents"),
    ("Integrated Safety and Equipment Analysis", "What percentage of monitored equipment is operating normally?", "equipment"),
    ("Integrated Safety and Equipment Analysis", "How many critical alerts are currently active?", "alerts"),
    ("Integrated Safety and Equipment Analysis", "Which areas of the operation require the greatest attention?", "workers,incidents,equipment"),
    ("Integrated Safety and Equipment Analysis", "What recommendations can be generated from the monitoring results?", "workers,incidents,equipment")
]


def answer_question(index, workers_table, incidents_table, equipment_table, alert_table):
    incident_count = len(incidents_table)
    serious_incidents = incidents_table[
        incidents_table["severity"].isin(["Major", "Critical"])
    ]
    high_risk_workers = workers_table[
        workers_table["risk_level"].isin(["High", "Critical"])
    ]
    overdue_equipment = equipment_table[
        equipment_table["maintenance_check"] == "Overdue"
    ]
    equipment_attention = equipment_table[
        (equipment_table["condition"] == "CRITICAL")
        | equipment_table["maintenance_check"].isin(["Overdue", "Due Soon"])
        | (equipment_table["availability"] < 80)
    ]
    equipment_alerts = alert_table[alert_table["Category"] == "Equipment"]

    def result(message, data=None, kind="bar", table=None):
        return {"text": message, "data": data or {}, "kind": kind, "table": table}

    def frequency(column):
        return incidents_table[column].value_counts().to_dict()

    def top_item(items):
        return next(iter(items), "None")

    if index == 0:
        dates = pd.to_datetime(incidents_table["date"], errors="coerce")
        trend = dates.dt.to_period("M").astype(str).value_counts().sort_index()
        return result(
            f"{incident_count} safety incidents occurred during the selected period.",
            trend.to_dict(), "line"
        )

    if index == 1:
        counts = frequency("department")
        return result(
            f"{top_item(counts)} has the highest number of incidents "
            f"({next(iter(counts.values()), 0)}).", counts
        )

    if index == 2:
        counts = frequency("shift")
        return result(
            f"{top_item(counts)} shift records the most incidents "
            f"({next(iter(counts.values()), 0)}).", counts
        )

    if index == 3:
        rate = round((workers_table["ppe_compliant"] == "Yes").mean() * 100, 1) if len(workers_table) else 0
        by_department = workers_table.groupby("department")["ppe_compliant"].apply(
            lambda values: round((values == "Yes").mean() * 100, 1)
        ).to_dict()
        return result(f"{rate}% of workers comply with PPE requirements.", by_department)

    if index == 4:
        total = int(workers_table["near_misses"].sum())
        by_department = workers_table.groupby("department")["near_misses"].sum().to_dict()
        return result(f"{total} near misses have been recorded.", by_department)

    if index == 5:
        counts = frequency("incident_type")
        return result(f"{top_item(counts)} is the most frequent incident type.", counts)

    if index == 6:
        counts = serious_incidents["severity"].value_counts().to_dict()
        return result(
            f"{len(serious_incidents)} incidents are classified as Major or Critical.",
            counts, "donut"
        )

    if index == 7:
        if workers_table.empty:
            return result("No worker records.")
        averages = workers_table.groupby("department")["risk_score"].mean().round(1)
        averages = averages.sort_values(ascending=False).to_dict()
        return result(
            f"{top_item(averages)} has the highest average safety risk score.",
            averages
        )

    if index in (8, 20):
        counts = frequency("shift")
        return result(
            "Incident counts by shift; differences do not prove causation.",
            counts
        )

    if index == 9:
        danger = workers_table[
            (workers_table["ppe_compliant"] != "Yes")
            | (workers_table["training_status"] == "Expired")
            | (workers_table["fatigue_level"] >= 7)
            | workers_table["risk_level"].isin(["High", "Critical"])
        ]
        return result(
            f"{len(danger)} workers have safety conditions requiring attention.",
            danger["department"].value_counts().to_dict(),
            table=danger[
                ["worker_id", "department", "risk_level", "fatigue_level", "ppe_compliant"]
            ].head(30)
        )

    if 10 <= index <= 14:
        columns = ["downtime_hours", "availability", "vibration", "temperature", "alerts_30d"]
        column = columns[index - 10]
        ranked = equipment_table.sort_values(
            column, ascending=(index == 11)
        )[["equipment_id", "equipment_type", column]].head(10)

        if ranked.empty:
            return result("No equipment records.")

        first = ranked.iloc[0]
        direction = "lowest" if index == 11 else "highest"
        data = ranked.set_index("equipment_id")[column].to_dict()
        return result(
            f"{first['equipment_id']} has the {direction} {column.replace('_', ' ')}: "
            f"{first[column]}.",
            data, table=ranked
        )

    if index == 15:
        return result(
            f"{len(equipment_attention)} equipment units require maintenance or inspection.",
            equipment_attention["maintenance_check"].value_counts().to_dict(),
            table=equipment_attention[
                ["equipment_id", "condition", "maintenance_check", "availability"]
            ]
        )

    if index == 16:
        return result(
            f"{len(overdue_equipment)} equipment units are overdue for maintenance.",
            overdue_equipment["equipment_type"].value_counts().to_dict(),
            table=overdue_equipment[
                ["equipment_id", "next_service_due", "maintenance_status"]
            ]
        )

    if index == 17:
        averages = equipment_table.groupby("equipment_type")["availability"].mean().round(1).to_dict()
        average = equipment_table["availability"].mean() if len(equipment_table) else 0
        return result(f"Average equipment availability is {average:.1f}%.", averages)

    if index == 18:
        totals = equipment_table.groupby("equipment_type")["downtime_hours"].sum()
        totals = totals.sort_values(ascending=False).round(1).to_dict()
        return result(f"{top_item(totals)} has the highest total downtime.", totals)

    if index == 19:
        critical = equipment_table[equipment_table["condition"] == "CRITICAL"]
        return result(
            f"{len(critical)} units have recorded critical condition findings.",
            critical["equipment_type"].value_counts().to_dict(),
            table=critical[["equipment_id", "condition_message"]]
        )

    if index == 21:
        risk_by_department = workers_table.groupby("department")["risk_score"].mean()
        downtime_by_department = equipment_table.groupby("department")["downtime_hours"].sum()
        common = risk_by_department.index.intersection(downtime_by_department.index)
        comparison = pd.DataFrame({
            "risk": risk_by_department.reindex(common),
            "downtime": downtime_by_department.reindex(common)
        })

        if len(comparison):
            selected = comparison[
                (comparison["risk"] >= comparison["risk"].median())
                & (comparison["downtime"] >= comparison["downtime"].median())
            ]
        else:
            selected = comparison

        departments = ", ".join(selected.index) or "none"
        return result(
            "Departments at or above the median for both average risk and downtime: "
            + departments + ".",
            selected["downtime"].round(1).to_dict(),
            table=comparison.reset_index()
        )

    if index == 22:
        counts = equipment_alerts["ID"].value_counts().head(10).to_dict()
        return result(
            f"{top_item(counts)} contributes the most currently generated equipment alerts.",
            counts
        )

    if index == 23:
        ranked = equipment_table.copy()
        ranked["priority"] = (
            (ranked["condition"] == "CRITICAL").astype(int) * 3
            + (ranked["maintenance_check"] == "Overdue").astype(int) * 3
            + (ranked["availability"] < 80).astype(int) * 2
            + (ranked["downtime_hours"] > 100).astype(int)
            + (ranked["alerts_30d"] >= 3).astype(int)
        )
        ranked = ranked.sort_values("priority", ascending=False)
        message = (
            f"{ranked.iloc[0]['equipment_id']} has the highest maintenance priority score."
            if len(ranked) else "No equipment."
        )
        return result(
            message,
            ranked.set_index("equipment_id")["priority"].head(10).to_dict(),
            table=ranked[
                ["equipment_id", "priority", "condition", "maintenance_check"]
            ].head(10)
        )

    if index == 24:
        counts = frequency("cause")
        return result(f"{top_item(counts)} is the most frequently recorded incident cause.", counts)

    if index == 25:
        indicators = {
            "PPE non-compliant": int((workers_table["ppe_compliant"] != "Yes").sum()),
            "High fatigue": int((workers_table["fatigue_level"] >= 7).sum()),
            "Training expired": int((workers_table["training_status"] == "Expired").sum()),
            "High risk": len(high_risk_workers),
            "Open critical incidents": int((
                (incidents_table["severity"] == "Critical")
                & (incidents_table["status"] != "Closed")
            ).sum())
        }
        return result("Safety indicators requiring attention are shown below.", indicators)

    if index == 26:
        normal_percent = round(
            (equipment_table["condition"] == "NORMAL").mean() * 100, 1
        ) if len(equipment_table) else 0
        return result(
            f"{normal_percent}% of equipment is operating normally within monitoring limits.",
            equipment_table["condition"].value_counts().to_dict(),
            "donut"
        )

    if index == 27:
        critical_alerts = alert_table[alert_table["Severity"] == "CRITICAL"]
        return result(
            f"{len(critical_alerts)} critical alerts are currently active.",
            critical_alerts["Category"].value_counts().to_dict()
        )

    if index == 28:
        departments = sorted(
            set(workers_table["department"])
            | set(incidents_table["department"])
            | set(equipment_table["department"])
        )
        attention_counts = {}

        for department in departments:
            worker_count = (
                (workers_table["department"] == department)
                & workers_table["risk_level"].isin(["High", "Critical"])
            ).sum()
            incident_count_for_department = (
                incidents_table["department"] == department
            ).sum()
            critical_equipment = (
                (equipment_table["department"] == department)
                & (equipment_table["condition"] == "CRITICAL")
            ).sum()
            overdue_count = (
                (equipment_table["department"] == department)
                & (equipment_table["maintenance_check"] == "Overdue")
            ).sum()

            attention_counts[department] = int(
                worker_count + incident_count_for_department
                + critical_equipment + overdue_count
            )

        attention_counts = dict(
            sorted(attention_counts.items(), key=lambda item: -item[1])
        )
        return result(
            f"{top_item(attention_counts)} has the highest combined attention count (indicative only).",
            attention_counts
        )

    if index == 29:
        recommendations = []
        if (workers_table["ppe_compliant"] != "Yes").any():
            recommendations.append("Check PPE compliance before shifts.")
        if (workers_table["fatigue_level"] >= 7).any():
            recommendations.append("Review fatigue and work schedules.")
        if (workers_table["training_status"] == "Expired").any():
            recommendations.append("Schedule expired safety training.")
        if len(overdue_equipment):
            recommendations.append("Service overdue equipment.")
        if (equipment_table["condition"] == "CRITICAL").any():
            recommendations.append("Inspect critical equipment conditions.")
        if len(serious_incidents):
            recommendations.append("Review major and critical incidents.")
        if not recommendations:
            recommendations.append("Continue routine monitoring.")

        items = {f"{number}. {message}": 1 for number, message in enumerate(recommendations, 1)}
        return result("Recommendations based on current monitoring records.", items, "list")

    return result("No result available.")


@app.route("/analysis")
@login_required("analysis")
def analysis():
    available = [
        (number, group, label)
        for number, (group, label, required) in enumerate(QUESTIONS)
        if all(allowed(section) for section in required.split(","))
    ]

    group_names = [
        "Health and Safety", "Equipment", "Integrated Safety and Equipment Analysis"
    ]
    groups = {
        name: [(number, label) for number, group, label in available if group == name]
        for name in group_names
    }

    selected = request.args.get("question", type=int)
    available_ids = [number for number, _, _ in available]
    if selected not in available_ids:
        selected = available_ids[0] if available_ids else None

    workers_table = worker_data()
    incidents_table = read_data("incidents")
    equipment_table = equipment_data()

    # The date range currently filters incident records. Worker and equipment
    # records do not contain a matching incident date field.
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")

    try:
        if start_date and end_date and start_date > end_date:
            raise ValueError

        incident_dates = pd.to_datetime(incidents_table["date"], errors="coerce")
        if start_date:
            incidents_table = incidents_table[
                incident_dates >= pd.Timestamp(datetime.strptime(start_date, "%Y-%m-%d"))
            ]
            incident_dates = pd.to_datetime(incidents_table["date"], errors="coerce")
        if end_date:
            incidents_table = incidents_table[
                incident_dates <= pd.Timestamp(datetime.strptime(end_date, "%Y-%m-%d"))
            ]
    except ValueError:
        flash("Choose valid dates, with From before To.")
        return redirect(url_for("analysis"))

    # Alerts are generated from the complete incident dataset, independent of the date filter.
    all_incidents = read_data("incidents")
    alert_table = visible_alerts(
        make_alerts(workers_table, all_incidents, equipment_table)
    )

    answer = (
        answer_question(
            selected, workers_table, incidents_table, equipment_table, alert_table
        )
        if selected is not None else None
    )

    return render_template(
        "page.html",
        title="Interactive Data Analysis",
        section="analysis",
        question_groups=groups,
        selected_question=selected,
        answer=answer,
        note=None
    )


# 12. REPORTS AND DOWNLOADS

@app.route("/reports")
@login_required("reports")
def reports():
    """Show report downloads available to the current user."""
    available = [
        name for name, section in [
            ("workers", "workers"),
            ("incidents", "incidents"),
            ("equipment", "equipment")
        ]
        if allowed(section)
    ] + ["alerts"]

    return render_template(
        "page.html",
        title="Generate Reports",
        section="reports",
        downloads=available,
        note=None
    )


def create_full_report():
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.graphics.shapes import Drawing, Rect, String

    workers_table = worker_data()
    incidents_table = read_data("incidents")
    equipment_table = equipment_data()
    alert_table = make_alerts(workers_table, incidents_table, equipment_table)

    buffer = BytesIO()
    pdf = SimpleDocTemplate(
        buffer, pagesize=(595, 842),
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    styles = getSampleStyleSheet()
    styles["Title"].textColor = colors.HexColor("#17344A")
    styles["Heading2"].textColor = colors.HexColor("#17344A")
    parts = []

    def heading(title):
        parts.extend([Spacer(1, 12), Paragraph(title, styles["Heading2"])])

    def paragraph(message):
        parts.extend([Paragraph(str(message), styles["BodyText"]), Spacer(1, 7)])

    def add_table(rows):
        cells = [[Paragraph(str(value), styles["BodyText"]) for value in row] for row in rows]
        report_table = Table(cells, colWidths=[255, 255], repeatRows=1, hAlign="LEFT")
        report_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3edf3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#17344A")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7)
        ]))
        parts.append(report_table)

    def add_chart(title, counts):
        counts = list(counts.items())[:6]
        if not counts:
            return

        heading(title)
        highest = max(float(value) for _, value in counts) or 1
        height = 25 * len(counts) + 15
        drawing = Drawing(510, height)

        for number, (label, value) in enumerate(counts):
            y = height - 25 * (number + 1)
            drawing.add(String(0, y + 4, str(label)[:29], fontSize=8))
            drawing.add(Rect(
                180, y, 260 * max(float(value), 0) / highest, 13,
                fillColor=colors.HexColor("#e99a26"), strokeColor=None
            ))
            drawing.add(String(450, y + 4, f"{float(value):g}", fontSize=8))

        parts.append(drawing)

    parts.append(Paragraph(
        "Mining Health, Safety and Equipment Monitoring Report", styles["Title"]
    ))
    paragraph("Khwezi Mining | Generated " + date.today().strftime("%d %B %Y"))
    paragraph(
        "Based on the current workers.csv, incidents.csv and equipment.csv datasets."
    )

    heading("1. Monitoring Summary")
    ppe_rate = (
        (workers_table["ppe_compliant"] == "Yes").mean() * 100
        if len(workers_table) else 0
    )
    average_availability = (
        equipment_table["availability"].mean() if len(equipment_table) else 0
    )
    high_risk_count = int(
        workers_table["risk_level"].isin(["High", "Critical"]).sum()
    )

    add_table([
        ["Indicator", "Value"],
        ["Workers", len(workers_table)],
        ["Safety incidents", len(incidents_table)],
        ["Near misses", int(workers_table["near_misses"].sum())],
        ["PPE compliance", f"{ppe_rate:.1f}%"],
        ["High/Critical worker risks", high_risk_count],
        ["Equipment units", len(equipment_table)],
        ["Average availability", f"{average_availability:.1f}%"],
        ["Active monitoring alerts", len(alert_table)],
        ["Critical alerts", int((alert_table["Severity"] == "CRITICAL").sum())]
    ])

    heading("2. Worker Health and Safety")
    add_chart("Worker Risk Levels", workers_table["risk_level"].value_counts().to_dict())
    paragraph(
        "Workers with expired training: "
        + str(int((workers_table["training_status"] == "Expired").sum()))
        + ". Workers with high fatigue (7 or above): "
        + str(int((workers_table["fatigue_level"] >= 7).sum())) + "."
    )

    heading("3. Safety Incidents")
    add_chart("Incident Severity", incidents_table["severity"].value_counts().to_dict())
    add_chart("Incidents by Department", incidents_table["department"].value_counts().to_dict())

    if len(incidents_table):
        dates = pd.to_datetime(incidents_table["date"], errors="coerce").dropna()
        if len(dates):
            paragraph(
                "Incident dates: " + dates.min().strftime("%d %b %Y")
                + " to " + dates.max().strftime("%d %b %Y") + "."
            )
        add_chart("Incidents by Shift", incidents_table["shift"].value_counts().to_dict())

    heading("4. Equipment Condition and Maintenance")
    add_chart("Equipment Condition", equipment_table["condition"].value_counts().to_dict())
    add_chart("Maintenance Status", equipment_table["maintenance_check"].value_counts().to_dict())

    overdue = equipment_table[equipment_table["maintenance_check"] == "Overdue"]
    critical = equipment_table[equipment_table["condition"] == "CRITICAL"]
    paragraph(
        f"{len(overdue)} units are overdue for maintenance; "
        f"{len(critical)} units have critical condition findings; "
        f"{int((equipment_table['availability'] < 80).sum())} units have availability below 80%."
    )

    if len(critical):
        paragraph(
            "Critical equipment IDs: "
            + ", ".join(critical["equipment_id"].astype(str).tolist()[:20])
        )

    heading("5. Alerts and Notifications")
    add_chart("Alerts by Severity", alert_table["Severity"].value_counts().to_dict())
    add_chart("Alerts by Category", alert_table["Category"].value_counts().to_dict())

    critical_alerts = alert_table[alert_table["Severity"] == "CRITICAL"]
    for _, alert in critical_alerts.head(12).iterrows():
        paragraph(
            f"<b>{alert['ID']} - {alert['Parameter']}:</b> "
            f"{alert['Value']}. {alert['Status']}. {alert['Recommended Action']}"
        )

    if len(critical_alerts) > 12:
        paragraph("Only the first 12 critical alerts are listed in this report.")

    heading("6. Conclusions and Recommendations")
    recommendations = []

    if ppe_rate < 90:
        recommendations.append("Improve PPE compliance through shift inspections.")
    if high_risk_count:
        recommendations.append("Review controls for high and critical worker risks.")
    if (workers_table["fatigue_level"] >= 7).any():
        recommendations.append("Assess fatigue levels and review work schedules.")
    if len(overdue):
        recommendations.append("Prioritise overdue equipment servicing.")
    if len(critical):
        recommendations.append("Inspect equipment with critical monitoring conditions.")
    if not recommendations:
        recommendations.append("Continue routine monitoring and preventive maintenance.")

    for number, recommendation in enumerate(recommendations, 1):
        paragraph(f"{number}. {recommendation}")

    pdf.build(parts)
    buffer.seek(0)
    return buffer.getvalue()


@app.route("/full-report")
@login_required("reports")
def full_report():
    required_sections = ["workers", "incidents", "equipment", "maintenance", "risk"]
    if not all(allowed(section) for section in required_sections):
        flash("This report requires access to safety and equipment records.")
        return redirect(url_for("reports"))

    content = create_full_report()
    return Response(
        content,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=full_data_report.pdf"}
    )


@app.route("/download/<name>")
@login_required("reports")
def download(name):
    if name not in ["workers", "incidents", "equipment", "alerts"]:
        return redirect(url_for("reports"))

    if name != "alerts" and not allowed(name):
        return redirect(url_for("reports"))

    if name == "alerts":
        table = visible_alerts(
            make_alerts(worker_data(), read_data("incidents"), equipment_data())
        )
    else:
        table = read_data(name)

    content = table.to_csv(index=False)
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}_report.csv"}
    )


# USER ACCOUNT MANAGEMENT

@app.route("/users", methods=["GET", "POST"])
@login_required("users")
def users():
    if request.method == "POST":
        table = read_data("users")
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "")
        password = request.form.get("password", "")

        if (
            not username or not full_name or role not in ROLES
            or len(password) < 8 or username in table["username"].values
        ):
            flash(
                "Enter a unique username, a name, a role and a password "
                "of at least 8 characters."
            )
        else:
            new_user = {
                "username": username,
                "full_name": full_name,
                "role": role,
                "password_hash": generate_password_hash(password),
                "active": "Yes"
            }
            updated = pd.concat([table, pd.DataFrame([new_user])], ignore_index=True)
            save_data("users", updated)
            flash("User created.")
            return redirect(url_for("users"))

    table = read_data("users")[["username", "full_name", "role", "active"]]
    return render_template(
        "page.html",
        title="Access Control - Manage Users",
        section="users",
        table=table,
        roles=ROLES,
        note=None
    )


# LOGIN AND LOGOUT ROUTES

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        session.clear()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users_table = read_data("users")
        matching_users = users_table[users_table["username"] == username]

        if not matching_users.empty:
            user = matching_users.iloc[0]
            if (
                str(user["active"]) == "Yes"
                and check_password_hash(user["password_hash"], password)
            ):
                session.clear()
                session["username"] = username
                session["name"] = user["full_name"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))

        flash("Incorrect username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    return redirect(url_for("login"))


# Create initial demonstration accounts if the users dataset does not exist.
setup_users()


# APPLICATION ENTRY POINT

if __name__ == "__main__":
    app.run(debug=False)
