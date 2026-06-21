import os
import io
import pandas as pd
from flask import Flask, render_template, request, send_file, flash, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)

DEDUP_FIELDS = ["QID", "DNS"]


def find_column(df, candidates):
    """Return the first column name from df that matches any candidate (case-insensitive)."""
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def load_csv(file_storage):
    return pd.read_csv(file_storage, dtype=str, low_memory=False)


def resolve_dedup_columns(df):
    """Return (qid_col, dns_col) or raise ValueError if not found."""
    qid_col = find_column(df, ["QID", "Vuln ID", "VulnID"])
    dns_col = find_column(df, ["DNS", "DNS Name", "Hostname", "Host", "FQDN"])
    if not qid_col:
        raise ValueError("Could not find a QID column. Expected: 'QID'")
    if not dns_col:
        raise ValueError("Could not find a DNS/Hostname column. Expected: 'DNS' or 'DNS Name'")
    return qid_col, dns_col


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/deduplicate", methods=["POST"])
def deduplicate():
    prev_file = request.files.get("prev_file")
    curr_file = request.files.get("curr_file")

    if not prev_file or not curr_file:
        flash("Please upload both CSV files.", "error")
        return redirect(url_for("index"))

    if not prev_file.filename.endswith(".csv") or not curr_file.filename.endswith(".csv"):
        flash("Both files must be .csv format.", "error")
        return redirect(url_for("index"))

    try:
        prev_df = load_csv(prev_file)
        curr_df = load_csv(curr_file)
    except Exception as e:
        flash(f"Error reading CSV files: {e}", "error")
        return redirect(url_for("index"))

    try:
        prev_qid, prev_dns = resolve_dedup_columns(prev_df)
        curr_qid, curr_dns = resolve_dedup_columns(curr_df)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))

    # Build a set of (QID, DNS) tuples from the previous month
    prev_pairs = set(
        zip(
            prev_df[prev_qid].str.strip().str.lower(),
            prev_df[prev_dns].str.strip().str.lower(),
        )
    )

    curr_key = (
        curr_df[curr_qid].str.strip().str.lower() + "|||" +
        curr_df[curr_dns].str.strip().str.lower()
    )
    prev_key_set = {q + "|||" + d for q, d in prev_pairs}

    is_new = ~curr_key.isin(prev_key_set)
    new_df = curr_df[is_new].copy()

    total_curr = len(curr_df)
    deduped_count = total_curr - len(new_df)
    new_count = len(new_df)

    out = io.BytesIO()
    new_df.to_csv(out, index=False)
    out.seek(0)

    return render_template(
        "result.html",
        total=total_curr,
        removed=deduped_count,
        remaining=new_count,
        download_ready=True,
    ), 200, {
        "X-Total": str(total_curr),
        "X-Removed": str(deduped_count),
        "X-Remaining": str(new_count),
    }


@app.route("/download", methods=["POST"])
def download():
    prev_file = request.files.get("prev_file")
    curr_file = request.files.get("curr_file")

    if not prev_file or not curr_file:
        flash("Session expired. Please re-upload the files.", "error")
        return redirect(url_for("index"))

    prev_df = load_csv(prev_file)
    curr_df = load_csv(curr_file)

    prev_qid, prev_dns = resolve_dedup_columns(prev_df)
    curr_qid, curr_dns = resolve_dedup_columns(curr_df)

    prev_key_set = {
        q.strip().lower() + "|||" + d.strip().lower()
        for q, d in zip(prev_df[prev_qid], prev_df[prev_dns])
    }

    curr_key = (
        curr_df[curr_qid].str.strip().str.lower() + "|||" +
        curr_df[curr_dns].str.strip().str.lower()
    )

    new_df = curr_df[~curr_key.isin(prev_key_set)].copy()

    out = io.BytesIO()
    new_df.to_csv(out, index=False)
    out.seek(0)

    return send_file(
        out,
        mimetype="text/csv",
        as_attachment=True,
        download_name="deduplicated_vulnerabilities.csv",
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
