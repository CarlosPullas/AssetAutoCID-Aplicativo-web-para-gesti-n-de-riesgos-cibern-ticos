import json
import os
from datetime import datetime
from flask import Flask, request, render_template_string, send_file,redirect
from flask import session, redirect, render_template

from modules.scanner import scan
from modules.classifier import classify_asset
from modules.cid_engine import cid_for, criticidad, impacto
from modules.excel_generator import generate_excel
from modules.report_generator import generate_html_report
from modules.pdf_exporter import html_to_pdf
from modules.charts import generate_charts
from modules.db import db, Asset, Risk, Treatment, Residual, risk_score
from flask import render_template
from modules.report_full_generator import generate_full_report
from modules.risk_charts import generate_risk_charts
from flask import render_template
import subprocess

def _get_host_ip():
    try:
        out = subprocess.check_output(
            ["bash","-lc","ip -4 addr show | grep -m1 'inet ' | awk '{print $2}' | cut -d/ -f1"],
            text=True
        ).strip()
        return out or "127.0.0.1"
    except Exception:
        return "127.0.0.1"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "empresa.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)
app.secret_key = "assetautocid-demo-key"

# === CONFIGURACIÓN SQLITE ===
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "assetautocid.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()


with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CFG = json.load(f)

INDEX_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>AssetAutoCID</title></head>
<body style="font-family:Arial;margin:24px;">
  <h1>AssetAutoCID - Inventario y Criticidad (CID)</h1>
  <p><b>Empresa:</b> {{ empresa }}</p>

  <form method="POST" action="/run">
    <label>Rango de red (CIDR):</label><br/>
    <input name="target" value="10.10.10.0/24" style="width:320px;" required />
    <button type="submit">Ejecutar</button>
  </form>

  {% if msg %}<p><b>{{ msg }}</b></p>{% endif %}

  {% if files %}
    <h3>Archivos generados</h3>
    <ul>
      {% for f in files %}
        <li><a href="/download?name={{ f }}">{{ f }}</a></li>
      {% endfor %}
    </ul>
  {% endif %}
</body>
</html>
"""

@app.get("/")
def index():
    files = sorted(
        [x for x in os.listdir(OUTPUT_DIR) if x.endswith((".xlsx",".html",".pdf",".png"))],
        reverse=True
    )[:20]

    return render_template(
        "pages/index.html",
        empresa=CFG["empresa"],
        files=files,
        msg=None,
        default_target="10.10.10.0/24",
        host_ip=_get_host_ip()
    )

@app.route("/run", methods=["GET", "POST"])
def run():
    # Si alguien abre /run directo por navegador (GET), lo mandamos al inicio
    if request.method == "GET":
        return redirect("/")

    target = request.form.get("target", "").strip()
    if not target:
        return render_template_string(INDEX_HTML, empresa=CFG["empresa"], msg="Target vacío.", files=[])

    # 1) Escaneo
    hosts = scan(target)

    inventario = []
    calc = []
    activos_for_report = []

    # IDs automáticos A-001, A-002...
    idx = 1
    def next_id():
        nonlocal idx
        aid = f"A-{idx:03d}"
        idx += 1
        return aid

    # 2) Activos detectados por red
    for h in hosts:
        c = classify_asset(h)
        C, I, D = cid_for(c["tipo"])
        val = criticidad(C, I, D)
        imp = impacto(val)
        aid = next_id()

        row = {
            "ID": aid,
            "Ubicación": CFG.get("ubicacion_default", "Oficina principal"),
            "Tipo de activo": c["tipo"],
            "Descripción": c["descripcion"],
            "Propietario": "No asignado",
            "Responsable de seguridad": CFG.get("responsable_ti", "No asignado"),
            "Fecha del registro": datetime.now().strftime("%d/%m/%Y"),
            "Estado": "Activo",
            "Riesgo asociado": c["riesgo"],
            "Sensibilidad": c["sensibilidad"],
            "Criticidad": val
        }

        # Guardar en BD (dentro de la función, con contexto)
        if not Asset.query.get(aid):
            a = Asset(
                id=aid,
                ubicacion=row["Ubicación"],
                tipo=row["Tipo de activo"],
                descripcion=row["Descripción"],
                propietario=row["Propietario"],
                responsable_seguridad=row["Responsable de seguridad"],
                estado=row["Estado"],
                sensibilidad=row["Sensibilidad"],
                criticidad=row["Criticidad"],
                ip=c.get("ip",""),
                hostname=c.get("hostname","")
            )
            db.session.add(a)

        inventario.append(row)
        calc.append({"ID": aid, "C": C, "I": I, "D": D, "Valor": val, "Impacto": imp})
        activos_for_report.append({
            "ID": aid,
            "Ubicación": row["Ubicación"],
            "Tipo de activo": row["Tipo de activo"],
            "Descripción": row["Descripción"],
            "Sensibilidad": row["Sensibilidad"],
            "Criticidad": val,
            "Impacto": imp
        })

    # 3) Activos manuales (cloud) del JSON
    for m in CFG.get("activos_manuales", []):
        tipo = m.get("tipo", "Servicio")
        C, I, D = cid_for(tipo)
        val = criticidad(C, I, D)
        imp = impacto(val)
        aid = m.get("id") or next_id()

        inv_row = {
            "ID": aid,
            "Ubicación": m.get("ubicacion", "Nube"),
            "Tipo de activo": tipo,
            "Descripción": m.get("descripcion", "Activo manual"),
            "Propietario": m.get("propietario", "No asignado"),
            "Responsable de seguridad": m.get("responsable_seguridad", CFG.get("responsable_ti", "No asignado")),
            "Fecha del registro": datetime.now().strftime("%d/%m/%Y"),
            "Estado": m.get("estado", "Activo"),
            "Riesgo asociado": m.get("riesgo", "N/A"),
            "Sensibilidad": m.get("sensibilidad", "Interna"),
            "Criticidad": val
        }

        if not Asset.query.get(aid):
            a = Asset(
                id=aid,
                ubicacion=inv_row["Ubicación"],
                tipo=inv_row["Tipo de activo"],
                descripcion=inv_row["Descripción"],
                propietario=inv_row["Propietario"],
                responsable_seguridad=inv_row["Responsable de seguridad"],
                estado=inv_row["Estado"],
                sensibilidad=inv_row["Sensibilidad"],
                criticidad=inv_row["Criticidad"]
            )
            db.session.add(a)

        inventario.append(inv_row)
        calc.append({"ID": aid, "C": C, "I": I, "D": D, "Valor": val, "Impacto": imp})
        activos_for_report.append({
            "ID": aid,
            "Ubicación": inv_row["Ubicación"],
            "Tipo de activo": inv_row["Tipo de activo"],
            "Descripción": inv_row["Descripción"],
            "Sensibilidad": inv_row["Sensibilidad"],
            "Criticidad": val,
            "Impacto": imp
        })

    db.session.commit()

    # 4) Salidas (Excel + HTML + PDF + charts)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xlsx_name = f"inventario_activos_{stamp}.xlsx"
    html_name = f"reporte_activos_{stamp}.html"
    pdf_name = f"reporte_activos_{stamp}.pdf"

    xlsx_path = os.path.join(OUTPUT_DIR, xlsx_name)
    html_path = os.path.join(OUTPUT_DIR, html_name)
    pdf_path = os.path.join(OUTPUT_DIR, pdf_name)

    generate_excel(inventario, calc, xlsx_path)
    charts = generate_charts(activos_for_report, OUTPUT_DIR)
    generate_html_report(TEMPLATES_DIR, CFG["empresa"], target, activos_for_report, html_path, charts)
    html_to_pdf(html_path, pdf_path, OUTPUT_DIR)

    # ================= INFORME TÉCNICO COMPLETO =================

    risks_db = Risk.query.order_by(Risk.riesgo_inherente.desc()).all()
    treat_db = Treatment.query.all()
    res_db = Residual.query.all()

    riesgos_rows = []
    for r in risks_db:
        riesgos_rows.append({
            "risk_id": r.id,
            "asset_id": r.asset_id,
            "amenaza": r.amenaza,
            "vulnerabilidad": r.vulnerabilidad,
            "control_existente": r.control_existente,
            "probabilidad": r.probabilidad,
            "impacto": r.impacto,
            "inherente": r.riesgo_inherente,
            "estado": r.estado,
            "observaciones": r.observaciones
        })

    trat_rows = []
    for t in treat_db:
        trat_rows.append({
            "risk_id": t.risk_id,
            "estrategia": t.estrategia,
            "control_iso": t.control_iso,
            "control_propuesto": t.control_propuesto,
            "responsable": t.responsable,
            "fecha_objetivo": t.fecha_objetivo,
            "estado_control": t.estado_control
        })

    residual_rows = []
    for rr in res_db:
        residual_rows.append({
            "risk_id": rr.risk_id,
            "prob_residual": rr.prob_residual,
            "imp_residual": rr.imp_residual,
            "riesgo_residual": rr.riesgo_residual,
            "fecha_evaluacion": rr.fecha_evaluacion
        })

    abiertos = Risk.query.filter_by(estado="Abierto").count()
    tratamiento = Risk.query.filter_by(estado="En tratamiento").count()
    cerrados = Risk.query.filter_by(estado="Cerrado").count()
    kpi_riesgos = {"abiertos": abiertos, "tratamiento": tratamiento, "cerrados": cerrados}

    total = len(activos_for_report)
    criticos = sum(1 for a in activos_for_report if a["Criticidad"] >= 14)
    altos = sum(1 for a in activos_for_report if 11 <= a["Criticidad"] <= 13)
    kpi_activos = {"total": total, "criticos": criticos, "altos": altos}

    risk_chart_files = generate_risk_charts(
        risks_rows=[{
            "risk_id": r["risk_id"],
            "asset_id": r["asset_id"],
            "inherente": r["inherente"],
            "residual": next((x["riesgo_residual"] for x in residual_rows if x["risk_id"] == r["risk_id"]), 0),
            "estado": r["estado"],
        } for r in riesgos_rows],
        out_dir=OUTPUT_DIR
    )

    full_html_name = f"informe_tecnico_{stamp}.html"
    full_pdf_name = f"informe_tecnico_{stamp}.pdf"
    full_html_path = os.path.join(OUTPUT_DIR, full_html_name)
    full_pdf_path = os.path.join(OUTPUT_DIR, full_pdf_name)

    charts_for_full = {
        "chart_riesgos_estado": risk_chart_files["chart_riesgos_estado"],
        "chart_top_inherente": risk_chart_files["chart_top_inherente"],
        "chart_inh_vs_res": risk_chart_files["chart_inh_vs_res"],
    }

    generate_full_report(
        template_dir=TEMPLATES_DIR,
        empresa=CFG["empresa"],
        target=target,
        responsable=CFG.get("responsable_ti", "Administrador TI"),
        activos=activos_for_report,
        riesgos=riesgos_rows,
        tratamientos=trat_rows,
        residuals=residual_rows,
        kpi_activos=kpi_activos,
        kpi_riesgos=kpi_riesgos,
        charts=charts_for_full,
        out_path=full_html_path
    )

    html_to_pdf(full_html_path, full_pdf_path, OUTPUT_DIR)

    files = [
        xlsx_name,
        html_name,
        pdf_name,
        charts["chart_tipo"],
        charts["chart_impacto"],
        charts["chart_sensibilidad"]
    ]

    files += [
        full_html_name,
        full_pdf_name,
        risk_chart_files["chart_riesgos_estado"],
        risk_chart_files["chart_top_inherente"],
        risk_chart_files["chart_inh_vs_res"]
    ]

    return render_template(
    "pages/index.html",
    empresa=CFG["empresa"],
    msg="✅ Listo: se generó Excel + reportes + gráficos.",
    files=files,
    default_target=target,
    host_ip=_get_host_ip()
)

@app.get("/download")
def download():
    name = request.args.get("name","")
    path = os.path.join(OUTPUT_DIR, name)
    if not os.path.exists(path):
        return "No existe", 404
    return send_file(path, as_attachment=True)
@app.get("/assets")
def assets():
    assets = Asset.query.order_by(Asset.created_at.desc()).all()
    return render_template("pages/assets.html", assets=assets)

@app.get("/risks")
def risks():
    estado = request.args.get("estado","").strip()
    q = Risk.query
    if estado:
        q = q.filter(Risk.estado == estado)
    risks = q.order_by(Risk.riesgo_inherente.desc()).all()
    return render_template("pages/risks.html", risks=risks)

@app.route("/risks/new", methods=["GET","POST"])
def risk_new():
    asset_id = request.args.get("asset_id","").strip()
    asset = Asset.query.get(asset_id)
    if not asset:
        return "Activo no existe", 404

    if request.method == "POST":
        amenaza = request.form.get("amenaza","").strip()
        vulnerabilidad = request.form.get("vulnerabilidad","").strip()
        control_existente = request.form.get("control_existente","").strip() or "N/A"
        prob = int(request.form.get("probabilidad","3"))
        imp = int(request.form.get("impacto","3"))
        obs = request.form.get("observaciones","").strip()
        estado = request.form.get("estado","Abierto").strip()

        score = risk_score(prob, imp)

        r = Risk(
            asset_id=asset.id,
            amenaza=amenaza,
            vulnerabilidad=vulnerabilidad,
            control_existente=control_existente,
            probabilidad=prob,
            impacto=imp,
            riesgo_inherente=score,
            observaciones=obs,
            estado=estado
        )
        db.session.add(r)
        db.session.commit()
        return redirect("/risks")

    return render_template("pages/risk_new.html", asset=asset)

@app.route("/treatment/new", methods=["GET","POST"])
def treatment_new():
    risk_id = int(request.args.get("risk_id","0"))
    risk = Risk.query.get(risk_id)
    if not risk:
        return "Riesgo no existe", 404

    if request.method == "POST":
        estrategia = request.form.get("estrategia","").strip()
        control_iso = request.form.get("control_iso","").strip()
        control_prop = request.form.get("control_propuesto","").strip()
        responsable = request.form.get("responsable","").strip()
        fecha_obj = request.form.get("fecha_objetivo","").strip()
        estado_control = request.form.get("estado_control","Pendiente").strip()

        t = Treatment(
            risk_id=risk.id,
            estrategia=estrategia,
            control_iso=control_iso,
            control_propuesto=control_prop,
            responsable=responsable,
            fecha_objetivo=fecha_obj,
            estado_control=estado_control
        )
        db.session.add(t)

        # si están tratando el riesgo, cambia estado
        if risk.estado == "Abierto":
            risk.estado = "En tratamiento"

        db.session.commit()
        return redirect("/risks")

    return render_template("pages/treatment_new.html", risk=risk)

@app.route("/residual/new", methods=["GET","POST"])
def residual_new():
    risk_id = int(request.args.get("risk_id","0"))
    risk = Risk.query.get(risk_id)
    if not risk:
        return "Riesgo no existe", 404

    if request.method == "POST":
        pr = int(request.form.get("prob_residual","2"))
        ir = int(request.form.get("imp_residual","2"))
        fecha = request.form.get("fecha_evaluacion","").strip()

        score = risk_score(pr, ir)

        existing = Residual.query.filter_by(risk_id=risk.id).first()
        if existing:
            existing.prob_residual = pr
            existing.imp_residual = ir
            existing.riesgo_residual = score
            existing.fecha_evaluacion = fecha
        else:
            res = Residual(
                risk_id=risk.id,
                prob_residual=pr,
                imp_residual=ir,
                riesgo_residual=score,
                fecha_evaluacion=fecha
            )
            db.session.add(res)

        # si ya se evaluó residual, puede pasar a cerrado (si tú quieres)
        # aquí lo dejamos manual, pero puedes activar esto:
        # risk.estado = "Cerrado"

        db.session.commit()
        return redirect("/dashboard")

    return render_template("pages/residual_new.html", risk=risk)

@app.get("/dashboard")
def dashboard():
    abiertos = Risk.query.filter_by(estado="Abierto").count()
    tratamiento = Risk.query.filter_by(estado="En tratamiento").count()
    cerrados = Risk.query.filter_by(estado="Cerrado").count()

    # Top riesgos por inherente, y si hay residual lo mostramos
    top_risks = Risk.query.order_by(Risk.riesgo_inherente.desc()).limit(5).all()
    top = []
    for r in top_risks:
        res = Residual.query.filter_by(risk_id=r.id).first()
        top.append({
            "risk_id": r.id,
            "asset_id": r.asset_id,
            "inherente": r.riesgo_inherente,
            "residual": res.riesgo_residual if res else "-",
            "estado": r.estado
        })

    kpi = {"abiertos": abiertos, "tratamiento": tratamiento, "cerrados": cerrados}
    return render_template("pages/dashboard.html", kpi=kpi, top=top)
def require_admin():
    return session.get("is_admin") is True

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user","").strip()
        p = request.form.get("pass","").strip()
        if u == CFG.get("admin_user") and p == CFG.get("admin_pass"):
            session["is_admin"] = True
            return redirect("/admin")
        return render_template("pages/login.html", error="Credenciales incorrectas.")
    return render_template("pages/login.html", error=None)

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.get("/admin")
def admin():
    if not require_admin():
        return redirect("/login")

    assets_count = Asset.query.count()
    assets_list = Asset.query.all()  
    risks = Risk.query.order_by(Risk.riesgo_inherente.desc()).all()

    out = []
    for r in risks:
        res = Residual.query.filter_by(risk_id=r.id).first()
        r.residual = res.riesgo_residual if res else None
        out.append(r)

    return render_template(
        "pages/admin.html",
        empresa=CFG["empresa"],
        assets_list=assets_list,
        total_assets=assets_count,
        total_risks=len(out),
        risks=out
    )
@app.route("/admin/edit_asset_cid/<int:asset_id>", methods=["POST"])
def edit_asset_cid(asset_id):
    if not require_admin():
        return redirect("/login")

    C = int(request.form.get("C"))
    I = int(request.form.get("I"))
    D = int(request.form.get("D"))

    # Recalcular criticidad
    val = criticidad(C, I, D)
    imp = impacto(val)

    risk = Risk.query.get_or_404(risk_id)
    risk.C = C
    risk.I = I
    risk.D = D
    risk.criticidad = val
    risk.impacto = imp

    db.session.commit()
    return redirect("/admin")

@app.post("/admin/risk/<int:risk_id>/state")
def admin_risk_state(risk_id):
    if not require_admin():
        return redirect("/login")

    r = Risk.query.get(risk_id)
    if not r:
        return "Riesgo no existe", 404

    nuevo = request.form.get("estado","Abierto").strip()
    r.estado = nuevo
    db.session.commit()
    return redirect("/admin")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
