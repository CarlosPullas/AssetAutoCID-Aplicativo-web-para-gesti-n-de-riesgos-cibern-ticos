\begin{lstlisting}[language=Python, caption={app/server.py - Servidor principal (Flask) + Pipeline + Admin + Reportes}]
# app/server.py
# ------------------------------------------------------------
# Servidor principal del sistema AssetAutoCID.
# Funciones clave:
#  - Carga configuración (config/empresa.json)
#  - Inicializa base de datos SQLite con SQLAlchemy
#  - Expone rutas web (Flask) para:
#       * Valoración de activos (auto por Nmap + manual por JSON)
#       * Identificación de riesgos (amenaza/vulnerabilidad/control)
#       * Tratamiento (ISO/IEC 27002:2022 referencia)
#       * Riesgo residual
#       * Comunicación (Excel + PDF + gráficos)
#       * Monitoreo (Dashboard + Admin con login)
# ------------------------------------------------------------

import json
import os
from datetime import datetime

from flask import (
    Flask, request, redirect, render_template_string, render_template,
    send_file, session
)

# ---- MÓDULOS PROPIOS (lógica del sistema) ----
from modules.scanner import scan                       # Nmap -> hosts/servicios
from modules.classifier import classify_asset           # Clasifica activo por puertos
from modules.cid_engine import cid_for, criticidad, impacto
from modules.excel_generator import generate_excel      # Genera inventario .xlsx
from modules.charts import generate_charts              # Gráficos para reportes
from modules.report_generator import generate_html_report
from modules.pdf_exporter import html_to_pdf

# ---- BASE DE DATOS (SQLAlchemy) ----
from modules.db import db, Asset, Risk, Treatment, Residual, risk_score


# ============================================================
# 1) RUTAS/CONFIGURACIÓN GENERAL DEL PROYECTO
# ============================================================

# BASE_DIR apunta al "root" del proyecto:
#   AssetAutoCID/app/server.py -> subimos 2 niveles
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG_PATH = os.path.join(BASE_DIR, "config", "empresa.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Cargar configuración de empresa (nombre empresa, activos manuales, admin credentials, etc.)
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CFG = json.load(f)


# ============================================================
# 2) INICIALIZAR FLASK + CONFIG TEMPLATES (IMPORTANTE)
# ============================================================

# En estructuras tipo app/server.py, Flask a veces NO detecta templates automáticamente
# Por eso forzamos template_folder = BASE_DIR/templates
app = Flask(__name__, template_folder=TEMPLATES_DIR)

# Secret key para session (login)
app.secret_key = "assetautocid-demo-key"


# ============================================================
# 3) CONFIGURACIÓN SQLITE + CREACIÓN DE TABLAS
# ============================================================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "assetautocid.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# Crea tablas si no existen
with app.app_context():
    db.create_all()


# ============================================================
# 4) HTML SIMPLE PARA HOME (si quieres todo con templates, puedes migrarlo)
# ============================================================

INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AssetAutoCID</title>
  <style>
    body{font-family:Arial;margin:24px;background:#f6f7fb}
    .box{background:#fff;border:1px solid #e6e6e6;border-radius:14px;padding:16px;
         box-shadow:0 10px 28px rgba(0,0,0,.05);max-width:760px}
    input{padding:10px;width:420px;border:1px solid #d7d7d7;border-radius:10px}
    button{padding:10px 14px;border:none;border-radius:10px;background:#2d6cdf;color:#fff;font-weight:700;cursor:pointer}
    button:hover{background:#245ec5}
    a{color:#245ec5;text-decoration:none}
    a:hover{text-decoration:underline}
    .files li{margin:4px 0}
    .msg{margin-top:10px;padding:10px;border-radius:10px;background:#eef2ff;border:1px solid #c7d2fe}
  </style>

  <script>
    // Overlay simple de carga (opcional)
    function showLoading(){
      const ov = document.getElementById("overlay");
      ov.style.display = "flex";
    }
  </script>
</head>
<body>
  <div class="box">
    <h2>AssetAutoCID - Gestión de Riesgos</h2>
    <p>
      <a href="/assets">Activos</a> |
      <a href="/risks">Riesgos</a> |
      <a href="/dashboard">Dashboard</a> |
      <a href="/admin">Admin</a>
    </p>

    <h3>Ejecutar descubrimiento/valoración (Pipeline)</h3>
    <form method="POST" action="/run" onsubmit="showLoading()">
      <label>Target (CIDR o lista):</label><br/>
      <input name="target" value="10.10.10.0/24" required />
      <button type="submit">Ejecutar</button>
    </form>

    {% if msg %}
      <div class="msg"><b>{{ msg }}</b></div>
    {% endif %}

    {% if files %}
      <h3>Archivos generados (output/)</h3>
      <ul class="files">
        {% for f in files %}
          <li><a href="/download?name={{ f }}">{{ f }}</a></li>
        {% endfor %}
      </ul>
    {% endif %}
  </div>

  <div id="overlay" style="display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);
       align-items:center;justify-content:center;z-index:9999;">
    <div style="background:#fff;border-radius:14px;padding:14px 16px;border:1px solid #e6e6e6;
         box-shadow:0 18px 50px rgba(0,0,0,.25);min-width:320px;">
      <b>Ejecutando…</b>
      <p style="color:#666;font-size:12px;margin:6px 0 0;">Escaneo + cálculos + reportes (puede tardar)</p>
    </div>
  </div>
</body>
</html>
"""


# ============================================================
# 5) UTILIDAD: VALIDAR SESIÓN ADMIN
# ============================================================

def require_admin() -> bool:
    """Retorna True si el usuario está autenticado como admin."""
    return session.get("is_admin") is True


# ============================================================
# 6) RUTAS PRINCIPALES
# ============================================================

@app.get("/")
def index():
    # Mostrar últimos archivos generados para descarga rápida
    files = sorted(
        [x for x in os.listdir(OUTPUT_DIR) if x.endswith((".xlsx", ".html", ".pdf", ".png"))],
        reverse=True
    )[:20]
    return render_template_string(INDEX_HTML, msg=None, files=files)


@app.get("/download")
def download():
    """Descarga archivos generados dentro de output/."""
    name = request.args.get("name", "").strip()
    path = os.path.join(OUTPUT_DIR, name)
    if not os.path.exists(path):
        return "Archivo no existe", 404
    return send_file(path, as_attachment=True)


# ============================================================
# 7) PIPELINE PRINCIPAL: /run
#    - Descubre hosts y servicios (Nmap)
#    - Clasifica activos
#    - Calcula CID + criticidad
#    - Inserta/actualiza en DB
#    - Genera Excel + HTML + PDF + gráficos
# ============================================================

@app.post("/run")
def run():
    target = request.form.get("target", "").strip()
    if not target:
        return render_template_string(INDEX_HTML, msg="Target vacío.", files=[])

    # ------------------------------------------
    # 1) Descubrimiento y escaneo de servicios
    # ------------------------------------------
    hosts = scan(target)  # lista de dicts: ip, hostname, open_ports...

    # Preparar listas para outputs
    inventario_rows = []
    cid_rows = []
    activos_for_report = []

    # ------------------------------------------
    # 2) Registrar activos detectados (DB + inventario)
    # ------------------------------------------
    # Generamos IDs tipo A-001, A-002... SOLO para reportes/excel (no para DB)
    idx = 1
    def next_report_id():
        nonlocal idx
        v = f"A-{idx:03d}"
        idx += 1
        return v

    # Ubicación default
    ubic = CFG.get("ubicacion_default", "Oficina principal")
    resp_ti = CFG.get("responsable_ti", "Administrador TI")

    for h in hosts:
        # Clasificación por servicios
        c = classify_asset(h)

        # CID + criticidad
        C, I, D = cid_for(c["tipo"])
        val = criticidad(C, I, D)
        imp = impacto(val)

        report_id = next_report_id()

        # ---- Guardar en DB (Asset) si no existe ----
        # Criterio simple de unicidad: ip (puedes mejorar con hostname+ip)
        ip = c.get("ip", "")
        asset = Asset.query.filter_by(ip=ip).first()
        if not asset:
            asset = Asset(
                ip=ip,
                hostname=c.get("hostname", ""),
                ubicacion=ubic,
                tipo=c["tipo"],
                descripcion=c["descripcion"],
                sensibilidad=c["sensibilidad"],
                criticidad=val,
                created_at=datetime.now()
            )
            db.session.add(asset)
            db.session.commit()
        else:
            # Actualización básica (para mantener DB al día)
            asset.hostname = c.get("hostname", asset.hostname)
            asset.tipo = c["tipo"]
            asset.descripcion = c["descripcion"]
            asset.sensibilidad = c["sensibilidad"]
            asset.criticidad = val
            db.session.commit()

        # ---- Filas para Excel/Reportes ----
        inv_row = {
            "ID": report_id,
            "Ubicación": ubic,
            "Tipo de activo": c["tipo"],
            "Descripción": c["descripcion"],
            "Propietario": "No asignado",
            "Responsable de seguridad": resp_ti,
            "Fecha del registro": datetime.now().strftime("%d/%m/%Y"),
            "Estado": "Activo",
            "Riesgo asociado": c["riesgo"],
            "Sensibilidad": c["sensibilidad"],
            "Criticidad": val
        }
        inventario_rows.append(inv_row)
        cid_rows.append({"ID": report_id, "C": C, "I": I, "D": D, "Valor": val, "Impacto": imp})

        activos_for_report.append({
            "ID": report_id,
            "Ubicación": ubic,
            "Tipo de activo": c["tipo"],
            "Descripción": c["descripcion"],
            "Sensibilidad": c["sensibilidad"],
            "Criticidad": val,
            "Impacto": imp
        })

    # ------------------------------------------
    # 3) Activos manuales (cloud, RRSS, correo, etc.) desde empresa.json
    # ------------------------------------------
    for m in CFG.get("activos_manuales", []):
        tipo = m.get("tipo", "Servicio")
        C, I, D = cid_for(tipo)
        val = criticidad(C, I, D)
        imp = impacto(val)

        report_id = m.get("id") or next_report_id()

        inv_row = {
            "ID": report_id,
            "Ubicación": m.get("ubicacion", "Nube"),
            "Tipo de activo": tipo,
            "Descripción": m.get("descripcion", "Activo manual"),
            "Propietario": m.get("propietario", "No asignado"),
            "Responsable de seguridad": m.get("responsable_seguridad", resp_ti),
            "Fecha del registro": datetime.now().strftime("%d/%m/%Y"),
            "Estado": m.get("estado", "Activo"),
            "Riesgo asociado": m.get("riesgo", "N/A"),
            "Sensibilidad": m.get("sensibilidad", "Interna"),
            "Criticidad": val
        }
        inventario_rows.append(inv_row)
        cid_rows.append({"ID": report_id, "C": C, "I": I, "D": D, "Valor": val, "Impacto": imp})
        activos_for_report.append({
            "ID": report_id,
            "Ubicación": inv_row["Ubicación"],
            "Tipo de activo": inv_row["Tipo de activo"],
            "Descripción": inv_row["Descripción"],
            "Sensibilidad": inv_row["Sensibilidad"],
            "Criticidad": val,
            "Impacto": imp
        })

    # ------------------------------------------
    # 4) Exportación: Excel + HTML + PDF + Charts
    # ------------------------------------------
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xlsx_name = f"inventario_activos_{stamp}.xlsx"
    html_name = f"reporte_activos_{stamp}.html"
    pdf_name  = f"reporte_activos_{stamp}.pdf"

    xlsx_path = os.path.join(OUTPUT_DIR, xlsx_name)
    html_path = os.path.join(OUTPUT_DIR, html_name)
    pdf_path  = os.path.join(OUTPUT_DIR, pdf_name)

    # Excel
    generate_excel(inventario_rows, cid_rows, xlsx_path)

    # Charts (png en output/)
    charts = generate_charts(activos_for_report, OUTPUT_DIR)

    # Reporte HTML + PDF
    generate_html_report(TEMPLATES_DIR, CFG["empresa"], target, activos_for_report, html_path, charts)
    html_to_pdf(html_path, pdf_path, OUTPUT_DIR)

    files = [
        xlsx_name, html_name, pdf_name,
        charts["chart_tipo"], charts["chart_impacto"], charts["chart_sensibilidad"]
    ]

    return render_template_string(INDEX_HTML, msg="Listo: Excel + HTML + PDF + gráficos generados.", files=files)


# ============================================================
# 8) VISTAS PARA ACTIVOS Y RIESGOS (Monitoreo)
# ============================================================

@app.get("/assets")
def assets():
    assets = Asset.query.order_by(Asset.created_at.desc()).all()
    return render_template("pages/assets.html", assets=assets)


@app.get("/risks")
def risks():
    estado = request.args.get("estado", "").strip()
    q = Risk.query
    if estado:
        q = q.filter(Risk.estado == estado)
    risks = q.order_by(Risk.riesgo_inherente.desc()).all()
    return render_template("pages/risks.html", risks=risks)


@app.route("/risks/new", methods=["GET", "POST"])
def risk_new():
    asset_id = request.args.get("asset_id", "").strip()
    asset = Asset.query.get(asset_id)
    if not asset:
        return "Activo no existe", 404

    if request.method == "POST":
        amenaza = request.form.get("amenaza", "").strip()
        vulnerabilidad = request.form.get("vulnerabilidad", "").strip()
        control_existente = request.form.get("control_existente", "").strip() or "N/A"
        prob = int(request.form.get("probabilidad", "3"))
        imp = int(request.form.get("impacto", "3"))
        obs = request.form.get("observaciones", "").strip()
        estado = request.form.get("estado", "Abierto").strip()

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
            estado=estado,
            created_at=datetime.now()
        )
        db.session.add(r)
        db.session.commit()
        return redirect("/risks")

    return render_template("pages/risk_new.html", asset=asset)


@app.route("/treatment/new", methods=["GET", "POST"])
def treatment_new():
    risk_id = int(request.args.get("risk_id", "0"))
    risk = Risk.query.get(risk_id)
    if not risk:
        return "Riesgo no existe", 404

    if request.method == "POST":
        # Estrategia: mitigar/transferir/aceptar/evitar
        estrategia = request.form.get("estrategia", "").strip()

        # Referencia ISO/IEC 27002:2022 (campo manual)
        control_iso = request.form.get("control_iso", "").strip()

        # Control propuesto concreto
        control_prop = request.form.get("control_propuesto", "").strip()

        responsable = request.form.get("responsable", "").strip()
        fecha_obj = request.form.get("fecha_objetivo", "").strip()
        estado_control = request.form.get("estado_control", "Pendiente").strip()

        t = Treatment(
            risk_id=risk.id,
            estrategia=estrategia,
            control_iso=control_iso,
            control_propuesto=control_prop,
            responsable=responsable,
            fecha_objetivo=fecha_obj,
            estado_control=estado_control,
            created_at=datetime.now()
        )
        db.session.add(t)

        # Cambio automático de estado del riesgo (flujo de vida)
        if risk.estado == "Abierto":
            risk.estado = "En tratamiento"

        db.session.commit()
        return redirect("/risks")

    return render_template("pages/treatment_new.html", risk=risk)


@app.route("/residual/new", methods=["GET", "POST"])
def residual_new():
    risk_id = int(request.args.get("risk_id", "0"))
    risk = Risk.query.get(risk_id)
    if not risk:
        return "Riesgo no existe", 404

    if request.method == "POST":
        pr = int(request.form.get("prob_residual", "2"))
        ir = int(request.form.get("imp_residual", "2"))
        fecha = request.form.get("fecha_evaluacion", "").strip() or datetime.now().strftime("%Y-%m-%d")

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
                fecha_evaluacion=fecha,
                created_at=datetime.now()
            )
            db.session.add(res)

        # Aquí puedes opcionalmente marcar como "Verificado" automáticamente
        # si residual baja a cierto umbral
        db.session.commit()
        return redirect("/dashboard")

    return render_template("pages/residual_new.html", risk=risk)


@app.get("/dashboard")
def dashboard():
    abiertos = Risk.query.filter_by(estado="Abierto").count()
    tratamiento = Risk.query.filter_by(estado="En tratamiento").count()
    verificados = Risk.query.filter_by(estado="Verificado").count()
    cerrados = Risk.query.filter_by(estado="Cerrado").count()

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

    kpi = {"abiertos": abiertos, "tratamiento": tratamiento, "verificados": verificados, "cerrados": cerrados}
    return render_template("pages/dashboard.html", kpi=kpi, top=top)


# ============================================================
# 9) LOGIN + ADMIN (Monitoreo y Supervisión)
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", "").strip()
        p = request.form.get("pass", "").strip()

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
    risks = Risk.query.order_by(Risk.riesgo_inherente.desc()).all()

    out = []
    for r in risks:
        res = Residual.query.filter_by(risk_id=r.id).first()
        r.residual = res.riesgo_residual if res else None
        out.append(r)

    return render_template(
        "pages/admin.html",
        empresa=CFG["empresa"],
        total_assets=assets_count,
        total_risks=len(out),
        risks=out
    )


@app.post("/admin/risk/<int:risk_id>/state")
def admin_risk_state(risk_id):
    if not require_admin():
        return redirect("/login")

    r = Risk.query.get(risk_id)
    if not r:
        return "Riesgo no existe", 404

    nuevo = request.form.get("estado", "Abierto").strip()
    r.estado = nuevo
    db.session.commit()
    return redirect("/admin")


# ============================================================
# 10) EJECUCIÓN
# ============================================================

if __name__ == "__main__":
    # host=0.0.0.0 -> permite acceso desde otras PCs en la misma red
    app.run(host="0.0.0.0", port=5000, debug=True)

\end{lstlisting}
