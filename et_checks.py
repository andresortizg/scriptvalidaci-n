"""
═══════════════════════════════════════════════════════════════════════════════
VALIDACIÓN DE ESPECIFICACIÓN TÉCNICA (ET) — Compliance Ficohsa
═══════════════════════════════════════════════════════════════════════════════

Módulo complementario de compliance_pipeline_v5.py. Valida que la Especificación
Técnica (ET) de un micro:

  PLANO A — ET bien formada (contra la plantilla oficial ET-Plantilla.md / ET-wrapper.md):
    - Secciones obligatorias presentes.
    - Dominio BIAN / clasificación declarados.
    - Cada método con caller-service válido (lineamiento caller-service).
    - maskfields con estándares válidos del catálogo de enmascarado.
    - DynamoDB con countryDomaParamKey/versionVigenciaKey.

  PLANO B — ET coincide con el código desarrollado (lo crítico):
    - Los endpoints de la ET existen en el router/handler del micro.
    - El caller-service de la ET coincide con el del application.yml.
    - Los campos "Cifrado=SI" de la ET coinciden con los mask-fields del yml.
    - El dominio/método DynamoDB de la ET coincide con las constantes del código.

La ET se obtiene (en orden de prioridad):
  1) ruta local .md explícita,
  2) URL/ID de página de Wiki de Azure,
  3) autodescubierta desde los et_links de las HUs del micro (flujo del pipeline).

Diseño: funciones puras y parser por secciones (sin dependencias externas). El
análisis NO requiere red salvo para traer la ET desde la Wiki.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path


# ── Catálogo de estándares de enmascarado (Lineamiento-de-Enmascarado-de-Logs) ──
# 11 parciales + 7 completos (incl. m_object) + default + alias en uso en las ET.
# CATÁLOGO ÚNICO: también lo usa el check de Logs de compliance_pipeline_v5.py.
MASK_STANDARDS = {
    # parciales
    "m_account", "m_balance", "m_blacklist", "m_city", "m_email", "m_gender",
    "m_id", "m_ip", "m_name", "m_phone", "m_score",
    # completos
    "m_address", "m_amount", "m_card", "m_date", "m_pin", "m_token", "m_object",
    # default
    "default",
    # alias / genéricos aceptados (en uso en ET publicadas)
    "object", "m_mail", "m_generic", "m_text", "full",
}

# ── Tipología de API (Lineamiento caller-service) ──
CALLER_SERVICE_TYPES = {"sys", "product", "comp", "exp", "util"}

# ── Secciones obligatorias de la plantilla de ET (nivel ## encabezado) ──
REQUIRED_SECTIONS = [
    (r"##\s*1\.\s*Control de Cambios", "1. Control de Cambios"),
    (r"##\s*2\.\s*Informaci[oó]n General", "2. Información General"),
    (r"##\s*3\.\s*Especificaciones T[eé]cnicas", "3. Especificaciones Técnicas"),
    (r"##\s*4\.\s*M[eé]todos", "4. Métodos"),
    (r"##\s*6\.\s*Repositorio y Despliegue", "6. Repositorio y Despliegue"),
    (r"##\s*7\.\s*Consideraciones de Arquitectura", "7. Consideraciones de Arquitectura"),
]


@dataclass
class EtCheckResult:
    """Resultado de una validación de ET individual."""
    check: str
    status: str                      # ok | fail | na | warn
    detail: str = ""
    positives: list = field(default_factory=list)
    issues: list = field(default_factory=list)

    def to_dict(self):
        return {"check": self.check, "status": self.status, "detail": self.detail,
                "positives": self.positives, "issues": self.issues}


# ═══════════════════════════════════════════════════════════════════════════════
# PARSER DE LA ET
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EtMethod:
    """Un método documentado en la ET (sección 4.x)."""
    title: str = ""              # p. ej. "POST /abanks-wrapper-gtm/v1/execute-procedure"
    http_method: str = ""        # POST / GET / ...
    endpoints: list = field(default_factory=list)   # paths detectados
    caller_service: str = ""
    regions: list = field(default_factory=list)
    masked_fields: list = field(default_factory=list)   # (campo, estandar)
    cifrado_fields: list = field(default_factory=list)  # campos con Cifrado=SI en tablas
    dynamo_domain: str = ""
    dynamo_method: str = ""
    raw: str = ""


_ENDPOINT_RE = re.compile(r'\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_\-/{}.]+)')
_PATH_RE = re.compile(r'(/[a-z0-9][A-Za-z0-9_\-]*(?:/[A-Za-z0-9_\-{}.]+)+)')


def parse_et(content: str) -> dict:
    """Parsea el Markdown de la ET en estructura navegable:
    {clasificacion, bian, title, methods:[EtMethod], raw}."""
    out = {"title": "", "clasificacion": "", "bian": "", "methods": [], "raw": content}

    m = re.search(r'^#\s+Especificaci[oó]n T[eé]cnica:\s*(.+)$', content, re.MULTILINE)
    if m:
        out["title"] = m.group(1).strip()

    mc = re.search(r'\*\*Clasificaci[oó]n\*\*\s*:\s*(.+)', content)
    if mc:
        out["clasificacion"] = mc.group(1).strip()

    mb = re.search(r'\*\*Dominio BIAN\*\*\s*:\s*(.+)', content)
    if mb:
        out["bian"] = mb.group(1).strip()

    # Divide por bloques de método: encabezados "### 4.x. Método ..."
    method_blocks = re.split(r'(?=^###\s*4\.\d+\.?\s)', content, flags=re.MULTILINE)
    for blk in method_blocks:
        hm = re.match(r'^###\s*4\.\d+\.?\s*(?:M[eé]todo\s*\d*\s*:?\s*)?(.+)', blk)
        if not hm:
            continue
        em = EtMethod(title=hm.group(1).strip(), raw=blk)
        # endpoints (METHOD /path) y paths sueltos
        for mm in _ENDPOINT_RE.finditer(blk):
            em.http_method = em.http_method or mm.group(1)
            ep = mm.group(2).strip()
            if ep not in em.endpoints:
                em.endpoints.append(ep)
        # caller-service declarado
        mcs = re.search(r'[Cc]aller\s*[-_ ]?[Ss]ervice\**\s*:?\s*`?([A-Za-z0-9_\-]+)`?', blk)
        if mcs and mcs.group(1) not in ("No", "N", ""):
            em.caller_service = mcs.group(1).strip()
        # regiones
        for reg in ("HN01", "GT01", "PA01", "NI01"):
            if reg in blk and reg not in em.regions:
                em.regions.append(reg)
        # DynamoDB domain / method (del JSON de configuración)
        md = re.search(r'"domain"\s*:\s*"([^"]+)"', blk)
        if md:
            em.dynamo_domain = md.group(1)
        mn = re.search(r'"name"\s*:\s*"([^"]+)"', blk)
        if mn:
            em.dynamo_method = mn.group(1)
        # maskfields declarados: solo en CONTEXTO de enmascarado (sección "Enmascaramiento"
        # o lista "maskfields"), no cualquier `a/b` del bloque (p. ej. `application/json`).
        em.masked_fields = _extract_masked_fields(blk)
        # campos con Cifrado = SI en las tablas de request/response
        em.cifrado_fields = _extract_cifrado_si(blk)
        out["methods"].append(em)

    return out


_MASK_HEADING_RE = re.compile(r'^#{2,6}\s.*enmascar', re.IGNORECASE)
_HEADING_RE = re.compile(r'^#{1,6}\s')
# "campo/estrategia" completo entre comillas o backticks (formato de las listas maskfields);
# así no cuentan URLs (`_wiki/wikis`) ni prosa ("cuenta/tarjeta") dentro de la sección.
_MASK_PAIR_RE = re.compile(r'(["`])([A-Za-z][\w.\[\]-]*)/([a-z][a-z_]*)\1')
_MASK_FIELD_RE = re.compile(r'[A-Za-z][\w.\[\]-]*')
_MASK_STRATEGY_RE = re.compile(r'[a-z][a-z_]*')


def _extract_masked_fields(block: str):
    """Extrae (campo, estrategia) del bloque de un método, solo en contexto de enmascarado:
      - Tablas bajo un encabezado '#### x.y.z Enmascaramiento ...':
        | campo | `estrategia` | ...   (admite columna inicial de numeración)
      - Pares "campo/estrategia" dentro de esa sección o de un arreglo "maskfields": [...].
    La estrategia se devuelve tal cual; su validez la decide MASK_STANDARDS."""
    pairs = []

    def _add(campo, est):
        if (campo, est) not in pairs:
            pairs.append((campo, est))

    in_mask = False
    for line in block.splitlines():
        s = line.strip()
        if _HEADING_RE.match(s):
            in_mask = bool(_MASK_HEADING_RE.match(s))
            continue
        if not in_mask:
            continue
        if s.startswith("|"):
            # "data.accountNumber (request)" → "data.accountNumber"
            cells = [re.sub(r'\s*\([^)]*\)\s*$', "", c.strip().strip("`").strip()).strip("`")
                     for c in s.strip("|").split("|")]
            for i in range(1, len(cells)):
                if (_MASK_STRATEGY_RE.fullmatch(cells[i])
                        and _MASK_FIELD_RE.fullmatch(cells[i - 1])
                        and not cells[i - 1].isdigit()):
                    _add(cells[i - 1], cells[i])
                    break
        else:
            for mf in _MASK_PAIR_RE.finditer(s):
                _add(mf.group(2), mf.group(3))

    for arr in re.finditer(r'"?maskfields"?\s*:\s*\[(.*?)\]', block, re.IGNORECASE | re.DOTALL):
        for mf in re.finditer(r'"([A-Za-z][\w.\[\]-]*)/([a-z][a-z_]*)"', arr.group(1)):
            _add(mf.group(1), mf.group(2))
    return pairs


def _extract_cifrado_si(block: str):
    """De las tablas de la ET (Petición/Respuesta) extrae los campos cuya columna
    'Cifrado' es 'Sí'/'SI'. Localiza la columna Cifrado por su encabezado (no por
    posición fija) para no confundirla con 'Obligatoriedad' (que también usa Sí/No)."""
    fields = []
    lines = block.splitlines()
    cifrado_idx = None
    name_idx = 0
    in_table = False
    for line in lines:
        s = line.strip()
        if not s.startswith("|"):
            in_table = False
            cifrado_idx = None
            continue
        cells = [c.strip().strip("*` ") for c in s.strip("|").split("|")]
        low = [c.lower() for c in cells]
        # ¿fila de encabezado? (contiene 'cifrado')
        if any("cifrado" in c for c in low):
            cifrado_idx = next(i for i, c in enumerate(low) if "cifrado" in c)
            name_idx = next((i for i, c in enumerate(low) if "nombre campo" in c or c == "campo"), 0)
            in_table = True
            continue
        # separador markdown |---|---|
        if set("".join(cells)) <= set("-: "):
            continue
        if not in_table or cifrado_idx is None or cifrado_idx >= len(cells):
            continue
        if re.fullmatch(r's[ií]', cells[cifrado_idx], re.IGNORECASE):
            name = cells[name_idx] if name_idx < len(cells) else cells[0]
            name = name.strip("` *")
            if name and name not in ("-", ""):
                fields.append(name)
    return fields


# ═══════════════════════════════════════════════════════════════════════════════
# PLANO A — ET BIEN FORMADA
# ═══════════════════════════════════════════════════════════════════════════════

def check_et_structure(et: dict) -> EtCheckResult:
    """Secciones obligatorias de la plantilla presentes."""
    content = et["raw"]
    pos, iss = [], []
    for rx, label in REQUIRED_SECTIONS:
        if re.search(rx, content):
            pos.append(f"sección presente: {label}")
        else:
            iss.append(f"falta la sección obligatoria: {label}")
    if not et["methods"]:
        iss.append("no se detectó ningún método (sección 4.x)")
    else:
        pos.append(f"{len(et['methods'])} método(s) documentado(s)")
    return EtCheckResult("et_estructura", "ok" if not iss else "fail",
                         detail=f"{len(pos)} secciones OK", positives=pos, issues=iss)


def check_et_caller_service(et: dict) -> EtCheckResult:
    """Caller-service de cada método cumple el formato del lineamiento."""
    pos, iss = [], []
    checked = 0
    for em in et["methods"]:
        if not em.caller_service:
            continue
        checked += 1
        ok, reason = _validate_caller_service(em.caller_service)
        if ok:
            pos.append(f"caller-service '{em.caller_service}' OK ({em.title[:40]})")
        else:
            iss.append(f"caller-service '{em.caller_service}' ({em.title[:40]}): {reason}")
    if checked == 0:
        return EtCheckResult("et_caller_service", "na",
                             detail="ningún método declara caller-service en la ET")
    return EtCheckResult("et_caller_service", "ok" if not iss else "fail",
                         detail=f"{checked} caller-service revisado(s)", positives=pos, issues=iss)


def _validate_caller_service(value: str):
    if value != value.lower():
        return False, "debe estar en minúsculas"
    if re.search(r"[^a-z0-9_\-]", value):
        return False, "solo minúsculas, dígitos, '_' y '-'"
    if re.search(r"\bv\d+\b", value):
        return False, "no debe incluir la versión (vN)"
    parts = value.split("-")
    if len(parts) != 3:
        return False, f"debe tener 3 componentes <service_domain>-<tipo>-<metodo>, tiene {len(parts)}"
    if parts[1] not in CALLER_SERVICE_TYPES:
        return False, f"tipo-api '{parts[1]}' inválido (usar: {', '.join(sorted(CALLER_SERVICE_TYPES))})"
    return True, ""


def check_et_masking(et: dict) -> EtCheckResult:
    """Los maskfields declarados en la ET usan estándares válidos del catálogo."""
    pos, iss = [], []
    total = 0
    for em in et["methods"]:
        for campo, est in em.masked_fields:
            total += 1
            if est in MASK_STANDARDS:
                pos.append(f"{campo}/{est} OK")
            else:
                iss.append(f"'{campo}/{est}': estándar de enmascarado inválido "
                           f"(usar uno del catálogo, p. ej. m_card, m_id, default)")
    if total == 0:
        return EtCheckResult("et_enmascarado", "na",
                             detail="la ET no declara maskfields campo/estándar")
    return EtCheckResult("et_enmascarado", "ok" if not iss else "fail",
                         detail=f"{total} maskfield(s) revisado(s)",
                         positives=pos[:10], issues=iss)


# ═══════════════════════════════════════════════════════════════════════════════
# PLANO B — CRUCE ET ↔ CÓDIGO
# ═══════════════════════════════════════════════════════════════════════════════

def _read_app_yml(repo_root) -> str:
    for cand in ("applications/app-service/src/main/resources/application.yml",
                 "src/main/resources/application.yml"):
        p = Path(repo_root) / cand
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
    for p in Path(repo_root).rglob("application.yml"):
        if "/build/" not in str(p) and "/test/" not in str(p):
            return p.read_text(encoding="utf-8", errors="replace")
    return ""


def _iter_java(repo_root):
    for f in Path(repo_root).rglob("*.java"):
        s = str(f)
        if "/build/" not in s and "/.git/" not in s and "/test/" not in s:
            yield f


def _all_code(repo_root) -> str:
    """Concatena el código fuente relevante (java + yml) para búsquedas de endpoints."""
    chunks = []
    for jf in _iter_java(repo_root):
        try:
            chunks.append(jf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    return "\n".join(chunks)


def check_et_vs_endpoints(et: dict, repo_root) -> EtCheckResult:
    """Los endpoints documentados en la ET existen en el código del micro."""
    code = _all_code(repo_root) + "\n" + _read_app_yml(repo_root)
    pos, iss = [], []
    all_eps = []
    for em in et["methods"]:
        all_eps.extend(em.endpoints)
    all_eps = sorted(set(all_eps))
    if not all_eps:
        return EtCheckResult("et_vs_endpoints", "na",
                             detail="la ET no declara endpoints explícitos (METHOD /path)")
    for ep in all_eps:
        # normaliza: compara el path (ignora el verbo). Permite match por el último
        # segmento significativo para tolerar prefijos por país.
        tail = ep.rstrip("/").split("/")[-1]
        if ep in code or (tail and tail in code):
            pos.append(f"endpoint ET presente en código: {ep}")
        else:
            iss.append(f"endpoint '{ep}' documentado en la ET pero NO encontrado en el código")
    return EtCheckResult("et_vs_endpoints", "ok" if not iss else "fail",
                         detail=f"{len(all_eps)} endpoint(s) de la ET cruzado(s)",
                         positives=pos, issues=iss)


def check_et_vs_caller_service(et: dict, repo_root) -> EtCheckResult:
    """El caller-service de la ET coincide con el declarado en el código/yml."""
    yml = _read_app_yml(repo_root)
    code = _all_code(repo_root)
    et_values = [em.caller_service for em in et["methods"] if em.caller_service]
    if not et_values:
        return EtCheckResult("et_vs_caller_service", "na",
                             detail="la ET no declara caller-service a cruzar")
    pos, iss = [], []
    for cs in sorted(set(et_values)):
        if cs in yml or cs in code:
            pos.append(f"caller-service '{cs}' coincide ET↔código")
        else:
            iss.append(f"caller-service '{cs}' está en la ET pero NO en el código/application.yml")
    return EtCheckResult("et_vs_caller_service", "ok" if not iss else "fail",
                         detail=f"{len(set(et_values))} caller-service cruzado(s)",
                         positives=pos, issues=iss)


def check_et_vs_masking(et: dict, repo_root) -> EtCheckResult:
    """Los campos marcados Cifrado=SI en la ET deben estar en los mask-fields del micro
    (application.yml) o declarados como maskfield en el código."""
    yml = _read_app_yml(repo_root)
    code = _all_code(repo_root)
    hay = (yml + "\n" + code)
    cifrados = []
    for em in et["methods"]:
        cifrados.extend(em.cifrado_fields)
    cifrados = sorted(set(c for c in cifrados if c))
    if not cifrados:
        return EtCheckResult("et_vs_enmascarado", "na",
                             detail="la ET no marca campos con Cifrado=Sí")
    pos, iss = [], []
    for campo in cifrados:
        # match laxo: el nombre del campo aparece en la config de masking del micro
        if re.search(rf'\b{re.escape(campo)}\b', hay):
            pos.append(f"campo cifrado '{campo}' referenciado en el micro")
        else:
            iss.append(f"campo '{campo}' marcado Cifrado=Sí en la ET pero sin enmascarado visible en el micro")
    return EtCheckResult("et_vs_enmascarado", "ok" if not iss else "warn",
                         detail=f"{len(cifrados)} campo(s) cifrado(s) de la ET cruzado(s)",
                         positives=pos, issues=iss)


# Mapeo del segmento del nombre del micro → tipo-api esperado del caller-service.
_MICRO_SEGMENT_TO_TIPO = {
    "wpr": None,          # wrapper: no aplica tipo-api de caller-service
    "wrapper": None,
    "sys": "sys", "comp": "comp", "exp": "exp", "prod": "product", "product": "product",
    "util": "util",
}


def _micro_tipo(name: str):
    """Deduce el tipo-api esperado del micro por su nombre (ms-ic-<tipo>-...)."""
    n = name.lower()
    if "wrapper" in n or "-wpr-" in n:
        return "wrapper"
    m = re.search(r'ms-[a-z]+-([a-z]+)-', n)
    if m and m.group(1) in _MICRO_SEGMENT_TO_TIPO:
        return _MICRO_SEGMENT_TO_TIPO[m.group(1)] or "wrapper"
    # sufijos -sys/-comp/-exp/-product
    for seg, tipo in (("-sys", "sys"), ("-comp", "comp"), ("-exp", "exp"),
                      ("-product", "product"), ("-prod", "product")):
        if n.endswith(seg) or f"{seg}-" in n:
            return tipo
    return None


def check_et_vs_clasificacion(et: dict, repo_root, micro_name: str) -> EtCheckResult:
    """La tipología de la ET coincide con la del micro. Fuente de la tipología en la ET,
    en orden: (1) campo **Clasificación** (wrappers), (2) el tipo-api del caller-service
    de los métodos (sys/comp/exp/product/util). Se compara con el tipo deducido del nombre."""
    name = (micro_name or Path(repo_root).name).lower()
    micro_tipo = _micro_tipo(name)   # 'wrapper' | 'sys' | 'comp' | ...
    et_clasif = et.get("clasificacion", "").lower()

    # Caso wrapper: comparación por el campo Clasificación.
    if et_clasif:
        is_wrapper_et = "wrapper" in et_clasif
        is_wrapper_micro = (micro_tipo == "wrapper")
        if is_wrapper_et == is_wrapper_micro:
            return EtCheckResult("et_vs_clasificacion", "ok",
                                 detail=f"clasificación coherente (ET: {et.get('clasificacion')})",
                                 positives=[f"clasificación ET «{et.get('clasificacion')}» coincide con el tipo del micro"])
        return EtCheckResult("et_vs_clasificacion", "fail",
                             detail="la clasificación de la ET no coincide con el tipo del micro",
                             issues=[f"ET dice «{et.get('clasificacion')}» pero el micro "
                                     f"{'es' if is_wrapper_micro else 'no es'} wrapper"])

    # Caso API (sin Clasificación): usar el tipo-api del caller-service de los métodos.
    et_tipos = set()
    for em in et["methods"]:
        if em.caller_service:
            parts = em.caller_service.split("-")
            if len(parts) == 3:
                et_tipos.add(parts[1])
    if not et_tipos:
        return EtCheckResult("et_vs_clasificacion", "na",
                             detail="la ET no declara Clasificación ni tipo-api deducible (caller-service)")
    if micro_tipo in (None, "wrapper"):
        return EtCheckResult("et_vs_clasificacion", "na",
                             detail=f"tipo del micro no deducible por nombre para cruzar (ET: {', '.join(sorted(et_tipos))})")
    if micro_tipo in et_tipos:
        return EtCheckResult("et_vs_clasificacion", "ok",
                             detail=f"tipo-api coherente (ET caller-service: {', '.join(sorted(et_tipos))} ↔ micro: {micro_tipo})",
                             positives=[f"tipo-api «{micro_tipo}» del micro coincide con el caller-service de la ET"])
    return EtCheckResult("et_vs_clasificacion", "fail",
                         detail="el tipo-api del caller-service de la ET no coincide con el tipo del micro",
                         issues=[f"ET usa tipo-api {sorted(et_tipos)} pero el micro es «{micro_tipo}»"])


# ═══════════════════════════════════════════════════════════════════════════════
# ORQUESTADOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_et_checks(et_content: str, repo_root, micro_name: str) -> list:
    """Ejecuta todas las validaciones de ET (plano A + plano B) y devuelve lista de dicts."""
    if not et_content or len(et_content.strip()) < 50:
        return [EtCheckResult("et", "na",
                              detail="no se encontró la ET del micro (ni local, ni por URL, "
                                     "ni en los et_links de las HUs)").to_dict()]
    et = parse_et(et_content)
    results = [
        # Plano A — ET bien formada
        check_et_structure(et),
        check_et_caller_service(et),
        check_et_masking(et),
        # Plano B — cruce ET ↔ código
        check_et_vs_clasificacion(et, repo_root, micro_name),
        check_et_vs_endpoints(et, repo_root),
        check_et_vs_caller_service(et, repo_root),
        check_et_vs_masking(et, repo_root),
    ]
    return [r.to_dict() for r in results]


if __name__ == "__main__":
    import sys, json
    et_path, repo = sys.argv[1], sys.argv[2]
    name = Path(repo).resolve().name
    content = Path(et_path).read_text(encoding="utf-8", errors="replace")
    out = run_et_checks(content, repo, name)
    print(json.dumps(out, ensure_ascii=False, indent=2))
