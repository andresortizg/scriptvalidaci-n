#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
VALIDACIONES EXTERNAS AWS — Compliance Ficohsa (DynamoDB / Parameter Store / Secrets)
═══════════════════════════════════════════════════════════════════════════════

Módulo complementario de compliance_pipeline_v5.py. Valida que los recursos AWS
requeridos por un microservicio existan y cumplan el estándar de nombrado, según
los lineamientos oficiales (ver lineamientos/aws-validaciones/).

Diseño:
  - Resuelve la cuenta AWS a partir del nombre del micro (dominio → account → perfil SSO).
  - Usa boto3 con el perfil SSO correspondiente (nunca credenciales hardcodeadas).
  - Si no hay boto3 o el token SSO no está activo, los checks devuelven estado
    "N/A"/"no_creds" y NO rompen el análisis estático local.

Lineamientos cubiertos (incremental):
  - T24 (01-consumo-wrapper-t24.md): secret + registro DynamoDB + Parameter Store.
  - Regionalization / Homologation: pendientes de nombres de tabla/paths (stubs).

Uso desde el pipeline:
  from aws_checks import run_aws_checks
  results = run_aws_checks(repo_root, micro_name, env="dev")   # lista de dicts
"""

import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from decimal import Decimal


def _jsonable(obj):
    """Normaliza un item DynamoDB a tipos JSON-serializables (Decimal→int/float, set→list)."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, set):
        return [_jsonable(v) for v in obj]
    return obj


DEFAULT_REGION = "us-east-1"

# Dominios conocidos del estándar Ficohsa (segmento del nombre del micro y del clúster EKS).
KNOWN_DOMAINS = ("ic", "ap", "cpm", "ifs", "lc", "rc")

# ── Descubrimiento dinámico del mapeo dominio → account por ambiente ──────────
# NO se hardcodean account IDs ni nombres de perfil: se descubren en cada ejecución
# desde el ~/.kube/config (K8s Lens) y ~/.aws/config de la máquina que ejecuta.
# Esto permite compartir el script entre compañeros con configuraciones distintas.

_KUBE_CONFIG = Path(os.environ.get("KUBECONFIG", str(Path.home() / ".kube" / "config")))
_AWS_CONFIG = Path(os.environ.get("AWS_CONFIG_FILE", str(Path.home() / ".aws" / "config")))

# Patrón del ARN de clúster EKS: arn:aws:eks:<region>:<account>:cluster/ban-xrs-<dom>-eks-cluster(s)-<amb>
_EKS_ARN_RE = re.compile(
    r"arn:aws:eks:([a-z0-9-]+):(\d{12}):cluster/[\w-]*?-([a-z]+)-eks-clusters?-([a-z]+)"
)


def discover_domain_accounts(kube_config: Path = None):
    """Construye {domain: {env: {'account':..., 'region':...}}} leyendo el kubeconfig.
    Se basa en el estándar de nombrado de los clústeres EKS (estable entre máquinas),
    no en los nombres de perfil/contexto (que varían por usuario)."""
    kube_config = kube_config or _KUBE_CONFIG
    mapping = {}
    if not kube_config.exists():
        return mapping
    text = kube_config.read_text(encoding="utf-8", errors="replace")
    for region, account, domain, env in _EKS_ARN_RE.findall(text):
        if domain in KNOWN_DOMAINS:
            mapping.setdefault(domain, {})[env] = {"account": account, "region": region}
    return mapping


def discover_profile_for_account(account_id: str, aws_config: Path = None):
    """Busca en ~/.aws/config el nombre de perfil cuyo sso_account_id == account_id.
    Retorna el nombre de perfil o None. No asume ninguna convención de nombre."""
    aws_config = aws_config or _AWS_CONFIG
    if not account_id or not aws_config.exists():
        return None
    text = aws_config.read_text(encoding="utf-8", errors="replace")
    current = None
    found = None
    for line in text.splitlines():
        mh = re.match(r"\[profile\s+(.+?)\]\s*$", line.strip())
        if mh:
            current = mh.group(1)
            continue
        if current and re.match(rf"\s*sso_account_id\s*=\s*{re.escape(account_id)}\s*$", line):
            found = current
            # No cortamos: preferimos el último match estable, pero el primero suele servir.
            break
    return found


@dataclass
class AwsCheckResult:
    """Resultado de una validación AWS individual."""
    check: str
    status: str                      # ok | fail | na | no_creds | error
    detail: str = ""
    positives: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    records: list = field(default_factory=list)   # items DynamoDB cargados (para el reporte)

    def to_dict(self):
        return {
            "check": self.check, "status": self.status, "detail": self.detail,
            "positives": self.positives, "issues": self.issues,
            "records": self.records,
        }


# ── Resolución de cuenta / perfil ─────────────────────────────────────────────

def resolve_domain(micro_name: str) -> str:
    """Deduce el dominio (ic/ap/cpm/ifs/lc/rc) a partir del nombre del micro.
    Transversales con XRS o IC en el nombre → 'ic' (Integration Composition)."""
    name = micro_name.lower()
    if "xrs" in name or re.search(r"(^|[-_])ic([-_]|$)", name):
        return "ic"
    m = re.match(r"^ms-([a-z]+)-", name)
    if m and m.group(1) in KNOWN_DOMAINS:
        return m.group(1)
    # fallback: buscar cualquier token de dominio conocido en el nombre
    for dom in KNOWN_DOMAINS:
        if re.search(rf"(^|[-_]){dom}([-_]|$)", name):
            return dom
    return "ic"


def resolve_account(micro_name: str, env: str = "dev", domain_accounts=None):
    """Resuelve (domain, account_id, profile_name, region) para un micro/ambiente.
    El mapeo dominio→account se descubre en tiempo de ejecución desde ~/.kube/config,
    y el perfil se descubre desde ~/.aws/config (ambos por máquina). Devuelve None en
    account/profile si no se puede resolver, con el domain siempre presente."""
    domain = resolve_domain(micro_name)
    return resolve_account_for_domain(domain, env, domain_accounts)


def resolve_account_for_domain(domain: str, env: str = "dev", domain_accounts=None):
    """Igual que resolve_account pero para un dominio FIJO (no derivado del nombre).
    Útil para recursos centralizados que viven siempre en una cuenta concreta
    (p. ej. la parametrización DynamoDB/Secrets/Parameter Store vive en 'ic')."""
    if domain_accounts is None:
        domain_accounts = discover_domain_accounts()
    entry = domain_accounts.get(domain, {}).get(env) or {}
    account = entry.get("account")
    region = entry.get("region", DEFAULT_REGION)
    profile = discover_profile_for_account(account) if account else None
    return domain, account, profile, region


def _ensure_boto3():
    """Importa boto3. Si no está en el intérprete actual, intenta añadir el
    site-packages del .venv del proyecto al sys.path (para que el script funcione
    aunque se lance con el python del sistema). Retorna el módulo boto3 o None."""
    try:
        import boto3  # noqa
        return boto3
    except ImportError:
        pass
    # Buscar un .venv en el árbol del proyecto (junto al script o hacia arriba).
    import sys, glob
    here = Path(__file__).resolve()
    candidates = []
    for base in [here.parent, *here.parents]:
        candidates += glob.glob(str(base / ".venv" / "lib" / "python*" / "site-packages"))
        candidates += glob.glob(str(base / "venv" / "lib" / "python*" / "site-packages"))
    for sp in candidates:
        if os.path.isdir(sp) and sp not in sys.path:
            sys.path.insert(0, sp)
            try:
                import boto3  # noqa
                return boto3
            except ImportError:
                continue
    return None


# Permite desactivar el login SSO automático (p. ej. en CI): AWS_SSO_AUTOLOGIN=0
_SSO_AUTOLOGIN = os.environ.get("AWS_SSO_AUTOLOGIN", "1") not in ("0", "false", "no")


def _try_sso_login(profile: str) -> bool:
    """Lanza 'aws sso login --profile <profile>' (abre el navegador para aprobar).
    Retorna True si el comando terminó OK. Requiere la AWS CLI instalada."""
    import shutil, subprocess
    if not shutil.which("aws"):
        return False
    try:
        print(f"🔐  Sesión SSO expirada: lanzando 'aws sso login --profile {profile}' "
              f"(aprueba en el navegador)…")
        r = subprocess.run(["aws", "sso", "login", "--profile", profile], timeout=180)
        return r.returncode == 0
    except Exception:
        return False


def get_boto_session(profile: str, region: str = DEFAULT_REGION):
    """Crea una sesión boto3 con el perfil SSO. Retorna (session, None) si OK,
    o (None, motivo) si falta boto3 o el token SSO no se pudo activar.
    Si el token está expirado, intenta 'aws sso login' automáticamente (una vez)."""
    boto3 = _ensure_boto3()
    if boto3 is None:
        return None, ("boto3 no disponible. Instálalo con:  python3 -m pip install boto3  "
                      "(o crea el venv del proyecto: python3 -m venv .venv && .venv/bin/pip install boto3)")

    def _make_session():
        session = boto3.Session(profile_name=profile, region_name=region)
        session.client("sts").get_caller_identity()  # valida token con llamada barata
        return session

    try:
        return _make_session(), None
    except Exception as e:
        name = type(e).__name__
        # Reintento con login automático (a menos que esté desactivado).
        if _SSO_AUTOLOGIN and _try_sso_login(profile):
            try:
                return _make_session(), None
            except Exception as e2:
                return None, f"credenciales SSO siguen inactivas tras login ({type(e2).__name__})"
        return None, f"credenciales SSO no activas ({name}): ejecutar 'aws sso login --profile {profile}'"


# ── Derivación de operaciones T24 desde el código del micro ───────────────────

def _iter_java(repo_root):
    for f in Path(repo_root).rglob("*.java"):
        s = str(f)
        if "/build/" not in s and "/.git/" not in s and "/test/" not in s:
            yield f


def detect_t24_operations(repo_root):
    """Heurística: detecta consumos a wrappers/adapters T24 en el micro.
    Retorna una lista de nombres de operación (por adapter o por caller-service).
    NOTA: la fuente definitiva de qué operaciones T24 deben existir está pendiente
    de confirmar (adapters vs cm.yaml vs config DynamoDB). Ver lineamiento 01."""
    ops = set()
    for jf in _iter_java(repo_root):
        content = jf.read_text(encoding="utf-8", errors="replace")
        # Adapters que apuntan a T24 / wrappers de core bancario
        if re.search(r"t24|T24|wrapper", content) and jf.name.endswith("Adapter.java"):
            ops.add(jf.stem)  # placeholder: nombre del adapter
    return sorted(ops)


# ═══════════════════════════════════════════════════════════════════════════════
# ESTÁNDAR DE NOMBRADO (runbook 02-gobierno-parametros.md)
# ═══════════════════════════════════════════════════════════════════════════════
# Formato general de recursos: ban-<region>-<dominio>-<tipo>-<recurso>-<env>
#   region : xrs (transversal) | hn | gt | ni | pa | ...  (o combinaciones tipo hn-xx)
#   dominio: ic | ap | cpm | ifs | lc | rc | t24 | ...
#   tipo   : secm | secret  (Secrets Manager) ;  parm | param  (Parameter Store)
#   recurso: token libre con [a-z0-9_-]
#   env    : dev | stg | uat | prd
# El check es tolerante a las variantes (secm/secret, parm/param) y valida estructura,
# no un único literal. Los <env> con placeholder "<env>" en Dynamo se normalizan.

_ENVS = ("dev", "stg", "uat", "prd")

# Grupo de "tipo" según sea secret o parameter store.
_TYPE_SECRET = r"(?:secm|secret)"
_TYPE_PARAM = r"(?:parm|param)"

# Estructura: ban-<seg>-...-<tipo>-...-<env>   (segmentos separados por guiones)
def _naming_regex(type_group: str) -> re.Pattern:
    return re.compile(
        rf"^ban-[a-z0-9]+(?:-[a-z0-9_]+)*-{type_group}-[a-z0-9_]+(?:-[a-z0-9_]+)*-(?:{'|'.join(_ENVS)})$",
        re.IGNORECASE,
    )


_SECRET_NAME_RE = _naming_regex(_TYPE_SECRET)
_PARAM_NAME_RE = _naming_regex(_TYPE_PARAM)


def normalize_resource_name(name: str, env: str) -> str:
    """Reemplaza el placeholder <env> por el ambiente concreto (los registros Dynamo
    usan 'ban-...-<env>'). Devuelve el nombre tal cual si no hay placeholder."""
    if not name:
        return name
    return name.replace("<env>", env).replace("${env}", env)


def validate_secret_name(name: str, env: str = None) -> bool:
    """True si el nombre de secret cumple el estándar (tras normalizar <env>)."""
    n = normalize_resource_name(name, env) if env else name
    return bool(_SECRET_NAME_RE.match(n or ""))


def validate_param_name(name: str, env: str = None) -> bool:
    """True si el nombre de parameter store cumple el estándar (tras normalizar <env>)."""
    n = normalize_resource_name(name, env) if env else name
    return bool(_PARAM_NAME_RE.match(n or ""))


# ═══════════════════════════════════════════════════════════════════════════════
# MODELO DE CLAVE DYNAMODB (runbook 02, sección 3.2)
# ═══════════════════════════════════════════════════════════════════════════════
# pk (countryDomaParamKey) = COUNTRY#{COUNTRY}#DOMAIN#{DOMAIN}#PARAM#{METHOD}
# sk (versionVigenciaKey)  = V#{VERSION}
DYNAMO_PK_ATTR = os.environ.get("DYNAMO_PK_ATTR", "countryDomaParamKey")
DYNAMO_SK_ATTR = os.environ.get("DYNAMO_SK_ATTR", "versionVigenciaKey")

# Tabla de parametrización/regionalización. El nombre real sigue el patrón:
#   ban-xrs-ic-ddb-support-get-params-{env}
# donde {env} se deriva de la rama git del micro (develop→dev, staging→stg, etc.).
# Se puede sobreescribir el patrón completo con DYNAMO_PARAM_TABLE (debe incluir {env}
# o ya venir resuelto), o el nombre exacto vía --dynamo-table.
DYNAMO_TABLE_PATTERN = os.environ.get("DYNAMO_PARAM_TABLE", "ban-xrs-ic-ddb-support-get-params-{env}")

# La parametrización (tabla DynamoDB central, Secrets Manager y Parameter Store con
# prefijo -ic-) está CENTRALIZADA en la cuenta de Integration Composition (ic). Todos
# los micros la consultan ahí, sin importar en qué cuenta/dominio viva el micro.
PARAM_STORE_DOMAIN = os.environ.get("PARAM_STORE_DOMAIN", "ic")

# Mapeo rama git → ambiente. La rama de la que se tomó el código determina el ambiente
# (y por tanto la cuenta AWS, la tabla DynamoDB y el sufijo de secrets/params).
_BRANCH_ENV = {
    "develop": "dev", "development": "dev", "dev": "dev",
    "staging": "stg", "stagging": "stg", "stage": "stg", "stg": "stg",
    "uat": "uat", "qa": "uat",
    "main": "prd", "master": "prd", "production": "prd", "prod": "prd", "prd": "prd",
}


def env_from_branch(branch: str):
    """Deriva el ambiente (dev/stg/uat/prd) a partir del nombre de la rama git.
    Coincidencia exacta primero; si no, por prefijo (p. ej. 'release/uat-x' → uat).
    Retorna None si no se puede mapear."""
    if not branch:
        return None
    b = branch.strip().lower().split("/")[-1]  # toma el último segmento (origin/develop → develop)
    if b in _BRANCH_ENV:
        return _BRANCH_ENV[b]
    for key, env in _BRANCH_ENV.items():
        if b.startswith(key):
            return env
    return None


def resolve_dynamo_table(env: str, explicit: str = None) -> str:
    """Nombre de la tabla DynamoDB para el ambiente. Prioridad:
    1) nombre explícito (--dynamo-table),
    2) patrón DYNAMO_TABLE_PATTERN con {env} sustituido."""
    if explicit:
        return explicit
    if "{env}" in DYNAMO_TABLE_PATTERN:
        return DYNAMO_TABLE_PATTERN.format(env=env)
    return DYNAMO_TABLE_PATTERN


def detect_regionalization_records(repo_root):
    """Extrae de CADA use case sus constantes de regionalización que identifican su
    registro en DynamoDB: COUNTRY, DOMAIN, NAME/METHOD y VERSION. Un micro puede tener
    varios use cases (p. ej. encrypt + decrypt) → varios registros.
    El nombre del método puede declararse como REGIONALIZATION_NAME o REGIONALIZATION_METHOD.
    Retorna lista de dicts {country, domain, name, version} (solo los completos)."""
    patt_country = re.compile(r'REGIONALIZATION_COUNTRY\s*=\s*"([^"]+)"')
    patt_domain  = re.compile(r'REGIONALIZATION_DOMAIN\s*=\s*"([^"]+)"')
    patt_name    = re.compile(r'REGIONALIZATION_(?:NAME|METHOD)\s*=\s*"([^"]+)"')
    patt_version = re.compile(r'REGIONALIZATION_VERSION\s*=\s*"([^"]+)"')
    records = []
    seen = set()
    for jf in _iter_java(repo_root):
        s = str(jf)
        if "/test/" in s or "/build/" in s:
            continue
        content = jf.read_text(encoding="utf-8", errors="replace")
        if "REGIONALIZATION_" not in content:
            continue
        c = patt_country.search(content)
        d = patt_domain.search(content)
        n = patt_name.search(content)
        v = patt_version.search(content)
        if c and d and n:
            rec = {"country": c.group(1), "domain": d.group(1),
                   "name": n.group(1), "version": v.group(1) if v else None}
            key = (rec["country"], rec["domain"], rec["name"], rec["version"])
            if key not in seen:
                seen.add(key)
                records.append(rec)
    return records


def detect_regionalization_keys(repo_root):
    """Compat: retorna el PRIMER registro de regionalización como dict (o {} si no hay).
    Se conserva para usos que solo necesitan saber si hay regionalización."""
    recs = detect_regionalization_records(repo_root)
    return recs[0] if recs else {}


def uses_parametrizacion(repo_root, micro_name=""):
    """Determina si al micro le APLICA la parametrización vía DynamoDB/regionalización.
    NO aplica a Wrappers ni Handlers (por tipo) — esos micros no usan este esquema.
    Aplica si hay señales reales: constantes REGIONALIZATION_* en el código o el bloque
    ficohsa.regionalization en el application.yml. Retorna (aplica: bool, motivo: str)."""
    name = (micro_name or Path(repo_root).name).lower()
    # Exclusión por tipo: wrapper / handler.
    if "wrapper" in name or "-wpr-" in name or "handler" in name or "-hdl-" in name:
        return False, "micro tipo wrapper/handler: no aplica parametrización por DynamoDB"
    # Señal 1: constantes de regionalización en el código.
    if detect_regionalization_keys(repo_root):
        return True, "usa regionalización (constantes REGIONALIZATION_*)"
    # Señal 2: bloque ficohsa.regionalization en el application.yml.
    for f in Path(repo_root).rglob("application*.yml"):
        if "/build/" in str(f):
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if re.search(r"^\s+regionalization:\s*$", txt, re.MULTILINE):
            return True, "declara ficohsa.regionalization en application.yml"
    return False, "el micro no consume regionalización (sin constantes ni ficohsa.regionalization)"


def build_pk(country: str, domain: str, method: str) -> str:
    return f"COUNTRY#{country}#DOMAIN#{domain}#PARAM#{method}"


def build_sk(version: str) -> str:
    v = version if str(version).startswith("V#") else f"V#{version}"
    return v


def extract_resource_refs(dynamo_item: dict):
    """De un item DynamoDB (con 'value' lista de reglas por región) extrae los
    secret_name / param_name referenciados. Retorna (secrets:set, params:set)."""
    secrets, params = set(), set()
    value = dynamo_item.get("value")
    rules = value if isinstance(value, list) else ([value] if isinstance(value, dict) else [])
    # Claves que referencian recursos, según el modelo del runbook y lo observado en vivo:
    #  - secret_name → Secrets Manager
    #  - param_name / circuit-breaker → Parameter Store (el CB de resiliencia es un parámetro)
    secret_keys = ("secret_name", "secretName")
    param_keys = ("param_name", "paramName", "circuit-breaker", "circuitBreaker")
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        # Solo se consideran reglas habilitadas (enabled != false); una regla deshabilitada
        # por región no exige que el recurso exista.
        if rule.get("enabled") is False:
            continue
        for k in secret_keys:
            if rule.get(k):
                secrets.add(rule[k])
        for k in param_keys:
            if rule.get(k):
                params.add(rule[k])
    return secrets, params


# ── Helpers de existencia en AWS (requieren sesión boto3 válida) ──────────────

def _secret_exists(session, name):
    try:
        session.client("secretsmanager").describe_secret(SecretId=name)
        return True
    except Exception:
        return False


def _param_exists(session, name):
    try:
        session.client("ssm").get_parameter(Name=name if name.startswith("/") else f"/{name}")
        return True
    except Exception:
        # reintento sin barra inicial por si el estándar no usa path absoluto
        try:
            session.client("ssm").get_parameter(Name=name)
            return True
        except Exception:
            return False


def _dynamo_get_item(session, table, pk, sk):
    try:
        resp = session.resource("dynamodb").Table(table).get_item(
            Key={DYNAMO_PK_ATTR: pk, DYNAMO_SK_ATTR: sk})
        return resp.get("Item")
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# CHECK: parametrización (DynamoDB → Secret/Parameter), flujo del runbook 02
# ═══════════════════════════════════════════════════════════════════════════════

def check_parametrizacion(repo_root, micro_name, env="dev", table=None):
    """Sigue el flujo de resolución del runbook 02:
      1) Resuelve cuenta/perfil del micro y abre sesión SSO.
      2) (si hay tabla) Lee el/los registro(s) DynamoDB del micro.
      3) Extrae secret_name / param_name de las reglas por región.
      4) Valida que existan en Secrets Manager / Parameter Store.
      5) Valida que sus nombres cumplan el estándar de nombrado.
    Sin tabla o sin credenciales, degrada a 'na'/'no_creds' con detalle claro.

    NOTA: la parametrización (tabla DynamoDB central + Secrets/Parameter Store con
    prefijo -ic-) vive SIEMPRE en la cuenta de Integration Composition (ic), sin
    importar el dominio del micro. Por eso se resuelve la cuenta 'ic', no la del micro."""
    domain, account, profile, region = resolve_account_for_domain(PARAM_STORE_DOMAIN, env)
    micro_domain = resolve_domain(micro_name)
    if not account:
        return AwsCheckResult("parametrizacion", "na",
                              detail=(f"no se pudo resolver la cuenta central '{PARAM_STORE_DOMAIN}' en '{env}' "
                                      f"desde ~/.kube/config (¿tienes el clúster de {PARAM_STORE_DOMAIN} agregado en K8s Lens?)"))
    if not profile:
        return AwsCheckResult("parametrizacion", "na",
                              detail=(f"cuenta {account} (dominio central {PARAM_STORE_DOMAIN}) sin perfil SSO en ~/.aws/config"))

    session, err = get_boto_session(profile, region)
    if err:
        return AwsCheckResult("parametrizacion", "no_creds", detail=err)

    table = resolve_dynamo_table(env, table)
    if not table:
        return AwsCheckResult(
            "parametrizacion", "na",
            detail="no se pudo resolver el nombre de la tabla DynamoDB para el ambiente.",
            positives=[f"cuenta resuelta: {domain}/{account} (perfil {profile}, region {region})"])

    # ¿Le aplica la parametrización a este micro? Wrappers/handlers y micros sin
    # regionalización NO usan este esquema → N/A (no es un fallo).
    aplica, motivo = uses_parametrizacion(repo_root, micro_name)
    if not aplica:
        return AwsCheckResult("parametrizacion", "na", detail=motivo,
                              positives=[f"cuenta {domain}/{account}", f"tabla {table}"])

    # Identificar el/los registro(s) DEL MICRO (no toda la tabla, que es compartida).
    # Cada use case declara sus constantes REGIONALIZATION_* → puede haber VARIOS
    # registros (p. ej. encrypt-data y decrypt-data). El método puede llamarse
    # REGIONALIZATION_NAME o REGIONALIZATION_METHOD.
    pos, iss = [], []
    records = detect_regionalization_records(repo_root)
    items = []
    lookups = []
    missing_lookups = []
    try:
        ddb = session.resource("dynamodb").Table(table)
        from boto3.dynamodb.conditions import Key as _Key
        if records:
            for rk in records:
                pk = build_pk(rk["country"], rk["domain"], rk["name"])
                got = []
                if rk.get("version"):
                    r = ddb.get_item(Key={DYNAMO_PK_ATTR: pk, DYNAMO_SK_ATTR: build_sk(rk["version"])})
                    if r.get("Item"):
                        got = [r["Item"]]
                if not got:
                    r = ddb.query(KeyConditionExpression=_Key(DYNAMO_PK_ATTR).eq(pk))
                    got = r.get("Items", [])
                if got:
                    lookups.append(pk)
                    items.extend(got)
                else:
                    missing_lookups.append(pk)
        else:
            # Sin constantes en código: no podemos ubicar el registro con precisión.
            lookups = ["(sin constantes REGIONALIZATION_* en el código)"]
    except Exception as e:
        return AwsCheckResult("parametrizacion", "error",
                              detail=f"no se pudo leer la tabla {table}: {type(e).__name__}: {e}")

    # Registros esperados (por constantes) que NO existen en DynamoDB → fallo real.
    if missing_lookups:
        for pk in missing_lookups:
            iss.append(f"registro DynamoDB no encontrado: {pk}")

    if not items and not missing_lookups:
        # No hay constantes y no hay nada que ubicar: no verificable → N/A.
        return AwsCheckResult(
            "parametrizacion", "na",
            detail="el micro usa regionalización pero no declara constantes REGIONALIZATION_* "
                   "en el código; no se puede ubicar su registro en DynamoDB para verificar.",
            positives=[f"cuenta central {domain}/{account}", f"tabla {table}",
                       f"dominio del micro: {micro_domain}"])

    # Validar nombrado de los recursos referenciados en los registros.
    all_secrets, all_params = set(), set()
    for it in items:
        s, p = extract_resource_refs(it)
        all_secrets |= s
        all_params |= p

    for sname in sorted(all_secrets):
        norm = normalize_resource_name(sname, env)
        if not validate_secret_name(norm):
            iss.append(f"secret '{sname}' no cumple el estándar de nombrado")
        elif not _secret_exists(session, norm):
            iss.append(f"secret '{norm}' referenciado en Dynamo pero NO existe en Secrets Manager")
        else:
            pos.append(f"secret OK: {norm}")
    for pname in sorted(all_params):
        norm = normalize_resource_name(pname, env)
        if not validate_param_name(norm):
            iss.append(f"param '{pname}' no cumple el estándar de nombrado")
        elif not _param_exists(session, norm):
            iss.append(f"parameter '{norm}' referenciado en Dynamo pero NO existe en Parameter Store")
        else:
            pos.append(f"parameter OK: {norm}")

    found_str = ", ".join(lookups) if lookups else "(ninguno)"
    detail = (f"registros [{found_str}] ({len(items)} ítem/s); "
              f"{len(all_secrets)} secrets / {len(all_params)} params referenciados")
    for pk in lookups:
        pos.insert(0, f"registro DynamoDB OK: {pk}")
    status = "ok" if not iss else "fail"
    if not iss and not all_secrets and not all_params:
        # Registros existen pero sin referencias a validar (regionalización sin recursos).
        status = "ok"
        detail += " — registros presentes, sin referencias secret_name/param_name"
    return AwsCheckResult("parametrizacion", status, detail=detail, positives=pos, issues=iss,
                          records=[_jsonable(it) for it in items])


# ── Regionalización / Homologación: existencia de la Lambda configurada ───────
# Ambas librerías invocan una Lambda (functionName / ARN) que internamente lee DynamoDB.
# Lo verificable desde el micro es que esa Lambda exista en la cuenta.

def _read_app_yml(repo_root):
    for cand in ("applications/app-service/src/main/resources/application.yml",
                 "src/main/resources/application.yml"):
        p = Path(repo_root) / cand
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
    for p in Path(repo_root).rglob("application.yml"):
        if "/build/" not in str(p) and "/test/" not in str(p):
            return p.read_text(encoding="utf-8", errors="replace")
    return ""


def _lambda_exists(session, name_or_arn):
    try:
        session.client("lambda").get_function(FunctionName=name_or_arn)
        return True
    except Exception:
        return False


def _parse_env_placeholder(value: str):
    """Interpreta un valor YAML que puede ser ${VAR:default}, ${VAR}, o un literal.
    Retorna (var_name|None, default|None):
      ${VAR:algo} → ('VAR', 'algo')      ${VAR:} → ('VAR', '')      ${VAR} → ('VAR', None)
      literal     → (None, 'literal')"""
    value = value.strip().strip('"').strip("'").strip()
    m = re.fullmatch(r"\$\{([^:}]+)(?::(.*))?\}", value)
    if m:
        var_name = m.group(1).strip()
        default = m.group(2)  # None si no había ':', '' si era '${VAR:}'
        return var_name, (default if default is None else default.strip())
    return None, value  # literal directo


def _extract_function_name(yml: str, yml_key: str):
    """Busca ficohsa.<yml_key>.{function-name|functionName} en el YAML y devuelve
    (var_name, default) del valor. Acota la búsqueda al sub-bloque para no capturar
    coincidencias sueltas (p. ej. la versión en la lista de librerías). Retorna None
    si el micro no declara esa sección."""
    lines = yml.splitlines()
    # Localiza la línea 'key:' que abre el bloque (p. ej. 'regionalization:' o 'homologator:').
    block_re = re.compile(rf"^(\s*){re.escape(yml_key)}\s*:\s*$")
    fn_re = re.compile(r"^\s*(?:function-name|functionName)\s*:\s*(\S.*?)\s*$")
    for i, line in enumerate(lines):
        mb = block_re.match(line)
        if not mb:
            continue
        base_indent = len(mb.group(1))
        # Recorre las líneas del sub-bloque (indentación mayor a la de la clave).
        for j in range(i + 1, len(lines)):
            nxt = lines[j]
            if not nxt.strip():
                continue
            indent = len(nxt) - len(nxt.lstrip())
            if indent <= base_indent:
                break  # fin del sub-bloque
            mf = fn_re.match(nxt)
            if mf:
                return _parse_env_placeholder(mf.group(1))
    return None


def _check_lambda_backed(check_name, yml_key, repo_root, micro_name, env):
    # Wrappers/handlers no usan regionalización/homologación → N/A por tipo.
    _n = (micro_name or Path(repo_root).name).lower()
    if "wrapper" in _n or "-wpr-" in _n or "handler" in _n or "-hdl-" in _n:
        return AwsCheckResult(check_name, "na",
                              detail=f"micro tipo wrapper/handler: no aplica {check_name}")
    domain, account, profile, region = resolve_account(micro_name, env)
    if not account or not profile:
        return AwsCheckResult(check_name, "na",
                              detail=f"cuenta/perfil no resueltos para dominio '{domain}' en '{env}'")
    yml = _read_app_yml(repo_root)
    # Extrae el function-name/functionName DENTRO del bloque ficohsa.<yml_key>.
    # No basta con buscar la palabra suelta (p. ej. 'webflux-regionalization:2.0.0' en la
    # lista de librerías produciría un falso match). Se busca el sub-bloque y su clave.
    fn = _extract_function_name(yml, yml_key)
    if fn is None:
        return AwsCheckResult(check_name, "na",
                              detail=f"el micro no declara ficohsa.{yml_key}.function-name (no usa {check_name})")

    var_name, default = fn  # (nombre de la env var o None, valor por defecto o None)
    resolved = default if default else None

    if not resolved:
        # function-name viene de una env var con default vacío (${VAR:} o ${VAR}).
        # El ARN real se inyecta en runtime desde el Variable Group / cm.yaml; no es
        # verificable desde el código. N/A (declarado correctamente, sin valor local).
        ref = f"${{{var_name}}}" if var_name else "(env var)"
        return AwsCheckResult(check_name, "na",
                              detail=(f"ficohsa.{yml_key}.function-name viene de {ref} con default vacío; "
                                      f"el ARN se resuelve en runtime desde el Variable Group."),
                              positives=[f"cuenta {domain}/{account}", f"ficohsa.{yml_key}.function-name declarada"])

    # Hay un ARN/valor concreto: verificar que la Lambda exista.
    session, err = get_boto_session(profile, region)
    if err:
        return AwsCheckResult(check_name, "no_creds", detail=err)
    if _lambda_exists(session, resolved):
        return AwsCheckResult(check_name, "ok", detail=f"Lambda '{resolved}' existe",
                              positives=[f"Lambda OK: {resolved}"])
    return AwsCheckResult(check_name, "fail", detail=f"Lambda '{resolved}' NO existe en la cuenta {account}",
                          issues=[f"Lambda '{resolved}' no encontrada"])


def check_regionalization(repo_root, micro_name, env="dev"):
    return _check_lambda_backed("regionalization", "regionalization",
                                repo_root, micro_name, env)


def check_homologation(repo_root, micro_name, env="dev"):
    return _check_lambda_backed("homologation", "homologator",
                                repo_root, micro_name, env)


# ── Orquestador ───────────────────────────────────────────────────────────────

def run_aws_checks(repo_root, micro_name, env="dev", table=None):
    """Ejecuta todas las validaciones AWS disponibles y devuelve una lista de dicts."""
    results = [
        check_parametrizacion(repo_root, micro_name, env, table),
        check_regionalization(repo_root, micro_name, env),
        check_homologation(repo_root, micro_name, env),
    ]
    return [r.to_dict() for r in results]


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Validaciones AWS de compliance (Ficohsa)")
    p.add_argument("repo", help="ruta al repo del micro")
    p.add_argument("--env", default="dev", choices=["dev", "stg", "uat", "prd"])
    p.add_argument("--name", help="nombre del micro (default: nombre de carpeta)")
    p.add_argument("--dynamo-table", default=None, help="nombre de la tabla DynamoDB de parametrización")
    args = p.parse_args()
    name = args.name or Path(args.repo).resolve().name
    out = run_aws_checks(args.repo, name, args.env, args.dynamo_table)
    print(json.dumps(out, ensure_ascii=False, indent=2))
