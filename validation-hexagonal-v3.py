#!/usr/bin/env python3
"""
Validador de Arquitectura Hexagonal v3 - Arquetipo Ficohsa WebFlux (Spring Boot 4)
==================================================================================
Base estructural: validate_hexagonal.py (v1). Reglas actualizadas al arquetipo destino
del TD `ficohsa-springboot3-to-4-migration` (spec td-hexagonal-guidelines-update,
reglas finales Wave 1-4 post-supersession).

Cambios de reglas respecto a v1 (Spring Boot 3):
    - Paquetes: com.ficohsa.model (NO domain.model), com.ficohsa.ports.in / ports.out,
      com.ficohsa.usecase, com.ficohsa.api(.handlers/.dto/.mappers/.openapi),
      com.ficohsa.driven.<name>.{adapter,config,dto,mapper}, com.ficohsa.helper, com.ficohsa.
    - Handlers en paquete PLURAL com.ficohsa.api.handlers (SUPERSEDE singular handler).
    - Módulos driven `<name>-client-api` (SUPERSEDE `<name>-client`).
    - Sin excepciones custom del proyecto; solo librería com.ficohsa.lib.core.exception.* (D2 2.2).
    - Jackson 3: prohibido com.fasterxml.jackson.{databind,core,datatype}; annotation permitido;
      prohibido withCoercionConfigFor.
    - @FicohsaResilience: modo deprecado (label/paramName/paramLabel) prohibido;
      instanceName cb-<sistema>-<capacidad> desaconsejado (debe ser el nombre del método).
    - Caller-Service se propaga automáticamente: prohibido setearlo manualmente.
    - DTOs record; anotaciones JSON preserve-if-present (NO se exigen).
    - RouterRest: envelope RequestModel<D>, sin getRequestType().

Uso:
    python validation-hexagonal-v3.py <ruta-del-repositorio>
    python validation-hexagonal-v3.py <ruta-del-repositorio> --report json
    python validation-hexagonal-v3.py <ruta-del-repositorio> --report html
    python validation-hexagonal-v3.py <ruta-del-repositorio> --only errors --fail-on-errors
"""

import sys
import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone, timedelta
from enum import Enum


# ─────────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────────

class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class Violation:
    severity: Severity
    rule: str
    file: str
    message: str
    line: Optional[int] = None

    def __str__(self):
        loc = f"{self.file}" + (f":{self.line}" if self.line else "")
        return f"[{self.severity.value}] {self.rule}\n  → {loc}\n  → {self.message}"


@dataclass
class ValidationResult:
    violations: list = field(default_factory=list)
    repo_name: str = ""
    repo_path: str = ""

    def add(self, severity: Severity, rule: str, file: str, message: str, line: int = None):
        self.violations.append(Violation(severity, rule, file, message, line))

    @property
    def errors(self):
        return [v for v in self.violations if v.severity == Severity.ERROR]

    @property
    def warnings(self):
        return [v for v in self.violations if v.severity == Severity.WARNING]

    @property
    def infos(self):
        return [v for v in self.violations if v.severity == Severity.INFO]

    def summary(self):
        return f"{len(self.errors)} errores, {len(self.warnings)} advertencias, {len(self.infos)} infos"


# ─────────────────────────────────────────────
# MENSAJES DE VALIDACIÓN CENTRALIZADOS
# ─────────────────────────────────────────────

class Messages:
    # ── Model (D2 2.1) ──
    MODEL_NO_SPRING_ANNOTATION = "El modelo tiene @{annotation} — solo Lombok está permitido en domain/model (D2 2.1)"
    MODEL_NO_SPRING_IMPORT     = "Import de Spring prohibido en model (solo *.validation): {imp} (D2 2.1)"
    MODEL_LAYER_VIOLATION      = "Import de capa prohibida en model: {imp} (D2 2.1)"
    MODEL_WRONG_PACKAGE        = "Package '{pkg}' no corresponde a '{expected_pkg}' — el arquetipo SB4 usa com.ficohsa.model (NO com.ficohsa.domain.model)"

    # ── Exception (D2 2.2) ──
    PROJECT_CUSTOM_EXCEPTION   = "'{name}' es una excepción custom del proyecto — prohibido (D2 2.2). Use la librería Ficohsa (com.ficohsa.lib.core.exception.*) vía error-mapping"
    PROJECT_EXCEPTION_PACKAGE  = "Paquete de excepciones propio prohibido: '{pkg}' (D2 2.2)"

    # ── Port IN (D2 2.3) ──
    PORT_IN_MUST_BE_INTERFACE  = "'{name}' debe ser una interfaz (in-port)"
    PORT_IN_PREFIX             = "'{name}' debe tener prefijo 'I' (in-port, ej: I{name})"
    PORT_IN_NO_GATEWAY         = "'{name}' es in-port pero termina en 'Gateway' — los in-ports no llevan sufijo Gateway (D2 2.3)"
    PORT_IN_LAYER_VIOLATION    = "Import prohibido en in-port: {imp} (no puede importar usecase/api/driven) (D2 2.3)"
    PORT_IN_WRONG_PACKAGE      = "Package '{pkg}' debería estar bajo '{expected_pkg}'"
    PORT_IN_NO_REACTIVE        = "Los métodos del in-port deberían retornar Mono<> o Flux<>"

    # ── Port OUT (D2 2.4) ──
    PORT_OUT_MUST_BE_INTERFACE = "'{name}' debe ser una interfaz (out-port)"
    PORT_OUT_SUFFIX            = "'{name}' debe terminar en 'Gateway' (out-port)"
    PORT_OUT_NO_I_PREFIX       = "'{name}' es out-port pero tiene prefijo 'I' — los out-ports no llevan prefijo I (D2 2.4)"
    PORT_OUT_LAYER_VIOLATION   = "Import prohibido en out-port: {imp} (no puede importar usecase/api/driven) (D2 2.4)"
    PORT_OUT_WRONG_PACKAGE     = "Package '{pkg}' debería estar bajo '{expected_pkg}'"
    PORT_OUT_NO_REACTIVE       = "Los métodos del out-port deberían retornar Mono<> o Flux<>"
    PORT_OUT_INFRA_TYPE        = "Firma de out-port contiene tipo de infraestructura prohibido '{typ}' — la URI resuelta se pasa como String (D2 2.4 / Req 2.3)"
    PORT_OUT_SYSTEM_NAME       = "'{name}' filtra el nombre del sistema externo ('{sysname}') — los out-ports se nombran por entidad/acción, no por sistema (port rename table)"

    # ── Ports folder (D2 2.5) ──
    PORTS_INVALID_SUBFOLDER    = "Subcarpeta prohibida en ports/: '{subfolder}'. Solo in/ y out/ (D2 2.5)"
    PORT_UNKNOWN_CONVENTION    = "'{name}' en ports/ no sigue convención: in-ports prefijo 'I', out-ports sufijo 'Gateway' (D2 2.5)"

    # ── UseCase (D2 2.6) ──
    USECASE_NOT_INTERFACE      = "'{name}' en usecase no debe ser interfaz"
    USECASE_SUFFIX             = "'{name}' debe terminar en 'UseCase'"
    USECASE_NO_SERVICE         = "'{name}' tiene @Service — debe usar @Component (nunca @Service) (D2 2.6)"
    USECASE_NO_COMPONENT       = "'{name}' debería anotarse con @Component"
    USECASE_NO_REQUIRED_ARGS   = "'{name}' debería usar @RequiredArgsConstructor (D2 2.6)"
    USECASE_NO_INPORT          = "'{name}' debe implementar un in-port con prefijo I (ej: I{name}) (D2 2.6)"
    USECASE_LAYER_VIOLATION    = "Import prohibido en usecase: {imp} (no puede importar api/driven) (D2 2.6)"
    USECASE_SPRING_IMPORT      = "Use case importa Spring ({imp}) — la capa de dominio debe estar libre de framework (Req 3.2)"
    USECASE_PRIVATE_LEAK       = "Use case importa subpaquete privado de un adapter: '{imp}' — muévelo a com.ficohsa.model si es dominio (D2 2.6)"
    USECASE_WRONG_PACKAGE      = "Package '{pkg}' debería estar bajo '{expected_pkg}'"

    # ── Handler (D2 2.7) ──
    HANDLER_SUFFIX             = "'{name}' debe terminar en 'Handler'"
    HANDLER_CONCRETE_USECASE   = "Handler inyecta la clase concreta '{name}' — debe inyectar la interfaz 'I{name}' (D2 2.7)"
    HANDLER_LAYER_VIOLATION_DA = "Handler importa driven-adapter: {imp} (prohibido) (D2 2.7)"
    HANDLER_LAYER_VIOLATION_UC = "Handler importa implementación de use case: {imp} — debe usar la interfaz (D2 2.7)"
    HANDLER_PRIVATE_LEAK       = "Handler importa DTO/helper privado de un adapter: '{imp}' (D2 2.7)"
    HANDLER_WRONG_PACKAGE      = "Package '{pkg}' debería ser '{expected_pkg}' (paquete PLURAL 'handlers', SUPERSEDE 'handler' singular)"
    HANDLER_APPLICATION_ID     = "Handler usa applicationId para logging — debe usar correlationId vía ctx.correlationId() (Req 21.2)"

    # ── DTO (D2 2.8) ──
    DTO_SUFFIX                 = "'{name}' debe terminar en 'Dto' (no 'DTO')"
    DTO_MUST_BE_RECORD         = "'{name}' debe ser un Java record (D2 2.8)"
    DTO_WRONG_PACKAGE          = "Package '{pkg}' debería estar bajo '{expected_pkg}'"

    # ── Mapper (D2 2.9) ──
    MAPPER_MUST_BE_INTERFACE   = "'{name}' debe ser una interfaz MapStruct (D2 2.9)"
    MAPPER_SUFFIX              = "'{name}' debe terminar en 'Mapper'"
    MAPPER_ANNOTATION          = "'{name}' debe tener @Mapper(componentModel = \"spring\") (D2 2.9)"
    MAPPER_SPRING_MODEL        = "'{name}' debería usar @Mapper(componentModel = \"spring\")"
    MAPPER_WRONG_PACKAGE       = "Package '{pkg}' debería estar bajo '{expected_pkg}'"

    # ── Adapter (D2 2.10) ──
    ADAPTER_NOT_INTERFACE      = "'{name}' en adapter no debe ser interfaz"
    ADAPTER_SUFFIX             = "'{name}' debe terminar en 'Adapter' o 'Repository'"
    ADAPTER_ANNOTATION         = "'{name}' debería tener @Component o @Repository"
    ADAPTER_NO_GATEWAY         = "'{name}' debe implementar un out-port (*Gateway) (D2 2.10)"
    ADAPTER_LAYER_VIOLATION    = "Adapter importa entry-point (api): {imp} (prohibido) (D2 2.10)"
    ADAPTER_CROSS_DEPENDENCY   = "'{name}' importa de otro adapter: {imp} (D2 2.10)"
    ADAPTER_PRIVATE_LEAK       = "'{name}' accede al subpaquete privado 'dto' de otro adapter: '{imp}' (D2 2.10)"
    ADAPTER_MANUAL_CALLER_SVC  = "Adapter setea 'Caller-Service' manualmente — se propaga automáticamente por webflux-web-client (Req 57)"
    ADAPTER_NO_LOG_EXTERNAL    = "'{name}' no usa @LogExternalCall(provider = ...) — obligatorio en métodos outbound (Req 57.4)"

    # ── Adapter Config ──
    PROPS_CONFIG_MUST_BE_RECORD = "'{name}' debe ser un Java record (config props)"
    PROPS_CONFIG_ANNOTATION     = "'{name}' debe tener @ConfigurationProperties"
    CLIENT_CONFIG_ANNOTATION    = "'{name}' debe tener @Configuration"
    ADAPTER_CONFIG_NAMING       = "'{name}' en config/ debería terminar en 'Properties' (@ConfigurationProperties), 'PropsConfig' o 'ClientConfig'"

    # ── Router (D2 2.11) ──
    ROUTER_NAME                = "El router debe llamarse EXACTAMENTE 'RouterRest', no '{name}' (D2 2.11)"
    ROUTER_NO_CONFIGURATION    = "'RouterRest' debe tener @Configuration (D2 2.11)"
    ROUTER_LAYER_VIOLATION_DA  = "RouterRest importa driven-adapter: {imp} (prohibido) (D2 2.11)"
    ROUTER_LAYER_VIOLATION_UC  = "RouterRest importa implementación de use case: {imp} — debe usar interfaces (D2 2.11)"
    ROUTER_GET_REQUEST_TYPE    = "RouterRest usa getRequestType() — debe eliminarse en favor de RequestModel<D> (Req 22.2)"
    ROUTER_NO_ENVELOPE         = "RouterRest debería deserializar el envelope vía ParameterizedTypeReference<RequestModel<...>> (Req 22)"

    # ── Main (D2 2.12) ──
    MAIN_ANNOTATION_MISSING    = "MainApplication debe usar @{annotation} (D2 2.12)"
    MAIN_ANNOTATION_FORBIDDEN  = "Prohibido @SpringBootApplication — usar @{annotation} (D2 2.12)"
    MAIN_WRONG_PACKAGE         = "MainApplication debe estar en el paquete raíz '{expected_pkg}', no en '{pkg}' (D2 2.12)"

    # ── Helper (D2 2.15) ──
    HELPER_DRIVEN_IMPORT       = "Helper importa driven-adapter: {imp}"
    HELPER_WRONG_PACKAGE       = "Package '{pkg}' debería estar bajo '{expected_pkg}' (com.ficohsa.helper) (D2 2.15)"
    REGIONALIZATION_PROPERTIES = "'{name}' es propiedades de regionalización por operación (@ConfigurationProperties) — RETIRADA: country/domain/name deben ser constantes in-code en el use case (Req 49)"

    # ── Jackson 3 (A1) ──
    JACKSON2_IMPORT            = "Import de Jackson 2 prohibido: {imp} — migrar a tools.jackson.* (Jackson 3, A1)"
    JACKSON_COERCION_FOR       = "Uso de .withCoercionConfigFor(...) (Jackson 2) — debe ser .withCoercionConfig(...) (Req 7.3)"

    # ── Resilience (Component 6 / Req 61) ──
    RESILIENCE_DEPRECATED_MODE = "@FicohsaResilience usa modo deprecado ('{attr}') — prohibido (Req 6.4)"
    RESILIENCE_INSTANCE_CB     = "@FicohsaResilience instanceName = '{val}' parece cb-<sistema>-<capacidad> — el valor final debe ser el nombre del método del endpoint (Req 61.1)"

    # ── Transversales ──
    NO_FIELD_AUTOWIRED         = "Usar inyección por constructor (@RequiredArgsConstructor), no @Autowired en campo"
    NO_BLOCKING_CALLS          = "Uso de .block()/.blockFirst()/.blockLast() prohibido: '{line}'"
    NO_BLOCKING_CALLS_WARNING  = "Posible uso de .block() en helper: '{line}'"

    # ── Estructura del proyecto ──
    MISSING_REQUIRED_FILE      = "Archivo obligatorio no encontrado: {path}"
    FORBIDDEN_FILE             = "Archivo prohibido por el arquetipo: {filename}"
    MISSING_MODULE             = "Módulo obligatorio no encontrado: {module}"
    LOMBOK_CONFIG_MISSING      = "Falta '{prop}' en lombok.config"
    LOGGING_CONFIG_FORBIDDEN   = "Config de logging propia: '{filename}' — debe eliminarse, la librería la provee (D2 2.13)"
    INFRA_FOLDER_TYPO          = "Carpeta de infraestructura mal escrita: '{found}' — el nombre correcto es exactamente 'infrastructure' (D2 2.13)"
    DRIVEN_MODULE_OLD_NAMING   = "Módulo driven '{found}' usa naming antiguo — debe ser '{expected}' (sufijo -client-api, Req 45)"
    FORBIDDEN_MODULE           = "Módulo prohibido: '{module}'"

    # ── Strings hardcodeados (D2 2.14) ──
    HARDCODED_URL              = "URL/endpoint hardcodeado: {value!r} — debe venir de @ConfigurationProperties o env (D2 2.14)"
    HARDCODED_IP               = "IP/host hardcodeado: {value!r} — debe venir de configuración externa (D2 2.14)"
    HARDCODED_LONG_STRING      = "String largo hardcodeado ({length} chars): {preview!r}... — considerar constante o recurso"

    # ── Seguridad — gradle.properties (D2 2.14) ──
    GRADLE_CREDENTIAL_EXPOSED  = "Credencial expuesta en gradle.properties: '{key}' con valor real — usar placeholder {key}=$({key})"
    GRADLE_CREDENTIAL_COMMENTED = "Credencial comentada con valor real en gradle.properties: '{key}' — incluso comentada es riesgo"


# ─────────────────────────────────────────────
# HELPERS DE ANÁLISIS DE JAVA
# ─────────────────────────────────────────────

def get_declared_package_from_path(rel_path):
    p = rel_path.replace("\\", "/")
    m = re.search(r'src/(?:main|test)/java/(.+)/[^/]+\.java$', p)
    if m:
        return m.group(1).replace("/", ".")
    return None


def read_java_file(path):
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return content, content.splitlines()
    except Exception:
        return "", []


def get_imports(lines):
    imports = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") and stripped.endswith(";"):
            imports.append(stripped[7:-1].replace("static ", "").strip())
    return imports


def has_annotation(content, annotation):
    return bool(re.search(rf'@{re.escape(annotation)}\b', content))


def is_interface(content):
    return bool(re.search(r'\b(?:public\s+|abstract\s+)*interface\s+\w+', content))


def is_record(content):
    return bool(re.search(r'\brecord\s+\w+\s*\(', content))


def is_protocol_transformer(content):
    """Una clase '*Mapper' que NO es un mapper MapStruct sino un transformador de
    protocolo con lógica imperativa (envelope SOAP/XML, parseo DOM, inyección de
    propiedades Spring). Estas clases no pueden ser interfaces MapStruct, así que se
    excluyen de MAPPER_MUST_BE_INTERFACE / MAPPER_ANNOTATION (D2 2.9).

    Se considera transformador de protocolo cuando NO es interfaz, NO tiene @Mapper de
    MapStruct, y cumple al menos una señal de lógica imperativa de protocolo:
      - inyecta propiedades de Spring con @Value;
      - parsea/serializa un protocolo externo (XML/SOAP/JSON raw): DOM, SAX, JAXB,
        envelopes SOAP, lectura cruda de árboles JSON.
    """
    if is_interface(content) or has_annotation(content, "Mapper"):
        return False
    if has_annotation(content, "Value"):
        return True
    protocol_markers = (
        "DocumentBuilderFactory", "DocumentBuilder", "SAXParser", "XMLStreamReader",
        "javax.xml", "jakarta.xml", "SOAPMessage", "SOAPEnvelope", "MessageFactory",
        "Transformer", "Marshaller", "Unmarshaller", "JAXBContext",
        "readTree", "ObjectMapper", "<soap", "<SOAP", "Envelope",
    )
    return any(marker in content for marker in protocol_markers)


def get_class_name(lines):
    for line in lines:
        m = re.search(r'\b(?:class|interface|record|enum)\s+(\w+)', line)
        if m:
            return m.group(1)
    return None


def get_declared_package(lines):
    for line in lines:
        m = re.match(r'^\s*package\s+([\w.]+)\s*;', line)
        if m:
            return m.group(1)
    return None


def uses_block(content):
    hits = []
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(r'\.(block|blockFirst|blockLast)\s*\(', line):
            hits.append((i, line.strip()))
    return hits


def get_implements(content):
    m = re.search(r'\bimplements\s+([\w\s,<>.]+?)(?:\{|extends)', content)
    if m:
        raw = m.group(1)
        return [x.strip().split('<')[0].split('.')[-1] for x in raw.split(',') if x.strip()]
    return []


# ─────────────────────────────────────────────
# CONFIGURACIÓN DEL PROYECTO (arquetipo SB4)
# ─────────────────────────────────────────────

@dataclass
class ProjectConfig:
    base_package: str = "com.ficohsa"

    pkg_model:      str = ""
    pkg_ports:      str = ""
    pkg_ports_in:   str = ""
    pkg_ports_out:  str = ""
    pkg_usecase:    str = ""
    pkg_api:        str = ""
    pkg_handlers:   str = ""
    pkg_dto:        str = ""
    pkg_mappers:    str = ""
    pkg_openapi:    str = ""
    pkg_driven:     str = ""
    pkg_helper:     str = ""
    pkg_exception:  str = ""
    pkg_app:        str = ""

    folder_infrastructure: str = "infrastructure"
    folder_model:      str = "domain/model"
    folder_ports:      str = "domain/ports"
    folder_usecase:    str = "domain/use-case"
    folder_entrypoint: str = "infrastructure/entry-points/reactive-web"
    folder_driven:     str = "infrastructure/driven-adapters"
    folder_helper:     str = "infrastructure/helpers"
    folder_app:        str = "applications/app-service"

    main_annotation: str = "FicohsaMainApplication"

    def __post_init__(self):
        bp = self.base_package
        defaults = {
            "pkg_model":     f"{bp}.model",
            "pkg_ports":     f"{bp}.ports",
            "pkg_ports_in":  f"{bp}.ports.in",
            "pkg_ports_out": f"{bp}.ports.out",
            "pkg_usecase":   f"{bp}.usecase",
            "pkg_api":       f"{bp}.api",
            "pkg_handlers":  f"{bp}.api.handlers",
            "pkg_dto":       f"{bp}.api.dto",
            "pkg_mappers":   f"{bp}.api.mappers",
            "pkg_openapi":   f"{bp}.api.openapi",
            "pkg_driven":    f"{bp}.driven",
            "pkg_helper":    f"{bp}.helper",
            "pkg_exception": f"{bp}.exception",
            "pkg_app":       bp,
        }
        for fld, default in defaults.items():
            if not getattr(self, fld):
                setattr(self, fld, default)


DEFAULT_CONFIG = ProjectConfig()


def load_project_config(repo_root):
    config_path = repo_root / "hexagonal.config.json"
    if not config_path.exists():
        return DEFAULT_CONFIG
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        base_package = raw.get("base_package", "com.ficohsa")
        cfg = ProjectConfig(base_package=base_package)
        for key, value in raw.items():
            if key == "base_package":
                continue
            if hasattr(cfg, key):
                setattr(cfg, key, value)
            else:
                print(f"⚠️   hexagonal.config.json: clave desconocida '{key}' ignorada")
        print(f"📋  Configuración cargada (base_package={cfg.base_package})")
        return cfg
    except Exception as e:
        print(f"⚠️   Error leyendo hexagonal.config.json: {e} — usando defaults")
        return DEFAULT_CONFIG


# ─────────────────────────────────────────────
# JACKSON 2 — imports prohibidos (databind/core/datatype), annotation permitido
# ─────────────────────────────────────────────

_JACKSON2_FORBIDDEN_RE = re.compile(r'^com\.fasterxml\.jackson\.(databind|core|datatype)\b')


def check_jackson2_imports(imports, file_str, result):
    for imp in imports:
        if _JACKSON2_FORBIDDEN_RE.match(imp):
            result.add(Severity.ERROR, "JACKSON2_IMPORT", file_str,
                       Messages.JACKSON2_IMPORT.format(imp=imp))


def check_coercion_config_for(lines, file_str, result):
    for i, line in enumerate(lines, 1):
        if "withCoercionConfigFor" in line:
            result.add(Severity.ERROR, "JACKSON_COERCION_FOR", file_str, Messages.JACKSON_COERCION_FOR, i)


# ─────────────────────────────────────────────
# CLASIFICADOR DE ARCHIVOS POR CAPA (arquetipo SB4, por paquete)
# ─────────────────────────────────────────────

def classify_java_file(rel_path, cfg=DEFAULT_CONFIG):
    p = rel_path.replace("\\", "/")
    is_test = "/src/test/" in p or "/test/java/" in p
    prefix = "test_" if is_test else ""
    pkg = get_declared_package_from_path(p) or ""

    if p.rsplit("/", 1)[-1] == "MainApplication.java":
        return prefix + "app"

    if pkg == cfg.pkg_exception or pkg.startswith(cfg.pkg_exception + "."):
        return prefix + "project_exception"

    if pkg == cfg.pkg_ports_in or pkg.startswith(cfg.pkg_ports_in + "."):
        return prefix + "port_in"
    if pkg == cfg.pkg_ports_out or pkg.startswith(cfg.pkg_ports_out + "."):
        return prefix + "port_out"
    if pkg == cfg.pkg_ports or pkg.startswith(cfg.pkg_ports + "."):
        sub = pkg[len(cfg.pkg_ports):].lstrip(".").split(".")[0] if pkg != cfg.pkg_ports else ""
        if sub and sub not in ("in", "out"):
            return prefix + "port_invalid_subfolder"
        return prefix + "port_unknown"

    if pkg == cfg.pkg_model or pkg.startswith(cfg.pkg_model + "."):
        return prefix + "model"

    if pkg == cfg.pkg_usecase or pkg.startswith(cfg.pkg_usecase + "."):
        return prefix + "usecase"

    if pkg == cfg.pkg_handlers or pkg.startswith(cfg.pkg_handlers + "."):
        return prefix + "handler"
    if pkg == cfg.base_package + ".api.handler" or pkg.startswith(cfg.base_package + ".api.handler."):
        return prefix + "handler"   # paquete singular antiguo → forzar error de paquete
    if pkg == cfg.pkg_dto or pkg.startswith(cfg.pkg_dto + "."):
        return prefix + "dto"
    if pkg == cfg.pkg_mappers or pkg.startswith(cfg.pkg_mappers + "."):
        return prefix + "mapper"
    if pkg == cfg.pkg_openapi or pkg.startswith(cfg.pkg_openapi + "."):
        return prefix + "openapi"
    if pkg == cfg.pkg_api or pkg.startswith(cfg.pkg_api + "."):
        fname = p.rsplit("/", 1)[-1]
        if "RouterRest" in fname:
            return prefix + "router"
        return prefix + "api_other"

    if pkg == cfg.pkg_driven or pkg.startswith(cfg.pkg_driven + "."):
        rest = pkg[len(cfg.pkg_driven):].lstrip(".")
        segs = rest.split(".") if rest else []
        if len(segs) >= 2:
            leaf = segs[1]
            if leaf == "adapter":
                return prefix + ("adapter" if pkg.endswith(".adapter") else "adapter_support")
            if leaf == "config":
                return prefix + "adapter_config"
            if leaf == "mapper":
                return prefix + ("mapper" if pkg.endswith(".mapper") else "adapter_support")
            if leaf == "dto":
                return prefix + "adapter_support"
        return prefix + "driven_other"

    if pkg == cfg.pkg_helper or pkg.startswith(cfg.pkg_helper + "."):
        return prefix + "helper"

    return None


def get_driven_module(pkg, cfg):
    if not pkg or not pkg.startswith(cfg.pkg_driven):
        return None
    rest = pkg[len(cfg.pkg_driven):].lstrip(".")
    segs = rest.split(".") if rest else []
    return segs[0] if segs else None


def get_driven_private_imports(imports, cfg):
    result = []
    prefix = re.escape(cfg.pkg_driven) + r'\.(\w+)\.(dto)\b'
    for imp in imports:
        if re.match(prefix, imp):
            result.append(imp)
    return result


# ─────────────────────────────────────────────
# VALIDADORES POR CAPA
# ─────────────────────────────────────────────

_SYSTEM_NAMES = ("Cobis", "T24", "Abanks", "Cobol")


def _common_java_checks(content, lines, file_str, result, forbid_block=True):
    if re.search(r'@Autowired\s+(?:private|protected|public)?\s*(?:final\s+)?[\w<>]', content):
        result.add(Severity.ERROR, "NO_FIELD_AUTOWIRED", file_str, Messages.NO_FIELD_AUTOWIRED)
    if forbid_block:
        for line_no, line_text in uses_block(content):
            result.add(Severity.ERROR, "NO_BLOCKING_CALLS", file_str,
                       Messages.NO_BLOCKING_CALLS.format(line=line_text), line_no)
    check_jackson2_imports(get_imports(lines), file_str, result)
    check_coercion_config_for(lines, file_str, result)


def validate_model(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    forbidden = ["Entity", "Table", "Document", "Component", "Service",
                 "Repository", "Configuration", "Controller"]
    for ann in forbidden:
        if has_annotation(content, ann):
            result.add(Severity.ERROR, "MODEL_NO_SPRING_ANNOTATIONS", file_str,
                       Messages.MODEL_NO_SPRING_ANNOTATION.format(annotation=ann))
    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith("org.springframework.") and "validation" not in imp:
            result.add(Severity.ERROR, "MODEL_NO_SPRING_IMPORTS", file_str,
                       Messages.MODEL_NO_SPRING_IMPORT.format(imp=imp))
        for fp in (cfg.pkg_driven + ".", cfg.pkg_api + ".", cfg.pkg_usecase + "."):
            if imp.startswith(fp):
                result.add(Severity.ERROR, "MODEL_LAYER_VIOLATION", file_str,
                           Messages.MODEL_LAYER_VIOLATION.format(imp=imp))
    check_jackson2_imports(imports, file_str, result)
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_model or pkg.startswith(cfg.pkg_model + ".")):
        result.add(Severity.ERROR, "MODEL_WRONG_PACKAGE", file_str,
                   Messages.MODEL_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_model))


def validate_project_exception(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    pkg = get_declared_package(lines)
    result.add(Severity.ERROR, "PROJECT_CUSTOM_EXCEPTION", file_str,
               Messages.PROJECT_CUSTOM_EXCEPTION.format(name=name or "clase"))
    if pkg:
        result.add(Severity.ERROR, "PROJECT_EXCEPTION_PACKAGE", file_str,
                   Messages.PROJECT_EXCEPTION_PACKAGE.format(pkg=pkg))


def validate_port_in(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if not is_interface(content):
        result.add(Severity.ERROR, "PORT_IN_MUST_BE_INTERFACE", file_str,
                   Messages.PORT_IN_MUST_BE_INTERFACE.format(name=name))
    if name and not re.match(r"^I[A-Z]", name):
        result.add(Severity.ERROR, "PORT_IN_PREFIX", file_str, Messages.PORT_IN_PREFIX.format(name=name))
    if name and name.endswith("Gateway"):
        result.add(Severity.ERROR, "PORT_IN_NO_GATEWAY", file_str, Messages.PORT_IN_NO_GATEWAY.format(name=name))
    imports = get_imports(lines)
    for imp in imports:
        for f in (cfg.pkg_usecase + ".", cfg.pkg_api + ".", cfg.pkg_driven + "."):
            if imp.startswith(f):
                result.add(Severity.ERROR, "PORT_IN_LAYER_VIOLATION", file_str,
                           Messages.PORT_IN_LAYER_VIOLATION.format(imp=imp))
    check_jackson2_imports(imports, file_str, result)
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_ports_in or pkg.startswith(cfg.pkg_ports_in + ".")):
        result.add(Severity.ERROR, "PORT_IN_WRONG_PACKAGE", file_str,
                   Messages.PORT_IN_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_ports_in))
    if "Mono<" not in content and "Flux<" not in content:
        result.add(Severity.WARNING, "PORT_IN_NO_REACTIVE", file_str, Messages.PORT_IN_NO_REACTIVE)


def validate_port_out(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if not is_interface(content):
        result.add(Severity.ERROR, "PORT_OUT_MUST_BE_INTERFACE", file_str,
                   Messages.PORT_OUT_MUST_BE_INTERFACE.format(name=name))
    if name and not name.endswith("Gateway"):
        result.add(Severity.ERROR, "PORT_OUT_SUFFIX", file_str, Messages.PORT_OUT_SUFFIX.format(name=name))
    if name and re.match(r"^I[A-Z]", name):
        result.add(Severity.ERROR, "PORT_OUT_NO_I_PREFIX", file_str, Messages.PORT_OUT_NO_I_PREFIX.format(name=name))
    if name:
        for sysname in _SYSTEM_NAMES:
            if sysname in name:
                result.add(Severity.WARNING, "PORT_OUT_SYSTEM_NAME", file_str,
                           Messages.PORT_OUT_SYSTEM_NAME.format(name=name, sysname=sysname))
                break
    imports = get_imports(lines)
    for imp in imports:
        for f in (cfg.pkg_usecase + ".", cfg.pkg_api + ".", cfg.pkg_driven + "."):
            if imp.startswith(f):
                result.add(Severity.ERROR, "PORT_OUT_LAYER_VIOLATION", file_str,
                           Messages.PORT_OUT_LAYER_VIOLATION.format(imp=imp))
    if "java.net.URI" in content:
        result.add(Severity.ERROR, "PORT_OUT_INFRA_TYPE", file_str,
                   Messages.PORT_OUT_INFRA_TYPE.format(typ="java.net.URI"))
    check_jackson2_imports(imports, file_str, result)
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_ports_out or pkg.startswith(cfg.pkg_ports_out + ".")):
        result.add(Severity.ERROR, "PORT_OUT_WRONG_PACKAGE", file_str,
                   Messages.PORT_OUT_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_ports_out))
    if "Mono<" not in content and "Flux<" not in content:
        result.add(Severity.WARNING, "PORT_OUT_NO_REACTIVE", file_str, Messages.PORT_OUT_NO_REACTIVE)


def validate_port_unknown(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    result.add(Severity.ERROR, "PORT_UNKNOWN_CONVENTION", str(rel),
               Messages.PORT_UNKNOWN_CONVENTION.format(name=get_class_name(lines)))


def validate_port_invalid_subfolder(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    pkg = get_declared_package(lines) or ""
    sub = pkg[len(cfg.pkg_ports):].lstrip(".").split(".")[0] if pkg.startswith(cfg.pkg_ports) else "desconocida"
    result.add(Severity.ERROR, "PORTS_INVALID_SUBFOLDER", str(rel),
               Messages.PORTS_INVALID_SUBFOLDER.format(subfolder=sub))


def validate_usecase(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    pkg = get_declared_package(lines)
    is_support = bool(name and pkg and pkg != cfg.pkg_usecase
                      and pkg.startswith(cfg.pkg_usecase + ".") and not name.endswith("UseCase"))

    if is_interface(content):
        result.add(Severity.ERROR, "USECASE_NOT_INTERFACE", file_str,
                   Messages.USECASE_NOT_INTERFACE.format(name=name))
    if not is_support:
        if name and not name.endswith("UseCase"):
            result.add(Severity.ERROR, "USECASE_SUFFIX", file_str, Messages.USECASE_SUFFIX.format(name=name))
        if not any(re.match(r"^I[A-Z]", i) for i in get_implements(content)):
            result.add(Severity.ERROR, "USECASE_NO_INPORT", file_str, Messages.USECASE_NO_INPORT.format(name=name))
        if not has_annotation(content, "Component"):
            result.add(Severity.WARNING, "USECASE_NO_COMPONENT", file_str, Messages.USECASE_NO_COMPONENT.format(name=name))
        if not has_annotation(content, "RequiredArgsConstructor"):
            result.add(Severity.WARNING, "USECASE_NO_REQUIRED_ARGS", file_str, Messages.USECASE_NO_REQUIRED_ARGS.format(name=name))
    if has_annotation(content, "Service"):
        result.add(Severity.ERROR, "USECASE_NO_SERVICE", file_str, Messages.USECASE_NO_SERVICE.format(name=name))

    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith(cfg.pkg_api + ".") or imp.startswith(cfg.pkg_driven + "."):
            result.add(Severity.ERROR, "USECASE_LAYER_VIOLATION", file_str,
                       Messages.USECASE_LAYER_VIOLATION.format(imp=imp))
        # El estándar del micro (scaffold Bancolombia/Ficohsa) SÍ usa @Component en el
        # use case para auto-registro (de hecho, arriba se advierte si NO lo tiene). Por
        # eso el estereotipo de Spring es esperado, no una violación: se permiten
        # stereotype/context.annotation/beans. Solo se advierte por imports de framework
        # genuinamente invasivos en el dominio (web/webflux/data/http/server).
        if imp.startswith("org.springframework."):
            allowed_spring = (
                "org.springframework.stereotype",
                "org.springframework.context.annotation",
                "org.springframework.beans.factory",
            )
            if imp.startswith(allowed_spring) or "validation" in imp:
                continue
            result.add(Severity.WARNING, "USECASE_SPRING_IMPORT", file_str,
                       Messages.USECASE_SPRING_IMPORT.format(imp=imp))
    for imp in get_driven_private_imports(imports, cfg):
        result.add(Severity.ERROR, "DRIVEN_PRIVATE_LEAK", file_str,
                   Messages.USECASE_PRIVATE_LEAK.format(imp=imp))

    _check_resilience(content, file_str, result)
    _common_java_checks(content, lines, file_str, result)
    if pkg and not (pkg == cfg.pkg_usecase or pkg.startswith(cfg.pkg_usecase + ".")):
        result.add(Severity.ERROR, "USECASE_WRONG_PACKAGE", file_str,
                   Messages.USECASE_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_usecase))


def _check_resilience(content, file_str, result):
    if "@FicohsaResilience" not in content:
        return
    for attr in ("label", "paramName", "paramLabel"):
        if re.search(rf'@FicohsaResilience\s*\([^)]*\b{attr}\s*=', content, re.DOTALL):
            result.add(Severity.ERROR, "RESILIENCE_DEPRECATED_MODE", file_str,
                       Messages.RESILIENCE_DEPRECATED_MODE.format(attr=attr))
    m = re.search(r'instanceName\s*=\s*"(cb-[\w-]+)"', content)
    if m:
        result.add(Severity.WARNING, "RESILIENCE_INSTANCE_CB", file_str,
                   Messages.RESILIENCE_INSTANCE_CB.format(val=m.group(1)))


def validate_handler(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if name and not name.endswith("Handler"):
        result.add(Severity.ERROR, "HANDLER_SUFFIX", file_str, Messages.HANDLER_SUFFIX.format(name=name))
    for ftype in re.findall(r'private\s+final\s+([\w<>]+)\s+\w+', content):
        base = ftype.split('<')[0]
        if base.endswith("UseCase") and not re.match(r"^I[A-Z]", base):
            result.add(Severity.ERROR, "HANDLER_CONCRETE_USECASE", file_str,
                       Messages.HANDLER_CONCRETE_USECASE.format(name=base))
    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith(cfg.pkg_driven + "."):
            result.add(Severity.ERROR, "HANDLER_LAYER_VIOLATION", file_str,
                       Messages.HANDLER_LAYER_VIOLATION_DA.format(imp=imp))
        if imp.startswith(cfg.pkg_usecase + "."):
            result.add(Severity.ERROR, "HANDLER_LAYER_VIOLATION", file_str,
                       Messages.HANDLER_LAYER_VIOLATION_UC.format(imp=imp))
    for imp in get_driven_private_imports(imports, cfg):
        result.add(Severity.ERROR, "DRIVEN_PRIVATE_LEAK", file_str,
                   Messages.HANDLER_PRIVATE_LEAK.format(imp=imp))
    if "applicationId" in content and "correlationId" not in content:
        result.add(Severity.WARNING, "HANDLER_APPLICATION_ID", file_str, Messages.HANDLER_APPLICATION_ID)
    _common_java_checks(content, lines, file_str, result)
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_handlers or pkg.startswith(cfg.pkg_handlers + ".")):
        result.add(Severity.ERROR, "HANDLER_WRONG_PACKAGE", file_str,
                   Messages.HANDLER_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_handlers))


def validate_dto(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if name and (name.endswith("DTO") or not name.endswith("Dto")):
        result.add(Severity.ERROR, "DTO_SUFFIX", file_str, Messages.DTO_SUFFIX.format(name=name))
    if not is_record(content):
        result.add(Severity.ERROR, "DTO_MUST_BE_RECORD", file_str, Messages.DTO_MUST_BE_RECORD.format(name=name))
    # @JsonIgnoreProperties / @JsonInclude son preserve-if-present (Req 58): NO se exigen.
    check_jackson2_imports(get_imports(lines), file_str, result)
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_dto or pkg.startswith(cfg.pkg_dto + ".")):
        result.add(Severity.ERROR, "DTO_WRONG_PACKAGE", file_str,
                   Messages.DTO_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_dto))


def validate_mapper(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)

    # D2 2.9 — Excepción: transformadores de protocolo. Las clases '*Mapper' que no son
    # mappers MapStruct sino transformadores de protocolo (envelope SOAP/XML, parseo DOM,
    # inyección de propiedades Spring con @Value) no pueden ser interfaces MapStruct. Para
    # ellas NO aplican MAPPER_MUST_BE_INTERFACE ni MAPPER_ANNOTATION; se validan igual el
    # sufijo, los imports Jackson 2 y el paquete.
    protocol_transformer = is_protocol_transformer(content)

    if not protocol_transformer:
        if not is_interface(content):
            result.add(Severity.ERROR, "MAPPER_MUST_BE_INTERFACE", file_str,
                       Messages.MAPPER_MUST_BE_INTERFACE.format(name=name))
        if not has_annotation(content, "Mapper"):
            result.add(Severity.ERROR, "MAPPER_ANNOTATION", file_str, Messages.MAPPER_ANNOTATION.format(name=name))
        elif 'componentModel = "spring"' not in content and "componentModel = 'spring'" not in content:
            result.add(Severity.WARNING, "MAPPER_SPRING_MODEL", file_str, Messages.MAPPER_SPRING_MODEL.format(name=name))

    if name and not name.endswith("Mapper"):
        result.add(Severity.ERROR, "MAPPER_SUFFIX", file_str, Messages.MAPPER_SUFFIX.format(name=name))
    check_jackson2_imports(get_imports(lines), file_str, result)
    pkg = get_declared_package(lines)
    ok = pkg and (pkg == cfg.pkg_mappers or pkg.startswith(cfg.pkg_mappers + ".")
                  or re.match(re.escape(cfg.pkg_driven) + r'\.\w+\.mapper', pkg))
    if pkg and not ok:
        result.add(Severity.ERROR, "MAPPER_WRONG_PACKAGE", file_str,
                   Messages.MAPPER_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_mappers))


def validate_adapter(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if is_interface(content):
        result.add(Severity.ERROR, "ADAPTER_NOT_INTERFACE", file_str, Messages.ADAPTER_NOT_INTERFACE.format(name=name))
    if name and not (name.endswith("Adapter") or name.endswith("Repository")):
        result.add(Severity.ERROR, "ADAPTER_SUFFIX", file_str, Messages.ADAPTER_SUFFIX.format(name=name))
    if not (has_annotation(content, "Component") or has_annotation(content, "Repository")):
        result.add(Severity.WARNING, "ADAPTER_ANNOTATION", file_str, Messages.ADAPTER_ANNOTATION.format(name=name))
    if not any(i.endswith("Gateway") for i in get_implements(content)) and "implements" not in content:
        result.add(Severity.ERROR, "ADAPTER_NO_GATEWAY", file_str, Messages.ADAPTER_NO_GATEWAY.format(name=name))

    pkg = get_declared_package(lines)
    current_module = get_driven_module(pkg, cfg)
    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith(cfg.pkg_api + "."):
            result.add(Severity.ERROR, "ADAPTER_LAYER_VIOLATION", file_str,
                       Messages.ADAPTER_LAYER_VIOLATION.format(imp=imp))
        if imp.startswith(cfg.pkg_driven + ".") and current_module:
            m = re.match(re.escape(cfg.pkg_driven) + r'\.(\w+)', imp)
            if m and m.group(1) != current_module:
                if re.match(re.escape(cfg.pkg_driven) + r'\.\w+\.dto\b', imp):
                    result.add(Severity.ERROR, "DRIVEN_PRIVATE_LEAK", file_str,
                               Messages.ADAPTER_PRIVATE_LEAK.format(name=name, imp=imp))
                else:
                    result.add(Severity.ERROR, "ADAPTER_CROSS_DEPENDENCY", file_str,
                               Messages.ADAPTER_CROSS_DEPENDENCY.format(name=name, imp=imp))
    if '"Caller-Service"' in content:
        for i, line in enumerate(lines, 1):
            if "Caller-Service" in line and (".set(" in line or "Map.of(" in line or ".header(" in line):
                result.add(Severity.ERROR, "ADAPTER_MANUAL_CALLER_SVC", file_str, Messages.ADAPTER_MANUAL_CALLER_SVC, i)
                break
    if "WebClientComponent" in content and "@LogExternalCall" not in content:
        result.add(Severity.WARNING, "ADAPTER_NO_LOG_EXTERNAL", file_str,
                   Messages.ADAPTER_NO_LOG_EXTERNAL.format(name=name))
    _check_resilience(content, file_str, result)
    _common_java_checks(content, lines, file_str, result)


def validate_adapter_support(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    for imp in get_imports(lines):
        if imp.startswith(cfg.pkg_api + "."):
            result.add(Severity.ERROR, "ADAPTER_SUPPORT_LAYER_VIOLATION", file_str,
                       f"Clase de soporte en adapter no puede importar entry-points (api): {imp}")
    _common_java_checks(content, lines, file_str, result)


def validate_adapter_config(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if not name:
        return
    if name.endswith("PropsConfig"):
        if not is_record(content):
            result.add(Severity.ERROR, "PROPS_CONFIG_MUST_BE_RECORD", file_str,
                       Messages.PROPS_CONFIG_MUST_BE_RECORD.format(name=name))
        if not has_annotation(content, "ConfigurationProperties"):
            result.add(Severity.ERROR, "PROPS_CONFIG_ANNOTATION", file_str,
                       Messages.PROPS_CONFIG_ANNOTATION.format(name=name))
    elif name.endswith("Properties"):
        # Sufijo estándar de Spring Boot para @ConfigurationProperties (convención oficial;
        # es el patrón usado por el micro de referencia sp4). Solo se exige la anotación
        # @ConfigurationProperties; NO se exige record (el estándar del micro usa
        # @Data/@Component mutable, patrón válido de Spring Boot).
        if not has_annotation(content, "ConfigurationProperties"):
            result.add(Severity.ERROR, "PROPS_CONFIG_ANNOTATION", file_str,
                       Messages.PROPS_CONFIG_ANNOTATION.format(name=name))
    elif name.endswith("ClientConfig"):
        if not has_annotation(content, "Configuration"):
            result.add(Severity.ERROR, "CLIENT_CONFIG_ANNOTATION", file_str,
                       Messages.CLIENT_CONFIG_ANNOTATION.format(name=name))
    else:
        result.add(Severity.WARNING, "ADAPTER_CONFIG_NAMING", file_str,
                   Messages.ADAPTER_CONFIG_NAMING.format(name=name))
    check_jackson2_imports(get_imports(lines), file_str, result)


def validate_router(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if name and name != "RouterRest":
        result.add(Severity.ERROR, "ROUTER_NAME", file_str, Messages.ROUTER_NAME.format(name=name))
    if not has_annotation(content, "Configuration"):
        result.add(Severity.ERROR, "ROUTER_NO_CONFIGURATION", file_str, Messages.ROUTER_NO_CONFIGURATION)
    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith(cfg.pkg_driven + "."):
            result.add(Severity.ERROR, "ROUTER_LAYER_VIOLATION", file_str,
                       Messages.ROUTER_LAYER_VIOLATION_DA.format(imp=imp))
        if imp.startswith(cfg.pkg_usecase + "."):
            result.add(Severity.ERROR, "ROUTER_LAYER_VIOLATION", file_str,
                       Messages.ROUTER_LAYER_VIOLATION_UC.format(imp=imp))
    if "getRequestType()" in content:
        result.add(Severity.ERROR, "ROUTER_GET_REQUEST_TYPE", file_str, Messages.ROUTER_GET_REQUEST_TYPE)
    if "RequestModel" not in content and "ParameterizedTypeReference" not in content:
        result.add(Severity.WARNING, "ROUTER_NO_ENVELOPE", file_str, Messages.ROUTER_NO_ENVELOPE)
    check_jackson2_imports(imports, file_str, result)


def validate_app(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    name = get_class_name(lines)
    if name == "MainApplication" or "MainApplication.java" in str(path):
        if not has_annotation(content, cfg.main_annotation):
            result.add(Severity.ERROR, "MAIN_ANNOTATION", file_str,
                       Messages.MAIN_ANNOTATION_MISSING.format(annotation=cfg.main_annotation))
        if has_annotation(content, "SpringBootApplication"):
            result.add(Severity.ERROR, "MAIN_ANNOTATION", file_str,
                       Messages.MAIN_ANNOTATION_FORBIDDEN.format(annotation=cfg.main_annotation))
        pkg = get_declared_package(lines)
        if pkg and pkg != cfg.pkg_app:
            result.add(Severity.ERROR, "MAIN_WRONG_PACKAGE", file_str,
                       Messages.MAIN_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_app))
    check_jackson2_imports(get_imports(lines), file_str, result)
    check_coercion_config_for(lines, file_str, result)


def validate_helper(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    imports = get_imports(lines)
    for imp in imports:
        if imp.startswith(cfg.pkg_driven + "."):
            result.add(Severity.WARNING, "HELPER_DRIVEN_IMPORT", file_str,
                       Messages.HELPER_DRIVEN_IMPORT.format(imp=imp))
    check_jackson2_imports(imports, file_str, result)
    name = get_class_name(lines)
    if name and name.endswith("RegionalizationProperties") and has_annotation(content, "ConfigurationProperties"):
        result.add(Severity.WARNING, "REGIONALIZATION_PROPERTIES", file_str,
                   Messages.REGIONALIZATION_PROPERTIES.format(name=name))
    pkg = get_declared_package(lines)
    if pkg and not (pkg == cfg.pkg_helper or pkg.startswith(cfg.pkg_helper + ".")):
        result.add(Severity.WARNING, "HELPER_WRONG_PACKAGE", file_str,
                   Messages.HELPER_WRONG_PACKAGE.format(pkg=pkg, expected_pkg=cfg.pkg_helper))
    for line_no, line_text in uses_block(content):
        result.add(Severity.WARNING, "NO_BLOCKING_CALLS", file_str,
                   Messages.NO_BLOCKING_CALLS_WARNING.format(line=line_text), line_no)


def validate_generic(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    check_jackson2_imports(get_imports(lines), str(rel), result)
    check_coercion_config_for(lines, str(rel), result)


VALIDATORS = {
    "model":                  validate_model,
    "project_exception":      validate_project_exception,
    "port_in":                validate_port_in,
    "port_out":               validate_port_out,
    "port_unknown":           validate_port_unknown,
    "port_invalid_subfolder": validate_port_invalid_subfolder,
    "usecase":                validate_usecase,
    "handler":                validate_handler,
    "dto":                    validate_dto,
    "mapper":                 validate_mapper,
    "openapi":                validate_generic,
    "api_other":              validate_generic,
    "router":                 validate_router,
    "adapter":                validate_adapter,
    "adapter_support":        validate_adapter_support,
    "adapter_config":         validate_adapter_config,
    "driven_other":           validate_generic,
    "app":                    validate_app,
    "helper":                 validate_helper,
}


# ─────────────────────────────────────────────
# VALIDACIÓN DE STRINGS HARDCODEADOS (heredado de v1, simplificado)
# ─────────────────────────────────────────────

LONG_STRING_THRESHOLD = 100
_URL_RE = re.compile(r'https?://[\w\-./:%?=&#@!+,;]+', re.IGNORECASE)
_IP_RE = re.compile(
    r'\b(?!0\.0\.0\.0)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?\b')
_LOCALHOST_RE = re.compile(r'localhost:\d{2,5}', re.IGNORECASE)
_IGNORE_LINE = [
    re.compile(r'^\s*//'), re.compile(r'^\s*\*'), re.compile(r'@\w+\('),
    re.compile(r'import\s+'), re.compile(r'package\s+'), re.compile(r'log\.'),
    re.compile(r'Logger'), re.compile(r'throw new \w+Exception'),
    re.compile(r'@ConfigurationProperties'), re.compile(r'@Value\('),
]
_ALLOWED_STRINGS = {
    "application/json", "application/xml", "text/plain", "UTF-8", "utf-8",
    "Bearer ", "Basic ", "Content-Type", "Authorization", "Accept",
    "GET", "POST", "PUT", "DELETE", "PATCH", "true", "false", "null", "",
    "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "HH:mm:ss",
}

# Archivos de documentación de contrato (OpenAPI/Swagger): contienen ejemplos de
# request/response y esquemas, no lógica de red. Las URLs en ellos son documentación,
# no endpoints invocables → no aplica D2 2.14. (Estándar del micro de referencia sp4:
# OpenApiResponseConfig con ejemplos de Problem Detail RFC 7807.)
_OPENAPI_FILE_RE = re.compile(r'(?:/openapi/|openapi|swagger|apidoc|apiresponse)', re.IGNORECASE)

# URIs de tipo de error RFC 7807 (Problem Detail): el campo "type"/"instance" es un URI
# de REFERENCIA que identifica el tipo de problema; el RFC no exige que sea resoluble ni
# que venga de config. No es un endpoint que el micro consuma. Se reconoce por el patrón
# ".../errors/<slug>" o por estar declarado como valor de "type"/"instance" en un JSON.
_RFC7807_TYPE_RE = re.compile(r'https?://[\w\-./:%]+/errors/[\w\-]+/?$', re.IGNORECASE)


def _is_openapi_doc_file(rel) -> bool:
    return bool(_OPENAPI_FILE_RE.search(str(rel).replace("\\", "/")))


def _is_rfc7807_type_uri(value, line) -> bool:
    """True si la URL es un URI de tipo/instancia de Problem Detail (RFC 7807),
    no un endpoint de red. Señales: termina en /errors/<slug>, o la línea la declara
    como valor del campo JSON "type"/"instance"."""
    if _RFC7807_TYPE_RE.search(value.strip()):
        return True
    if re.search(r'"(?:type|instance)"\s*:', line):
        return True
    return False


def _extract_string_literals(content):
    results = []
    string_re = re.compile(r'"((?:[^"\\]|\\.)*)"')
    for line_no, line in enumerate(content.splitlines(), 1):
        if any(p.search(line) for p in _IGNORE_LINE):
            continue
        for m in string_re.finditer(line):
            value = m.group(1)
            if not value or value in _ALLOWED_STRINGS:
                continue
            results.append((line_no, value, line))
    return results


def validate_hardcoded_strings(path, rel, content, lines, result, cfg=DEFAULT_CONFIG):
    file_str = str(rel)
    # Los archivos de documentación OpenAPI/Swagger no llevan lógica de red: sus URLs
    # son ejemplos de contrato, no endpoints invocables. No aplica D2 2.14 sobre URLs.
    is_openapi_doc = _is_openapi_doc_file(rel)
    for line_no, value, raw_line in _extract_string_literals(content):
        if _URL_RE.search(value):
            # Excepciones legítimas (estándar del micro sp4):
            #  1) URLs en archivos de documentación OpenAPI/Swagger.
            #  2) URIs de tipo/instancia de Problem Detail (RFC 7807) — no son endpoints.
            if is_openapi_doc or _is_rfc7807_type_uri(value, raw_line):
                continue
            result.add(Severity.ERROR, "HARDCODED_URL", file_str,
                       Messages.HARDCODED_URL.format(value=value[:80]), line_no)
            continue
        if _IP_RE.search(value) or _LOCALHOST_RE.search(value):
            result.add(Severity.ERROR, "HARDCODED_IP", file_str,
                       Messages.HARDCODED_IP.format(value=value[:80]), line_no)
            continue
        if len(value) > LONG_STRING_THRESHOLD:
            result.add(Severity.WARNING, "HARDCODED_LONG_STRING", file_str,
                       Messages.HARDCODED_LONG_STRING.format(length=len(value), preview=value[:40]), line_no)


# ─────────────────────────────────────────────
# VALIDACIONES DE ESTRUCTURA DE PROYECTO
# ─────────────────────────────────────────────

REQUIRED_FILES = [
    "settings.gradle",
    "build.gradle",
    "gradle.properties",
    "gradle/libs.versions.toml",
    "lombok.config",
    "applications/app-service/src/main/resources/application.yml",
    "applications/app-service/src/main/resources/banner.txt",
]

FORBIDDEN_FILES = [
    "application.properties", "log4j2.properties", "log4j2.xml",
    "logback.xml", "logback-spring.xml",
    # NOTA: main.gradle NO es prohibido — es parte del arquetipo SB4 (config común de
    # subprojects). Ver lineamientos/aws-validaciones/05-estandar-main-gradle.md.
]

REQUIRED_MODULES = [
    "domain/model", "domain/ports", "domain/use-case",
    "infrastructure/entry-points/reactive-web", "applications/app-service",
]

SENSITIVE_GRADLE_KEYS = ["azuredo_user", "azuredo_pass", "azuredo_url", "azureUser", "azurePass"]
_PLACEHOLDER_RE = re.compile(r'^\$\(.+\)$')
_INFRA_ALIASES = ["infraestructure", "infraestructura", "infrastructuric", "infra"]


def validate_project_structure(repo_root, result, cfg=DEFAULT_CONFIG):
    for required in REQUIRED_FILES:
        if not (repo_root / required).exists():
            result.add(Severity.ERROR, "MISSING_REQUIRED_FILE", required,
                       Messages.MISSING_REQUIRED_FILE.format(path=required))

    for forbidden in FORBIDDEN_FILES:
        for found in repo_root.rglob(forbidden):
            s = str(found)
            if "/.git/" in s or "/build/" in s:
                continue
            result.add(Severity.ERROR, "FORBIDDEN_FILE", str(found.relative_to(repo_root)),
                       Messages.FORBIDDEN_FILE.format(filename=forbidden))

    for module in REQUIRED_MODULES:
        if not (repo_root / module).exists():
            result.add(Severity.ERROR, "MISSING_MODULE", module,
                       Messages.MISSING_MODULE.format(module=module))

    if not (repo_root / "infrastructure").exists():
        for alias in _INFRA_ALIASES:
            if (repo_root / alias).exists():
                result.add(Severity.ERROR, "INFRA_FOLDER_TYPO", alias,
                           Messages.INFRA_FOLDER_TYPO.format(found=alias))
                break

    # El sufijo -client-api (Req 45) aplica SOLO a los adapters de sistemas externos
    # (t24, abanks, cobis y wrappers de sistema). Módulos de infraestructura propia como
    # regionalization, parameter-store, secret-manager, homologator NO se renombran.
    _NON_CLIENT_API_MODULES = (
        "regionalization", "parameter-store", "secret-manager", "secrets",
        "homologator", "resilience", "helpers",
    )
    driven_dir = repo_root / "infrastructure" / "driven-adapters"
    if driven_dir.exists():
        for sub in driven_dir.iterdir():
            if not sub.is_dir():
                continue
            n = sub.name
            base = n[:-len("-client")] if n.endswith("-client") else n
            is_infra_module = any(k in n for k in _NON_CLIENT_API_MODULES)
            if n.endswith("-client") and not n.endswith("-client-api") and not is_infra_module:
                result.add(Severity.ERROR, "DRIVEN_MODULE_OLD_NAMING", str(sub.relative_to(repo_root)),
                           Messages.DRIVEN_MODULE_OLD_NAMING.format(found=n, expected=n + "-api"))
            if n == "feign":
                result.add(Severity.ERROR, "FORBIDDEN_MODULE", str(sub.relative_to(repo_root)),
                           Messages.FORBIDDEN_MODULE.format(module="driven-adapters/feign") +
                           " (bloqueante, incompatible con WebFlux, Req 5.5)")

    lombok = repo_root / "lombok.config"
    if lombok.exists():
        content = lombok.read_text(encoding="utf-8", errors="replace")
        if "config.stopBubbling = true" not in content:
            result.add(Severity.ERROR, "LOMBOK_CONFIG", "lombok.config",
                       Messages.LOMBOK_CONFIG_MISSING.format(prop="config.stopBubbling = true"))
        if "lombok.addLombokGeneratedAnnotation = true" not in content:
            result.add(Severity.ERROR, "LOMBOK_CONFIG", "lombok.config",
                       Messages.LOMBOK_CONFIG_MISSING.format(prop="lombok.addLombokGeneratedAnnotation = true"))

    for pat in ("logback*.xml", "log4j2*.xml", "log4j2*.properties"):
        for f in repo_root.rglob(pat):
            s = str(f)
            if "/.git/" in s or "/build/" in s:
                continue
            result.add(Severity.ERROR, "LOGGING_CONFIG_FORBIDDEN", str(f.relative_to(repo_root)),
                       Messages.LOGGING_CONFIG_FORBIDDEN.format(filename=f.name))

    _validate_gradle_credentials(repo_root, result)


def _validate_gradle_credentials(repo_root, result):
    gp = repo_root / "gradle.properties"
    if not gp.exists():
        return
    for line_no, raw in enumerate(gp.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        stripped = raw.strip()
        is_comment = stripped.startswith("#")
        effective = stripped.lstrip("#").strip()
        m = re.match(r'^([\w.]+)\s*=\s*(.+)$', effective)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if key not in SENSITIVE_GRADLE_KEYS or _PLACEHOLDER_RE.match(value):
            continue
        if is_comment:
            result.add(Severity.ERROR, "GRADLE_CREDENTIAL_COMMENTED", "gradle.properties",
                       Messages.GRADLE_CREDENTIAL_COMMENTED.format(key=key), line_no)
        else:
            result.add(Severity.ERROR, "GRADLE_CREDENTIAL_EXPOSED", "gradle.properties",
                       Messages.GRADLE_CREDENTIAL_EXPOSED.format(key=key), line_no)


# ─────────────────────────────────────────────
# MOTOR PRINCIPAL
# ─────────────────────────────────────────────

def validate_repo(repo_root, base_package=None):
    result = ValidationResult()
    result.repo_name = os.environ.get("REPO_NAME", repo_root.resolve().name)
    result.repo_path = str(repo_root.resolve())

    if not repo_root.exists():
        print(f"ERROR: El directorio '{repo_root}' no existe.", file=sys.stderr)
        sys.exit(1)

    cfg = load_project_config(repo_root)
    if base_package and base_package != "com.ficohsa" and cfg.base_package == "com.ficohsa":
        cfg = ProjectConfig(base_package=base_package)

    print(f"\n🔍  Analizando repositorio (arquetipo SB4): {repo_root.resolve()}\n")
    validate_project_structure(repo_root, result, cfg)

    java_files = [f for f in repo_root.rglob("*.java")
                  if "/build/" not in str(f) and "/.git/" not in str(f)]
    print(f"📄  Archivos Java encontrados: {len(java_files)}")

    unclassified = 0
    counts = {}
    for jf in java_files:
        try:
            rel = jf.relative_to(repo_root)
        except ValueError:
            rel = jf
        layer = classify_java_file(str(rel), cfg)
        if layer is None:
            unclassified += 1
            continue
        counts[layer] = counts.get(layer, 0) + 1
        if layer.startswith("test_"):
            continue
        content, lines = read_java_file(jf)
        if not content:
            continue
        validator = VALIDATORS.get(layer)
        if validator:
            validator(jf, str(rel), content, lines, result, cfg)
        validate_hardcoded_strings(jf, str(rel), content, lines, result, cfg)

    print(f"✅  Clasificados: {sum(counts.values())} | Sin clasificar: {unclassified}")
    if counts:
        print(f"    Capas: {', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}\n")
    return result


# ─────────────────────────────────────────────
# REPORTES
# ─────────────────────────────────────────────

def print_console_report(result):
    print(f"\n{'═'*60}")
    print(f"  Microservicio : {result.repo_name}")
    print(f"{'═'*60}")
    if not result.violations:
        print("🎉  Sin violaciones. Cumple con el arquetipo hexagonal Ficohsa SB4.")
        return
    for severity in (Severity.ERROR, Severity.WARNING, Severity.INFO):
        group = [v for v in result.violations if v.severity == severity]
        if not group:
            continue
        icon = {"ERROR": "❌", "WARNING": "⚠️ ", "INFO": "ℹ️ "}[severity.value]
        print(f"\n{'─'*60}\n{icon}  {severity.value}S ({len(group)})\n{'─'*60}")
        for v in group:
            loc = v.file + (f":{v.line}" if v.line else "")
            print(f"  [{v.rule}]\n    Archivo : {loc}\n    Mensaje : {v.message}\n")
    print(f"\n{'═'*60}\nRESUMEN: {result.summary()}\n{'═'*60}\n")


def generate_json_report(result, output_path):
    data = {
        "microservice": result.repo_name,
        "repo_path": result.repo_path,
        "archetype": "ficohsa-webflux-springboot4",
        "generated_at": datetime.now(timezone(timedelta(hours=-6))).isoformat(),
        "summary": {
            "errors": len(result.errors), "warnings": len(result.warnings),
            "infos": len(result.infos), "total": len(result.violations),
        },
        "violations": [
            {"severity": v.severity.value, "rule": v.rule, "file": v.file,
             "line": v.line, "message": v.message}
            for v in result.violations
        ],
    }
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"📝  Reporte JSON generado: {output_path}")


def generate_html_report(result, output_path):
    rows = ""
    for v in result.violations:
        color = {"ERROR": "#fee2e2", "WARNING": "#fef9c3", "INFO": "#e0f2fe"}.get(v.severity.value, "#f9fafb")
        badge = {"ERROR": "#dc2626", "WARNING": "#d97706", "INFO": "#0284c7"}.get(v.severity.value, "#6b7280")
        loc = v.file + (f":{v.line}" if v.line else "")
        rows += (f'<tr style="background:{color}"><td><span style="background:{badge};color:white;'
                 f'padding:2px 8px;border-radius:4px;font-size:12px">{v.severity.value}</span></td>'
                 f'<td style="font-family:monospace;font-size:12px">{v.rule}</td>'
                 f'<td style="font-family:monospace;font-size:11px;word-break:break-all">{loc}</td>'
                 f'<td>{v.message}</td></tr>')
    errors_count = len(result.errors)
    warnings_count = len(result.warnings)
    status_color = "#dc2626" if errors_count else ("#d97706" if warnings_count else "#16a34a")
    status_text = "FALLÓ" if errors_count else ("ADVERTENCIAS" if warnings_count else "APROBÓ")
    html = f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Hexagonal v3 SB4 — {result.repo_name}</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:20px;background:#f8fafc;color:#1e293b}}
h1{{color:#0f172a}} .status{{display:inline-block;padding:4px 16px;border-radius:20px;color:white;font-weight:bold;background:{status_color}}}
.summary{{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}} .card{{background:white;border-radius:8px;padding:16px 24px;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:120px}}
.card .number{{font-size:32px;font-weight:bold}} .card .label{{font-size:14px;color:#64748b}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#1e293b;color:white;padding:10px 12px;text-align:left;font-size:13px}} td{{padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;vertical-align:top}}
.ts{{color:#64748b;font-size:12px}}</style></head><body>
<h1>🏛️ Validación Hexagonal v3 — Ficohsa WebFlux (Spring Boot 4)</h1>
<p>📦 Microservicio: <strong>{result.repo_name}</strong></p>
<p class="ts">Generado: {datetime.now(timezone(timedelta(hours=-6))).strftime('%Y-%m-%d %H:%M:%S')} | Estado: <span class="status">{status_text}</span></p>
<div class="summary">
<div class="card"><div class="number" style="color:#dc2626">{errors_count}</div><div class="label">Errores</div></div>
<div class="card"><div class="number" style="color:#d97706">{warnings_count}</div><div class="label">Advertencias</div></div>
<div class="card"><div class="number" style="color:#0284c7">{len(result.infos)}</div><div class="label">Infos</div></div>
<div class="card"><div class="number">{len(result.violations)}</div><div class="label">Total</div></div></div>
<table><thead><tr><th>Severidad</th><th>Regla</th><th>Archivo</th><th>Mensaje</th></tr></thead>
<tbody>{rows if rows else '<tr><td colspan="4" style="text-align:center;padding:20px;color:#16a34a">✅ Sin violaciones</td></tr>'}</tbody></table>
</body></html>"""
    output_path.write_text(html, encoding="utf-8")
    print(f"🌐  Reporte HTML generado: {output_path}")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Validador de Arquitectura Hexagonal v3 — Arquetipo Ficohsa WebFlux (Spring Boot 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python validation-hexagonal-v3.py /ruta/al/repo
  python validation-hexagonal-v3.py /ruta/al/repo --report all --output /tmp/reportes
  python validation-hexagonal-v3.py /ruta/al/repo --only errors --fail-on-errors
  python validation-hexagonal-v3.py /ruta/al/repo --base-package com.ficohsa
        """)
    parser.add_argument("repo", help="Ruta al repositorio a validar")
    parser.add_argument("--report", choices=["console", "json", "html", "all"], default="console")
    parser.add_argument("--output", default=".", help="Directorio de salida para reportes")
    parser.add_argument("--only", choices=["errors", "warnings", "all"], default="all")
    parser.add_argument("--fail-on-errors", action="store_true", help="Exit code 1 si hay errores (CI)")
    parser.add_argument("--base-package", default="com.ficohsa",
                        help="Paquete raíz de la organización (default: com.ficohsa)")
    args = parser.parse_args()

    repo_root = Path(args.repo)
    result = validate_repo(repo_root, base_package=args.base_package)

    if args.only == "errors":
        result.violations = result.errors
    elif args.only == "warnings":
        result.violations = result.warnings

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    repo_name = os.environ.get("REPO_NAME", Path(args.repo).resolve().name)
    timestamp = datetime.now(timezone(timedelta(hours=-6))).strftime("%Y%m%d_%H%M%S")
    report_base = f"{repo_name}_{timestamp}"

    if args.report in ("console", "all"):
        print_console_report(result)
    if args.report in ("json", "all"):
        generate_json_report(result, output_dir / f"{report_base}.json")
    if args.report in ("html", "all"):
        generate_html_report(result, output_dir / f"{report_base}.html")

    if args.fail_on_errors and result.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
