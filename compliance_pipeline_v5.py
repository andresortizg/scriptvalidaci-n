#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
PIPELINE DE COMPLIANCE v5 - Ficohsa Microservicios (Spring Boot 4)
═══════════════════════════════════════════════════════════════════════════════

Base estructural: compliance_pipeline_v3.py (análisis por criterio con ComplianceResult
+ enrichment map de observaciones accionables). Reglas actualizadas al arquetipo destino
del TD `ficohsa-springboot3-to-4-migration` (spec td-hexagonal-guidelines-update,
reglas finales Wave 1-4 post-supersession).

Cambios de reglas respecto a v3 (Spring Boot 3):
  - Spring Boot 4.1.x aceptado (prefijo "4.1."; 4.0.0 rechazado)
  - Librerías con prefijo webflux-* (solo repos lib-java-webflux_*); versiones reales
      verificadas del build.gradle de cada repo (ver LIB_MIN_VERSIONS). Ej: logging=1.2.0,
      web-client=1.2.0, resilience=2.0.1, aws-dynamo=1.0.1, resto=1.0.0
  - Jackson 3: prohibido com.fasterxml.jackson.{databind,core,datatype}; annotation permitido;
      prohibido withCoercionConfigFor; prohibido jackson-datatype-jsr310
  - @FicohsaResilience dinámico: perRegion = true, resilienceConfigParam = nombre de
      parámetro del método; método público. NO se valida la firma para sourceBank:
      la resolución por región la hace la librería (ResilienceAspect), no el micro.
  - MapStruct mappers obligatorios (componentModel="spring"); Request envelope RequestModel<D>
      vía RestComponent (sin getRequestType())
  - DTOs como record; @LogExternalCall con provider resoluble;
      Caller-Service propagado automáticamente (prohibido manual)
  - Regionalización: ficohsa.regionalization solo functionName + cache-local (trimmed)
  - Cobertura mínima 85% por módulo; cm.yaml sin literales; mask-fields obligatorio
  - Tallaje: variable ms-sizing (XS/S/M/L/XL) en el Variable Group
  - Estructura: main.gradle (estándar, con subprojects) + build.gradle raíz +
      application.yml + banner.txt

Uso (modo --single: SIEMPRE EN VIVO Azure Library + AWS):
  export AZURE_DEVOPS_PAT="<pat>"          # para consultar el Variable Group en vivo
  aws sso login --profile <perfil>          # para Parameter Store / Secrets / DynamoDB
  python3 compliance_pipeline_v5.py --single /path/to/microservice
  python3 compliance_pipeline_v5.py --single /path/to/microservice --format all --output /tmp
  python3 compliance_pipeline_v5.py --single /path/to/microservice --no-aws   # sin validaciones AWS
  El ambiente (dev/stg/uat/prd) se deriva de la rama git; --env lo fuerza; la tabla DynamoDB
  por defecto es ban-xrs-ic-ddb-support-get-params-{env}.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone, timedelta

try:
    # Catálogo ÚNICO de estrategias de enmascarado (compartido con la validación de la ET).
    from et_checks import MASK_STANDARDS
except Exception:
    MASK_STANDARDS = {"default", "m_account", "m_id", "m_card"}


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN — VERSIONES Y CATÁLOGO (Wave 4 / ODD 14 / D6)
# ═══════════════════════════════════════════════════════════════════════════════

# Versión mínima por librería webflux-*. Valores alineados con la versión efectiva
# publicada en el build.gradle de cada repositorio lib-* (ver carpeta lineamientos/).
# Solo se catalogan los repos lib-java-webflux_* con artefacto webflux-* real (verificado
# tras git pull en el build.gradle de cada repo). Se EXCLUYEN por decisión de alcance:
# webflux-rest-lib (artifact -lib, SB3), base64topdf (artifact no webflux), y los repos
# vacíos sin build (aurorapg, kafka, secret, sns, sqs). Otras libs fuera de convención
# (cache_key_generator, calculate-hash-handler, authorization_filter, error-lib) tampoco.
LIB_MIN_VERSIONS = {
    "webflux-core":                       "1.0.3",
    "webflux-router":                     "1.0.2",
    "webflux-exception":                  "2.0.2",
    "webflux-logging":                    "1.2.2",
    "webflux-web-client":                 "1.2.1",
    "webflux-resilience":                 "2.0.2",
    "webflux-regionalization":            "1.0.1",
    "webflux-homologator":                "1.0.1",
    "webflux-aws-lambda":                 "1.0.0",
    "webflux-aws-parameter":              "1.0.0",
    "webflux-aws-secrets":                "1.0.0",
    "webflux-aws-s3":                     "1.0.0",
    "webflux-aws-dynamo":                 "1.0.1",
    "webflux-bitmap":                     "1.0.0",
    "webflux-generate-hash":              "1.0.0",
    "webflux-identifier-generator":       "1.0.0",
    "webflux-auth-filter-spring-core":    "1.0.0",
    "webflux-auth-lambda-resolver-core":  "1.0.0",
    "webflux-authorization-filter-core":  "1.0.0",
}

ACCEPTED_BOOT_PREFIXES = ("4.1.",)
MIN_COVERAGE = 85

DEPRECATED_LOGGING_ARTIFACTS = [
    "webflux-logging-domain", "webflux-logging-infrastructure",
    "webflux-logging-clients", "webflux-logging-spring-boot-starter",
]
FORBIDDEN_DEPS = ["spring-cloud-openfeign", "jackson-datatype-jsr310"]
FORBIDDEN_DIRECT_RESILIENCE4J = [
    "resilience4j-circuitbreaker", "resilience4j-reactor",
    "resilience4j-timelimiter", "resilience4j-spring-boot3",
]

# Criterios críticos — exit code 1 si NO CUMPLEN (con --fail-on-critical)
CRITICAL_CRITERIA = {
    "arquetipo", "librerias_ficohsa", "jackson3", "logging",
    "resilience", "cobertura", "configmap", "vg_cm_alineacion", "aws_recursos",
}

# Criterios que solo aplican una vez migrado a SB4 (en SB3 se marcan NO ENCONTRADO, no NO CUMPLE)
_SB4_ONLY_CRITERIA = {
    "arquetipo", "librerias_ficohsa", "jackson3", "resilience",
    "mappers", "envelope", "caller_service", "regionalizacion", "dtos",
    "cobertura", "configmap", "logging",
}


# ═══════════════════════════════════════════════════════════════════════════════
# MODELO DE RESULTADO (misma forma que compliance_pipeline_v3.py)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ComplianceResult:
    """Resultado de un check individual."""
    criterion: str
    compliant: Optional[object]  # True=cumple, False=no cumple, None=N/A, "not_found"=no encontrado
    positives: list = field(default_factory=list)
    issues: list = field(default_factory=list)

    @property
    def status(self):
        if self.compliant is True:
            return "CUMPLE"
        elif self.compliant is False:
            return "NO CUMPLE"
        elif self.compliant == "not_found":
            return "NO ENCONTRADO"
        elif self.compliant == "partial":
            return "PARCIAL"
        return "N/A"

    @property
    def is_critical(self):
        return self.criterion in CRITICAL_CRITERIA

    @property
    def explanation_compliant(self):
        return "\n".join(f"• {p}" for p in self.positives) if self.positives else ""

    @property
    def explanation_non_compliant(self):
        return "\n".join(f"• {n}" for n in self.issues) if self.issues else ""

    @property
    def observation_summary(self):
        """Resumen accionable: cada issue enriquecido con Falla / Se requiere / Acción."""
        parts = []
        if self.issues:
            for issue in self.issues[:3]:
                parts.append(_enrich_observation(issue, self.criterion))
        elif self.positives:
            parts.extend(self.positives[:2])
        return " | ".join(parts)


# ── Enrichment map: observaciones detalladas y accionables ────────────────────

_OBSERVATION_ENRICHMENT = {
    # ── Arquetipo / estructura ──
    r"build\.gradle NO encontrado": (
        "No existe build.gradle en la raíz del proyecto.",
        "Se requiere build.gradle en la raíz (arquetipo SB4 multi-módulo).",
        "Acción: Crear build.gradle raíz con architectureConfig y las tareas de estructura."
    ),
    r"main\.gradle NO encontrado": (
        "No existe main.gradle en la raíz.",
        "El arquetipo SB4 requiere main.gradle con la config común de subprojects.",
        "Acción: Crear main.gradle con subprojects{} (plugins, Java 21, BOM, cobertura, -parameters, libs Ficohsa)."
    ),
    r"application\.yml NO encontrado": (
        "No se encontró application.yml.",
        "Se requiere applications/app-service/src/main/resources/application.yml.",
        "Acción: Crear application.yml con server, spring, springdoc, actuator, ficohsa.logging, error-mapping."
    ),
    r"banner\.txt NO encontrado": (
        "Falta el banner.txt obligatorio.",
        "Se requiere applications/app-service/src/main/resources/banner.txt (formato ANSI estándar).",
        "Acción: Agregar banner.txt en resources del app-service."
    ),
    r"carpetas no permitidas en la ra[ií]z": (
        "La raíz del repo tiene carpetas que no son del arquetipo SB4.",
        "En la raíz solo se permiten: applications, domain, infrastructure, gradle, k8s.",
        "Acción: Eliminar o reubicar las carpetas extra; mover su contenido a la capa que "
        "corresponda del arquetipo hexagonal (o quitarlas del control de versiones si son generadas)."
    ),
    r"Spring Boot .* NO aceptad": (
        "La versión de Spring Boot no es la aceptada.",
        "Se requiere Spring Boot 4.1.x (4.0.0 rechazado).",
        "Acción: Fijar springBootVersion=4.1.0 en gradle.properties / plugin."
    ),
    r"Gradle .* < 8\.14": (
        "El Gradle wrapper es inferior a 8.14.",
        "Se requiere Gradle >= 8.14.",
        "Acción: Actualizar gradle/wrapper/gradle-wrapper.properties a >= 8.14."
    ),
    # ── Librerías ──
    r"sin prefijo webflux-": (
        "Hay dependencias internas sin el prefijo webflux-.",
        "Se requiere que todas las librerías Ficohsa usen el prefijo webflux-*.",
        "Acción: Renombrar com.ficohsa.lib:<x> a com.ficohsa.lib:webflux-<x> en libs.versions.toml."
    ),
    r"artefacto de logging obsoleto": (
        "Hay artefactos de logging obsoletos (pre-consolidación).",
        "Se requiere el artefacto consolidado webflux-logging (OPTION A).",
        "Acción: Reemplazar webflux-logging-domain/infrastructure/clients/spring-boot-starter por webflux-logging."
    ),
    r"versión .* < .* requerida": (
        "Una librería webflux-* tiene versión inferior a la mínima.",
        "Se requiere regionalization/resilience >= 2.0.0 y el resto >= 1.0.0.",
        "Acción: Alinear versiones en libs.versions.toml a las versiones finales del TD."
    ),
    r"resilience4j directo": (
        "Se declara resilience4j directamente.",
        "resilience4j llega transitivo vía webflux-resilience (A3); no se declara directo.",
        "Acción: Eliminar resilience4j-* de libs.versions.toml/build.gradle; declarar solo ficohsa-resilience."
    ),
    r"No se detectaron librerías": (
        "No se detectaron librerías com.ficohsa.lib:webflux-*.",
        "Se requiere el ecosistema webflux-* del arquetipo.",
        "Acción: Agregar las dependencias webflux-* necesarias en libs.versions.toml."
    ),
    # ── Jackson 3 ──
    r"import.*Jackson 2": (
        "Hay imports de Jackson 2 (databind/core/datatype).",
        "Jackson 3 usa tools.jackson.*; solo las anotaciones com.fasterxml.jackson.annotation.* permanecen.",
        "Acción: Migrar databind/core/datatype a tools.jackson.* (A1)."
    ),
    r"withCoercionConfigFor": (
        "Se usa .withCoercionConfigFor(...) (API de Jackson 2).",
        "En Jackson 3 el método correcto es .withCoercionConfig(...).",
        "Acción: Reemplazar .withCoercionConfigFor(...) por .withCoercionConfig(...)."
    ),
    r"jackson-datatype-jsr310": (
        "Se declara jackson-datatype-jsr310.",
        "En Jackson 3 el soporte de fechas está en el core; jsr310 no existe.",
        "Acción: Eliminar jackson-datatype-jsr310 de libs.versions.toml/build.gradle."
    ),
    r"dependencia Jackson 2 '": (
        "Se declara una dependencia directa de Jackson 2 (databind/core/datatype).",
        "En Jackson 3 el databind/core vive en tools.jackson.*; solo jackson-annotations se mantiene.",
        "Acción: Reemplazar la dependencia por tools.jackson.core:jackson-databind (Jackson 3)."
    ),
    # ── Logging ──
    r"ficohsa\.logging NO configurado": (
        "Falta la sección ficohsa.logging en application.yml.",
        "Se requiere configurar ficohsa.logging con service-name, mask-confidential, format.",
        "Acción: Agregar la sección ficohsa.logging en application.yml."
    ),
    r"mask-fields NO configurado": (
        "Falta la entrada mask-fields obligatoria.",
        "Se requiere 'mask-fields: ${LOGGING_MASK_FIELDS:}' bajo ficohsa.logging.",
        "Acción: Agregar mask-fields en application.yml y LOGGING_MASK_FIELDS en cm.yaml."
    ),
    r"config de logging propia": (
        "Existe configuración de logging propia (logback/log4j2).",
        "La librería webflux-logging provee la config; no debe haber archivos propios.",
        "Acción: Eliminar logback*.xml / log4j2*.xml del proyecto."
    ),
    r"flag -parameters": (
        "El proyecto usa @LogExternalCall pero no compila con -parameters.",
        "El aspecto resuelve provider/operation/version por nombre de parámetro desde el bytecode; requiere -parameters.",
        "Acción: Agregar '-parameters' a options.compilerArgs en tasks.withType(JavaCompile), dentro de subprojects (main.gradle/build.gradle)."
    ),
    r"aop\.enabled NO está en true": (
        "@LogExternalCall no se activará: falta ficohsa.logging.aop.enabled = true.",
        "El AOP de webflux-logging se habilita con ficohsa.logging.aop.enabled: true.",
        "Acción: Agregar 'aop: { enabled: true }' bajo ficohsa.logging en application.yml."
    ),
    r"estrategia\(s\) de maskfield inválida": (
        "Se usan estrategias de enmascarado no soportadas.",
        "Las estrategias válidas son las del catálogo de enmascarado (m_*, default, object, full; ver MASK_STANDARDS en et_checks.py).",
        "Acción: Corregir el formato 'campo/estrategia' en mask-fields / mask-fields-by-path."
    ),
    r"falta ficohsa\.logging\.masking\.table-name": (
        "El masking por DynamoDB está habilitado pero no se define la tabla.",
        "Se requiere ficohsa.logging.masking.table-name cuando el masking DynamoDB está activo.",
        "Acción: Definir masking.table-name (y LOGGING_MASKING_TABLE_NAME en cm.yaml)."
    ),
    # ── Resilience ──
    r"modo deprecado": (
        "Se usa @FicohsaResilience en modo deprecado (label/paramName/paramLabel).",
        "Se requiere el modo dinámico (perRegion=true, resilienceConfigParam) o el estático.",
        "Acción: Migrar a @FicohsaResilience(instanceName=<método>, perRegion=true, resilienceConfigParam=\"resilienceParam\")."
    ),
    r"sin perRegion = true": (
        "El modo dinámico no fija perRegion = true.",
        "Los adapters regionalizados usan perRegion = true (el CB se resuelve por región).",
        "Acción: Agregar perRegion = true en la anotación @FicohsaResilience dinámica."
    ),

    r"resilienceConfigParam=.* pero no existe ese parámetro": (
        "resilienceConfigParam apunta a un parámetro que no existe en el método.",
        "El valor de resilienceConfigParam debe ser el nombre de un parámetro del método (String).",
        "Acción: Alinear resilienceConfigParam con el nombre real del parámetro (p. ej. resilienceParam)."
    ),
    r"debe ser público \(limitación de Spring AOP\)": (
        "El método con @FicohsaResilience no es público.",
        "Spring AOP proxy solo intercepta métodos públicos llamados desde fuera de la clase.",
        "Acción: Declarar el método como public."
    ),
    r"define resilience4j\.\*": (
        "application.yml define configuración resilience4j.* local.",
        "En el arquetipo la config de CB/TL viene de AWS Parameter Store, no del YAML.",
        "Acción: Eliminar el bloque resilience4j del application.yml."
    ),
    r"@FicohsaResilience sin instanceName": (
        "@FicohsaResilience se usa sin modo dinámico ni estático.",
        "Debe declararse instanceName (+resilienceConfigParam) para el modo dinámico.",
        "Acción: Agregar instanceName y resilienceConfigParam a la anotación."
    ),
    r"instanceName .* cb-": (
        "El instanceName usa el patrón cb-<sistema>-<capacidad>.",
        "El valor final del instanceName es el nombre del método del endpoint (constante in-code).",
        "Acción: Cambiar instanceName al nombre del método del endpoint (ej: retrieveMovements)."
    ),
    # ── Mappers ──
    r"sin mappers MapStruct": (
        "No se encontraron mappers MapStruct.",
        "MapStruct es obligatorio en el entry-point y en cada driven adapter.",
        "Acción: Crear mappers @Mapper(componentModel=\"spring\") (DTO→Command, Result→DTO; Command→RequestDto, ResponseDto→Result)."
    ),
    r"mapstruct NO está": (
        "mapstruct no está en el catálogo de dependencias.",
        "Se requiere mapstruct + mapstruct-processor (mappers obligatorios).",
        "Acción: Agregar mapstruct y mapstruct-processor en libs.versions.toml."
    ),
    r'@Mapper sin componentModel': (
        "Un @Mapper no declara componentModel = \"spring\".",
        "Sin componentModel=\"spring\" el mapper no se registra como bean e inyección falla.",
        "Acción: Cambiar la anotación a @Mapper(componentModel = \"spring\")."
    ),
    # ── Envelope ──
    r"getRequestType\(\)": (
        "Se usa el patrón getRequestType().",
        "Se requiere deserializar el envelope Ficohsa vía ParameterizedTypeReference<RequestModel<D>>.",
        "Acción: Eliminar getRequestType() y usar RequestModel<D> en los routers."
    ),
    r"usa Class<D> sin RequestModel": (
        "Un endpoint con body usa RestComponent con Class<D> en vez de RequestModel<D>.",
        "El body debe deserializarse como ParameterizedTypeReference<RequestModel<D>> (envelope Ficohsa).",
        "Acción: Cambiar la sobrecarga a post/put(path, new ParameterizedTypeReference<RequestModel<D>>(){}, handler)."
    ),
    r"RouterFunction manual sin RestComponent": (
        "Hay un router de negocio construido manualmente sin RestComponent.",
        "Los endpoints deben definirse con RestComponent de webflux-router (envelope, validación, links).",
        "Acción: Migrar el RouterFunction manual a RestComponent."
    ),
    # ── Caller-Service ──
    r"caller-service '.*': .*(componentes|minúsculas|tipo-api|versión|espacios|vacío|permiten)": (
        "El valor de caller-service no cumple el formato del lineamiento de Gobierno de APIs.",
        "Debe ser <service_domain>-<tipo-api>-<metodo> en minúsculas, sin versión (vN), "
        "service_domain y método con '_', y tipo-api en {sys, product, comp, exp, util}.",
        "Acción: Corregir el valor en la constante CALLER_SERVICE y en ficohsa.logging.caller-services "
        "(p. ej. '/credit-card-purchase/v1/execution' → 'credit_card_purchase-comp-execution')."
    ),
    r"Caller-Service.*manual": (
        "El header Caller-Service se setea manualmente en el adapter.",
        "El header se propaga automáticamente por webflux-web-client; no debe setearse manual.",
        "Acción: Eliminar headers.set(\"Caller-Service\", ...) del adapter (Req 57)."
    ),
    r"sin @LogExternalCall": (
        "Un método outbound del adapter no tiene @LogExternalCall.",
        "Se requiere @LogExternalCall(provider = \"<Servicio>\") en cada método outbound.",
        "Acción: Anotar el método outbound del adapter con @LogExternalCall(provider=...)."
    ),
    r"@LogExternalCall sin provider": (
        "Un @LogExternalCall no tiene el provider resoluble.",
        "El provider debe venir como atributo provider=\"...\" o como parámetro 'provider' del método.",
        "Acción: Agregar provider=\"<Servicio>\" a la anotación o un parámetro String provider al método."
    ),
    # ── Regionalización ──
    r"@ConfigurationProperties por operación": (
        "Hay @ConfigurationProperties de regionalización por operación (retirado).",
        "country/domain/name deben ser constantes private static final en el use case.",
        "Acción: Mover country/domain/name a constantes in-code y eliminar la clase de propiedades por operación."
    ),
    r"variables REGIONALIZATION_": (
        "Hay variables REGIONALIZATION_<OP>_* en config.",
        "Esos valores son business-identity in-code, no env vars.",
        "Acción: Remover REGIONALIZATION_<OP>_COUNTRY/DOMAIN/METHOD de application.yml y cm.yaml."
    ),
    r"ficohsa\.regionalization debe removerse": (
        "El bloque ficohsa.regionalization tiene claves de más.",
        "Se requiere solo functionName (ARN) + cache-local (trimmed, Req 60).",
        "Acción: Remover domain/default-version/retrieve del bloque y del record RegionalizationProperties."
    ),
    r"falta ficohsa\.regionalization\.function-name": (
        "El micro usa regionalización pero no declara function-name.",
        "ficohsa.regionalization.function-name (ARN de la Lambda) es obligatorio.",
        "Acción: Agregar function-name: ${LAMBDA_REGIONALIZATION_ARN} bajo ficohsa.regionalization."
    ),
    r"falta ficohsa\.homologator\.function-name": (
        "El micro usa homologación pero no declara function-name.",
        "ficohsa.homologator.function-name (ARN de la Lambda) es obligatorio.",
        "Acción: Agregar function-name: ${LAMBDA_FUNCTION_ARN} bajo ficohsa.homologator."
    ),
    r"falta el bloque ficohsa\.homologator": (
        "El micro usa homologación pero no configura el bloque ficohsa.homologator.",
        "Se requiere ficohsa.homologator.function-name con el ARN de la Lambda.",
        "Acción: Agregar el bloque ficohsa.homologator con function-name en application.yml."
    ),
    r"ttl-seconds = .* no es numérico": (
        "cache-local.ttl-seconds no es numérico.",
        "El TTL de la cache local debe ser un entero (segundos), default 86400.",
        "Acción: Corregir ttl-seconds a un valor numérico o ${VAR:86400}."
    ),
    # ── DTOs ──
    r"no es un record": (
        "Un DTO no es un Java record.",
        "Se requiere que los DTOs sean records (las anotaciones JSON son preserve-if-present).",
        "Acción: Convertir el DTO a record."
    ),
    r"record con @\w+ de Lombok": (
        "Un DTO record usa Lombok de mutabilidad (@Data/@Setter).",
        "Los records son inmutables; @Data/@Setter no aplican y señalan modelado incorrecto. "
        "(@Builder sí se permite: no rompe la inmutabilidad del record.)",
        "Acción: Eliminar @Data/@Setter del record DTO."
    ),
    # ── Cobertura ──
    r"cobertura .* 70": (
        "La cobertura mínima sigue en 70%.",
        "El mínimo es 85% por módulo (SUPERSEDE 70%).",
        "Acción: Actualizar architectureConfig a cobertura mínima 85% por módulo."
    ),
    r"umbral de cobertura no": (
        "No se detectó el umbral de cobertura.",
        "Se requiere architectureConfig con cobertura mínima 85% por módulo.",
        "Acción: Definir el umbral de 85% en el build.gradle raíz."
    ),
    r"architectureConfig NO": (
        "Falta el bloque architectureConfig.",
        "Se requiere architectureConfig (base package + cobertura mínima por módulo).",
        "Acción: Agregar architectureConfig y checkStructure/validateStructure en build.gradle raíz."
    ),
    # ── cm.yaml ──
    r"SERVER_ADDRESS": (
        "cm.yaml tiene SERVER_ADDRESS: 0.0.0.0 (literal).",
        "cm.yaml no debe tener literales hardcodeados.",
        "Acción: Reemplazar por un placeholder ${SERVER_ADDRESS} y definir en el Variable Group."
    ),
    r"SERVER_PORT": (
        "cm.yaml tiene SERVER_PORT: \"8080\" (literal).",
        "cm.yaml no debe tener literales hardcodeados.",
        "Acción: Reemplazar por ${SERVER_PORT}."
    ),
    r"path/url hardcodeado": (
        "cm.yaml tiene un valor de path/url hardcodeado.",
        "Todo valor en cm.yaml debe ser un placeholder ${...}.",
        "Acción: Reemplazar el literal por ${VARIABLE} y definir en el Variable Group."
    ),
    r"env vars sin default no definidas en cm\.yaml": (
        "Hay env vars obligatorias (sin default) usadas en application.yml que no están en cm.yaml.",
        "El ConfigMap debe definir toda variable ${VAR} sin default (salvo las de plataforma "
        "como OTEL_*, que inyecta el entorno) o el micro no arranca.",
        "Acción: Agregar esas claves al cm.yaml (y al Variable Group)."
    ),
    r"falta el endpoint de traces OTEL": (
        "El application.yml no exporta traces al collector de observabilidad.",
        "El estándar de observabilidad usa ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces.",
        "Acción: Configurar el endpoint de tracing como ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces."
    ),
    r"falta la URL de metrics OTEL": (
        "El application.yml no exporta métricas al collector de observabilidad.",
        "El estándar de observabilidad usa ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics.",
        "Acción: Configurar metrics.export.url como ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics."
    ),
    # ── Credenciales / excepciones ──
    r"credencial .* valor real|valor real expuesto|comentada con valor real": (
        "gradle.properties expone credenciales con valores reales.",
        "Las credenciales deben usar placeholders, nunca valores reales (ni comentados).",
        "Acción: Usar azuredo_user=$(azuredo_user), etc."
    ),
    r"excepción custom": (
        "Hay excepciones custom del proyecto.",
        "No se permiten excepciones custom; usar la librería Ficohsa (com.ficohsa.lib.core.exception.*).",
        "Acción: Eliminar las excepciones custom y lanzar vía la librería / error-mapping (D2 2.2)."
    ),
    # ── Tallaje EKS ──
    r"falta la variable ms-sizing": (
        "El Variable Group no define la variable ms-sizing.",
        "Se requiere ms-sizing con una talla válida (XS/S/M/L/XL) en la Library de Azure DevOps.",
        "Acción: Agregar la variable ms-sizing al Variable Group del micro con la talla que corresponda."
    ),
    r"ms-sizing = .* no es una talla válida": (
        "ms-sizing tiene un valor fuera del catálogo de tallas.",
        "Las tallas válidas son XS, S, M, L, XL (catálogo de tallaje EKS).",
        "Acción: Corregir ms-sizing a una talla válida según el P99 de memoria del micro."
    ),
    r"no coincide con talla": (
        "Los resources aplicados no coinciden con el catálogo de la talla declarada.",
        "requests/limits de CPU y memoria deben seguir el catálogo de la talla (ms-sizing).",
        "Acción: Alinear resources-request/limits-cpu/memory a los valores de la talla en el Variable Group."
    ),
}


def _enrich_observation(issue: str, criterion: str) -> str:
    for pattern, (falla, requiere, accion) in _OBSERVATION_ENRICHMENT.items():
        if re.search(pattern, issue, re.IGNORECASE):
            return f"{falla} {requiere} {accion}"
    return issue


# ═══════════════════════════════════════════════════════════════════════════════
# UTILIDADES
# ═══════════════════════════════════════════════════════════════════════════════

def _read(path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return ""


def _strip_java_comments(content: str) -> str:
    """Elimina comentarios Java (bloque /* */ incl. Javadoc, y línea //) preservando
    los saltos de línea para no desalinear números de línea. Útil para que menciones de
    anotaciones dentro de Javadoc (p. ej. {@code @FicohsaResilience}) NO se tomen como uso
    real. No intenta respetar literales string con '//' (suficiente para estos checks)."""
    def _keep_newlines(m):
        return "".join(ch for ch in m.group(0) if ch == "\n")
    # bloque /* ... */ (incluye Javadoc /** ... */)
    content = re.sub(r"/\*.*?\*/", _keep_newlines, content, flags=re.DOTALL)
    # línea // ... hasta fin de línea
    content = re.sub(r"//[^\n]*", "", content)
    return content


def _parse_version(s):
    parts = re.findall(r"\d+", s)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_gte(v, minimum):
    return _parse_version(v) >= _parse_version(minimum)


def _iter_java(repo_root):
    for f in repo_root.rglob("*.java"):
        s = str(f)
        if "/build/" not in s and "/.git/" not in s:
            yield f


def _iter_gradle(repo_root):
    for pat in ("*.gradle", "*.toml"):
        for f in repo_root.rglob(pat):
            s = str(f)
            if "/build/" not in s and "/.git/" not in s:
                yield f


def _all_gradle(repo_root):
    return "\n".join(_read(f) for f in _iter_gradle(repo_root))


def _detect_ficohsa_libs(repo_root, all_gradle=None):
    """Detecta librerías Ficohsa en cualquiera de los formatos usados. Reconoce dos
    grupos Maven: `com.ficohsa.lib:` (convención principal) y `com.ficohsa:` (algunas
    librerías como webflux-rest-lib o lib-java-cache_key_generator-xrs publican bajo
    este grupo). Formatos soportados:
      - inline en build.gradle:  implementation 'com.ficohsa.lib:webflux-core:1.0.0'
      - TOML version catalog:     ficohsa-core = { module = "com.ficohsa.lib:core", version.ref = "..." }
      - TOML módulo sin versión:   { module = "com.ficohsa.lib:web-client" }
    Retorna {artifact: version|'catalog-ref'}.
    El prefijo de grupo `com.ficohsa(.lib)?:` va seguido de un artefacto que NO empieza
    por `lib.` para no confundir el segmento de grupo con el artefacto.
    """
    if all_gradle is None:
        all_gradle = _all_gradle(repo_root)
    detected = {}
    # Prefijo de grupo: com.ficohsa.lib:  o  com.ficohsa:  (este último con lookahead
    # negativo para no capturar el ".lib:" del grupo largo como si fuera el artefacto).
    grp = r"com\.ficohsa(?:\.lib)?:"
    # 1) module = "<grupo>:<artifact>"  (formato TOML; la versión va aparte por version.ref)
    for m in re.finditer(r'module\s*=\s*["\']' + grp + r'([\w.-]+)["\']', all_gradle):
        detected.setdefault(m.group(1), "catalog-ref")
    # 2) "<grupo>:<artifact>:<version>"  (formato inline con versión pegada)
    for m in re.finditer(grp + r"([\w.-]+):([^\s'\"]+)", all_gradle):
        art, ver = m.group(1), m.group(2)
        detected[art] = "catalog-ref" if (ver.startswith("$") or "{" in ver) else ver
    # 3) "<grupo>:<artifact>"  suelto (sin versión) que no haya sido capturado arriba
    for m in re.finditer(grp + r"([\w.-]+)(?=['\"\s])", all_gradle):
        detected.setdefault(m.group(1), "catalog-ref")
    return detected


def _resolve_micro_lib_versions(repo_root):
    """Versión REAL que usa el micro por artefacto webflux-*, resolviendo las
    version.ref del libs.versions.toml. Devuelve {artifact: version|'?'}.
    Combina la detección inline con el mapeo [versions] del catálogo."""
    repo_root = Path(repo_root)
    all_gradle = _all_gradle(repo_root)
    detected = _detect_ficohsa_libs(repo_root, all_gradle)
    toml = _read(repo_root / "gradle" / "libs.versions.toml") or ""
    # [versions] alias = "x.y.z"
    versions = dict(re.findall(r'^\s*([\w.-]+)\s*=\s*["\']([^"\']+)["\']', toml, re.MULTILINE))
    # module = "com.ficohsa.lib:<art>", version.ref = "<alias>"  -> art: versions[alias]
    ref_by_art = {}
    for m in re.finditer(r'module\s*=\s*["\']com\.ficohsa(?:\.lib)?:([\w.-]+)["\'][^}\n]*version\.ref\s*=\s*["\']([\w.-]+)["\']', all_gradle):
        art, alias = m.group(1), m.group(2)
        if alias in versions:
            ref_by_art[art] = versions[alias]
    out = {}
    for art, ver in detected.items():
        if ver and ver != "catalog-ref":
            out[art] = ver
        elif art in ref_by_art:
            out[art] = ref_by_art[art]
        else:
            out[art] = "?"   # declarada por catálogo pero sin version.ref resoluble
    return out


def _find_build_gradle(repo_root):
    p = repo_root / "build.gradle"
    return p if p.exists() else None


def _find_app_yml(repo_root):
    p = repo_root / "applications" / "app-service" / "src" / "main" / "resources" / "application.yml"
    if p.exists():
        return p
    p2 = repo_root / "src" / "main" / "resources" / "application.yml"
    return p2 if p2.exists() else None


def _find_cm_yaml(repo_root):
    for cand in ("k8s/cm.yaml", "k8s/cm.yml", "cm.yaml"):
        p = repo_root / cand
        if p.exists():
            return p
    for f in repo_root.rglob("cm.yaml"):
        if "/.git/" not in str(f):
            return f
    return None


def detect_migration_state(repo_root):
    """Determina si el repo ya está migrado al arquetipo SB4 o sigue en SB3.

    Señales de SB4: librerías con prefijo webflux-*, Spring Boot 4.1.x.
    Señales de SB3: librerías com.ficohsa.lib sin prefijo (core/router/...), Spring Boot 3.x.
    Nota: main.gradle NO es señal — el arquetipo SB4 también lo usa (main.gradle estándar).

    Retorna 'sb4', 'sb3' o 'unknown'.
    """
    all_gradle = _all_gradle(repo_root)
    libs = _detect_ficohsa_libs(repo_root, all_gradle)
    has_webflux = any(a.startswith("webflux-") for a in libs)
    has_legacy = any(not a.startswith("webflux-") for a in libs)
    boot = _spring_boot_version(repo_root)

    sb4_signals = sum([has_webflux, boot.startswith("4.1.")])
    sb3_signals = sum([has_legacy and not has_webflux, boot.startswith("3.")])

    if has_webflux or boot.startswith("4.1."):
        return "sb4"
    if sb3_signals >= 2:
        return "sb3"
    if libs or boot:
        return "sb3" if sb3_signals > sb4_signals else "sb4"
    return "unknown"


def _spring_boot_version(repo_root):
    build = _read(_find_build_gradle(repo_root)) if _find_build_gradle(repo_root) else ""
    toml = _read(repo_root / "gradle" / "libs.versions.toml")
    props = _read(repo_root / "gradle.properties")

    def _resolve(v):
        """Resuelve una versión que puede venir como interpolación de variable Gradle
        (p. ej. "${springBootVersion}" o "$springBootVersion"). Si es una variable,
        busca su valor en gradle.properties; si no, devuelve el valor tal cual."""
        if not v:
            return v
        mvar = re.fullmatch(r"\$\{?([\w.]+)\}?", v.strip())
        if mvar:
            var = mvar.group(1).split(".")[-1]  # p. ej. springBootVersion
            mp = re.search(rf"{re.escape(var)}\s*=\s*['\"]?([^'\"\s]+)", props)
            return mp.group(1) if mp else ""
        return v

    for content in (build, toml):
        m = re.search(r"id\s+['\"]org\.springframework\.boot['\"]\s+version\s+['\"]([^'\"]+)['\"]", content)
        if m:
            return _resolve(m.group(1))
        m = re.search(r"org\.springframework\.boot['\"]?\s*version\s*['\"]([^'\"]+)['\"]", content)
        if m:
            return _resolve(m.group(1))
        m = re.search(r"spring-?boot(?:-version)?\s*=\s*['\"]?(\$\{?[\w.]+\}?|\d+\.\d+\.\d+)", content)
        if m:
            return _resolve(m.group(1))
    m = re.search(r"springBootVersion\s*=\s*(\d+\.\d+\.\d+)", props)
    return m.group(1) if m else ""


# ═══════════════════════════════════════════════════════════════════════════════
# CHECKS POR CRITERIO
# ═══════════════════════════════════════════════════════════════════════════════

# Carpetas permitidas en la RAÍZ del arquetipo SB4 (verificado contra los micros al 100%:
# vision_plus-wrapper-v2, credit_card_details-comp, customer_profile_retrieves-v2,
# data_warehouse-wrapper). Cualquier otra carpeta versionada en la raíz es una desviación
# del arquetipo y se marca como error.
_ALLOWED_ROOT_DIRS = {"applications", "domain", "infrastructure", "gradle", "k8s"}

# Carpetas que NO cuentan: artefactos generados / locales / de herramienta (no versionados
# o ignorados). Nunca indican una desviación del arquetipo.
_IGNORED_ROOT_DIRS = {
    ".git", ".gradle", "build", "build-cache", "bin", "out", ".idea", ".vscode",
    ".settings", ".venv", "boot", "node_modules", "target",
}


def _root_tracked_dirs(repo_root) -> list:
    """Carpetas en la RAÍZ del repo, preferentemente las VERSIONADAS en git
    (git ls-tree), para no contar artefactos generados (build, .gradle, etc.).
    Fallback al listado del disco filtrando _IGNORED_ROOT_DIRS si git no está disponible."""
    import subprocess as _sp
    try:
        r = _sp.run(["git", "ls-tree", "-d", "--name-only", "HEAD"],
                    cwd=str(repo_root), capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            dirs = [d.strip().strip("/") for d in r.stdout.splitlines() if d.strip()]
            # ls-tree de la raíz devuelve solo nombres de primer nivel; filtra artefactos.
            return [d for d in dirs if d and d not in _IGNORED_ROOT_DIRS]
    except Exception:
        pass
    # Fallback: disco.
    out = []
    try:
        for p in Path(repo_root).iterdir():
            if p.is_dir() and p.name not in _IGNORED_ROOT_DIRS and not p.name.startswith("."):
                out.append(p.name)
    except OSError:
        pass
    return out


def check_arquetipo(repo_root) -> ComplianceResult:
    pos, iss = [], []
    build = _find_build_gradle(repo_root)
    if not build:
        return ComplianceResult("arquetipo", False, [], ["build.gradle NO encontrado en la raíz"])
    pos.append("build.gradle en la raíz")

    # Estructura de carpetas en la raíz: solo se permiten las del arquetipo SB4.
    # Cualquier carpeta extra versionada (que no sea artefacto generado) es desviación.
    root_dirs = set(_root_tracked_dirs(repo_root))
    extra_dirs = sorted(root_dirs - _ALLOWED_ROOT_DIRS)
    if extra_dirs:
        iss.append("carpetas no permitidas en la raíz: " + ", ".join(extra_dirs)
                   + f" (solo se permiten: {', '.join(sorted(_ALLOWED_ROOT_DIRS))})")
    else:
        pos.append("estructura de carpetas raíz correcta (solo arquetipo SB4)")

    # main.gradle: el estándar real de Ficohsa (runbook webflux-logging y micros
    # migrados a SB4) mantiene main.gradle con el bloque subprojects{} (deps base y
    # el flag -parameters). Por tanto su presencia NO es incumplimiento; es informativa.
    if (repo_root / "main.gradle").exists():
        pos.append("main.gradle presente (subprojects con deps base y -parameters)")
    else:
        pos.append("sin main.gradle (deps base en build.gradle raíz)")

    if _find_app_yml(repo_root):
        pos.append("application.yml presente")
    else:
        iss.append("application.yml NO encontrado")

    banner = repo_root / "applications" / "app-service" / "src" / "main" / "resources" / "banner.txt"
    if banner.exists():
        pos.append("banner.txt presente")
    else:
        iss.append("banner.txt NO encontrado")

    boot = _spring_boot_version(repo_root)
    if boot:
        if boot.startswith(ACCEPTED_BOOT_PREFIXES):
            pos.append(f"Spring Boot {boot}")
        else:
            iss.append(f"Spring Boot {boot} NO aceptado (se requiere 4.1.x)")
    else:
        iss.append("Versión de Spring Boot no detectada")

    wrapper = repo_root / "gradle" / "wrapper" / "gradle-wrapper.properties"
    if wrapper.exists():
        m = re.search(r"gradle-(\d+)\.(\d+)", _read(wrapper))
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major > 8 or (major == 8 and minor >= 14):
                pos.append(f"Gradle {major}.{minor}")
            else:
                iss.append(f"Gradle {major}.{minor} < 8.14")
    else:
        iss.append("gradle-wrapper.properties NO encontrado")

    return ComplianceResult("arquetipo", len(iss) == 0, pos, iss)


def check_main_gradle(repo_root) -> ComplianceResult:
    """Valida el estándar de main.gradle (lineamiento 05-estandar-main-gradle.md),
    derivado del micro de referencia. main.gradle SÍ es parte del arquetipo SB4.
    Reglas: bloque subprojects, plugins base, Java 21, useJUnitPlatform, -parameters,
    cobertura 0.85 gateando el build, librerías Ficohsa base, BOM Spring Boot, repo
    Azure DevOps parametrizado, sonarqube y wrapper 8.14."""
    mg = repo_root / "main.gradle"
    if not mg.exists():
        return ComplianceResult("main_gradle", False, [],
                                ["main.gradle NO encontrado en la raíz (parte del arquetipo SB4)"])
    c = _read(mg)
    all_gradle = _all_gradle(repo_root)
    pos, iss = [], []

    checks = [
        ("bloque subprojects", bool(re.search(r"\bsubprojects\s*\{", c))),
        ("plugin java", "apply plugin: 'java'" in c or 'apply plugin: "java"' in c),
        ("plugin jacoco", "jacoco" in c),
        ("dependency-management", "io.spring.dependency-management" in c),
        ("Java 21", "JavaVersion.VERSION_21" in c),
        ("useJUnitPlatform()", "useJUnitPlatform" in c),
        ("-parameters", bool(re.search(r"['\"]-parameters['\"]", all_gradle))),
        ("BOM Spring Boot", "spring-boot-dependencies" in c),
        ("repo Azure DevOps parametrizado", "${azuredo_url}" in c or "azuredo_url" in c),
        ("sonarqube", "sonarqube" in c or "org.sonarqube" in c),
    ]
    for label, ok in checks:
        (pos if ok else iss).append(label if ok else f"falta '{label}' en main.gradle")

    # Cobertura 0.85 gateando el build.
    has_cov = bool(re.search(r"(?:minCoverage|minimum)\s*=\s*0?\.85", c))
    if has_cov:
        pos.append("cobertura mínima 0.85")
    else:
        iss.append("falta cobertura mínima 0.85 en jacocoTestCoverageVerification")
    if re.search(r"check\.dependsOn\s+jacocoTestCoverageVerification", c):
        pos.append("cobertura gatea el build (check.dependsOn)")
    else:
        iss.append("la verificación de cobertura no gatea el build (falta check.dependsOn jacocoTestCoverageVerification)")

    # Librerías Ficohsa base vía libs.ficohsa.* (al menos core/logging/exception).
    if re.search(r"libs\.ficohsa\.\w+", c):
        pos.append("librerías Ficohsa base (libs.ficohsa.*)")
    else:
        iss.append("no se declaran librerías Ficohsa base (libs.ficohsa.*) en subprojects")

    # Gradle wrapper 8.14 (en main.gradle o en gradle-wrapper.properties).
    wrapper = repo_root / "gradle" / "wrapper" / "gradle-wrapper.properties"
    wtxt = _read(wrapper) if wrapper.exists() else ""
    if re.search(r"gradleVersion\s*=\s*'?8\.14", c) or re.search(r"gradle-8\.14", wtxt):
        pos.append("Gradle wrapper 8.14")
    else:
        iss.append("Gradle wrapper no es 8.14")

    return ComplianceResult("main_gradle", len(iss) == 0, pos, iss)


def check_librerias_ficohsa(repo_root) -> ComplianceResult:
    all_gradle = _all_gradle(repo_root)
    pos, iss = [], []
    detected = _detect_ficohsa_libs(repo_root, all_gradle)

    if not detected:
        return ComplianceResult("librerias_ficohsa", False, [],
                                ["No se detectaron librerías com.ficohsa.lib:* (ni en libs.versions.toml ni en build.gradle)"])

    # Versión REAL que usa el micro (resuelve catalog-ref desde libs.versions.toml),
    # para poder comparar contra la versión del feed aunque se declare por catálogo.
    resolved = _resolve_micro_lib_versions(repo_root)

    for art, ver in detected.items():
        if not art.startswith("webflux-"):
            iss.append(f"{art} sin prefijo webflux-")
        elif art in DEPRECATED_LOGGING_ARTIFACTS:
            iss.append(f"{art}: artefacto de logging obsoleto")
        else:
            # Última versión publicada: feed de Azure Artifacts en vivo (fallback a catálogo).
            latest, fuente = latest_lib_version(art)
            real = resolved.get(art, ver)   # versión concreta (resuelta del TOML si era catalog-ref)
            if real in (None, "?", "catalog-ref"):
                # no se pudo resolver la versión concreta → no se puede comparar
                pos.append(f"{art} (catálogo, versión no resoluble)")
            elif latest and not _version_gte(real, latest):
                iss.append(f"{art} versión {real} < {latest} (última en {fuente}) — desactualizada")
            else:
                suf = f" (última {fuente}: {latest})" if latest else ""
                pos.append(f"{art} {real}{suf}")

    # resilience4j directo: solo cuenta como DECLARACIÓN de dependencia, no una EXCLUSIÓN.
    # Las líneas 'exclude group: "io.github.resilience4j", module: "resilience4j-spring-boot3"'
    # son correctas (sacan la variante incompatible con SB4) y NO deben marcarse. Se ignora
    # cualquier línea con 'exclude' y solo se evalúan las líneas de declaración real.
    _gradle_decl_lines = "\n".join(
        ln for ln in all_gradle.splitlines()
        if "exclude" not in ln and not ln.lstrip().startswith("//")
    )
    for r4j in FORBIDDEN_DIRECT_RESILIENCE4J:
        if r4j in _gradle_decl_lines:
            iss.append(f"{r4j}: resilience4j directo (llega transitivo vía webflux-resilience)")

    return ComplianceResult("librerias_ficohsa", len(iss) == 0, pos, iss)


def check_jackson3(repo_root) -> ComplianceResult:
    pos, iss = [], []
    forbidden_re = re.compile(r"import\s+com\.fasterxml\.jackson\.(databind|core|datatype)[.;]")
    has_tools = False
    for jf in _iter_java(repo_root):
        content = _read(jf)
        if "tools.jackson." in content:
            has_tools = True
        for i, line in enumerate(content.splitlines(), 1):
            if forbidden_re.search(line):
                iss.append(f"{jf.name}:{i} import de Jackson 2: {line.strip()}")
            if "withCoercionConfigFor" in line:
                iss.append(f"{jf.name}:{i} withCoercionConfigFor (Jackson 2)")
    for gf in _iter_gradle(repo_root):
        gcontent = _read(gf)
        if "jackson-datatype-jsr310" in gcontent:
            iss.append(f"{gf.name}: jackson-datatype-jsr310 (removido en Jackson 3)")
        # Dependencia directa de Jackson 2 databind/core/datatype (annotations SÍ se permite).
        for m in re.finditer(r'com\.fasterxml\.jackson\.(?:core|datatype):(jackson-(?:databind|core|datatype-\w+))',
                             gcontent):
            iss.append(f"{gf.name}: dependencia Jackson 2 '{m.group(1)}' (usar tools.jackson.* de Jackson 3)")
    if not iss:
        pos.append("tools.jackson.* en uso" if has_tools else "sin imports de Jackson 2")
    return ComplianceResult("jackson3", len(iss) == 0, pos, iss)


def _yaml_subblock(yml: str, key: str) -> str:
    """Devuelve el texto del sub-bloque YAML bajo 'key:' (líneas con mayor indentación),
    concatenando todas las apariciones. Recorre por líneas (sin regex de backtracking,
    evita el ReDoS de patrones como (?:\\s+.*\\n)*?)."""
    out = []
    lines = yml.splitlines()
    krx = re.compile(rf"^(\s*){re.escape(key)}:\s*$")
    for i, line in enumerate(lines):
        mkey = krx.match(line)
        if not mkey:
            continue
        base = len(mkey.group(1))
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                out.append(nxt)
                continue
            indent = len(nxt) - len(nxt.lstrip())
            if indent <= base:
                break
            out.append(nxt)
    return "\n".join(out)


def _yaml_aop_enabled(yml: str) -> bool:
    """True si existe un bloque 'aop:' con 'enabled: true' en su interior."""
    return bool(re.search(r"^\s*enabled\s*:\s*true\b", _yaml_subblock(yml, "aop"), re.MULTILINE))


def check_logging(repo_root) -> ComplianceResult:
    pos, iss = [], []
    all_gradle = _all_gradle(repo_root)
    if re.findall(r"webflux-logging-(?:domain|infrastructure|clients|spring-boot-starter)", all_gradle):
        iss.append("artefacto de logging obsoleto")
    elif re.search(r"webflux-logging(?![\w-])", all_gradle):
        pos.append("webflux-logging consolidado")
    else:
        iss.append("webflux-logging NO encontrado en gradle")

    log_files = []
    for pat in ("logback*.xml", "log4j2*.xml", "log4j2*.properties"):
        for f in repo_root.rglob(pat):
            s = str(f)
            if "/build/" not in s and "/.git/" not in s:
                log_files.append(f.name)
    if log_files:
        iss.append(f"config de logging propia: {', '.join(sorted(set(log_files)))}")

    yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
    if "ficohsa" in yml.lower() and "logging" in yml.lower():
        pos.append("ficohsa.logging configurado")
    else:
        iss.append("ficohsa.logging NO configurado")
    if "mask-fields" in yml:
        pos.append("mask-fields configurado")
    else:
        iss.append("mask-fields NO configurado")

    # ── @LogExternalCall: requisitos operativos (runbook webflux-logging) ─────────
    # Si el proyecto usa @LogExternalCall, el aspecto resuelve provider/operation/
    # version por nombre de parámetro desde el bytecode. Eso exige:
    #   1) el flag de compilación -parameters (en main.gradle/build.gradle, dentro de
    #      subprojects para que alcance a módulos como 'ports'), y
    #   2) ficohsa.logging.aop.enabled = true en application.yml.
    uses_log_external = any("@LogExternalCall" in _read(jf) for jf in _iter_java(repo_root))
    if uses_log_external:
        # 1) flag -parameters (se busca en cualquier *.gradle del repo: main.gradle o build.gradle)
        if re.search(r"['\"]-parameters['\"]", all_gradle):
            pos.append("compilación con -parameters")
        else:
            iss.append("falta el flag -parameters en la compilación (requerido por @LogExternalCall)")
        # 2) ficohsa.logging.aop.enabled: true
        #    Se valida acotando al sub-bloque 'aop:' línea por línea (evita regex con
        #    backtracking catastrófico sobre YAML grandes).
        if _yaml_aop_enabled(yml) or re.search(r"aop\.enabled\s*[:=]\s*true", yml):
            pos.append("ficohsa.logging.aop.enabled = true")
        else:
            iss.append("ficohsa.logging.aop.enabled NO está en true (requerido por @LogExternalCall)")

    # ── Estrategias de maskfield válidas (catálogo único MASK_STANDARDS de et_checks) ─
    # Formato de cada maskfield: "campo/estrategia". Se validan los valores que aparezcan
    # como default embebido en mask-fields / mask-fields-by-path del application.yml.
    valid_mask_strategies = MASK_STANDARDS
    detected_strategies = set()
    # Solo se analiza el VALOR de las claves mask-fields / mask-fields-by-path (no las
    # claves-ruta como "[/credit-card-purchase/v1/execution]"). Un maskfield tiene la
    # forma campo/estrategia; el valor puede venir como ${VAR:campo/estrategia,...}.
    for vm in re.finditer(r'mask-fields(?:-by-path)?\b[^\n]*?:\s*(.+)$', yml, re.MULTILINE):
        raw = vm.group(1).strip().strip('"\'')
        # Extraer el default embebido de ${ENV:default} si existe; si no, el valor tal cual.
        dm = re.search(r'\$\{[^:}]*:([^}]*)\}', raw)
        payload = dm.group(1) if dm else raw
        # Cada campo separado por coma; solo cuentan los que tienen forma campo/estrategia.
        for tok in re.split(r'[,\s]+', payload):
            m2 = re.fullmatch(r'[A-Za-z][\w-]*\/([A-Za-z][\w-]*)', tok)
            if m2:
                detected_strategies.add(m2.group(1))
    invalid = sorted(s for s in detected_strategies if s not in valid_mask_strategies)
    if detected_strategies:
        if invalid:
            iss.append(f"estrategia(s) de maskfield inválida(s): {', '.join(invalid)} (válidas: {', '.join(sorted(valid_mask_strategies))})")
        else:
            pos.append(f"estrategias de maskfield válidas ({', '.join(sorted(detected_strategies))})")

    # ── masking.table-name requerido si el masking por DynamoDB está habilitado ───
    # (runbook secciones 3 y 7). Solo se exige cuando el masking DynamoDB está activo.
    # Se lee el sub-bloque 'masking:' línea por línea (sin regex de backtracking).
    masking_blk = _yaml_subblock(yml, "masking")
    tn = re.search(r"^\s*table-name\s*:\s*(\S.*)$", masking_blk, re.MULTILINE)
    has_table_name = bool(tn and tn.group(1).strip() not in ("", '""', "''")
                          and not re.fullmatch(r"\$\{[^:}]*:\s*\}", tn.group(1).strip()))
    masking_block_enabled = bool(re.search(r"^\s*enabled\s*:\s*true\b", masking_blk, re.MULTILINE))
    if has_table_name:
        pos.append("ficohsa.logging.masking.table-name configurado")
    elif masking_block_enabled:
        iss.append("masking por DynamoDB habilitado pero falta ficohsa.logging.masking.table-name")

    return ComplianceResult("logging", len(iss) == 0, pos, iss)


def _parse_annotation_attrs(annot_args: str) -> dict:
    """Extrae los atributos de @FicohsaResilience(...) → {attr: valor_literal_str}.
    Soporta valores string ("x"), booleanos (true/false) y placeholders (${...})."""
    attrs = {}
    for m in re.finditer(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|true|false|[\w.${}]+)', annot_args):
        attrs[m.group(1)] = m.group(2).strip().strip('"')
    return attrs


def check_resilience(repo_root) -> ComplianceResult:
    """Valida el uso de @FicohsaResilience según la ET de webflux-resilience v2.0.0:
      - Modo (dinámico recomendado vs estático/deprecado label/paramName/paramLabel).
      - instanceName no debe seguir el patrón cb-<sistema>-<capacidad>.
      - perRegion=true NO exige firma con sourceBank/AppContext (lo resuelve la librería).
      - resilienceConfigParam="X" exige que exista el parámetro X en el método.
      - El método anotado debe ser público (limitación de Spring AOP proxy).
      - No debe existir configuración resilience4j.* en application.yml (viene de AWS).
    """
    pos, iss = [], []
    uses = False
    # Regex que captura: @FicohsaResilience( args )  seguido de la firma del método.
    annot_re = re.compile(
        r'@FicohsaResilience\s*\(([^)]*)\)\s*'      # 1: args de la anotación
        r'(?:@\w+(?:\([^)]*\))?\s*)*'               # posibles anotaciones intermedias (@Override, etc.)
        r'((?:public|protected|private|\s|static|final|abstract)*)'  # 2: modificadores
        r'\s*(?:<[^>]+>\s*)?'                        # genéricos opcionales
        # El tipo de retorno puede llevar anotaciones de tipo embebidas en los genéricos
        # (p. ej. Mono<@NonNull List<T>>); por eso se incluye '@' en la clase de caracteres.
        r'[\w.<>,\[\]@\s]+?\s+(\w+)\s*\(([^)]*)\)',  # 3: nombre método, 4: parámetros
        re.DOTALL,
    )
    for jf in _iter_java(repo_root):
        # Se evalúa el código SIN comentarios: una mención de @FicohsaResilience dentro de
        # Javadoc (p. ej. {@code @FicohsaResilience}) no es un uso real de la anotación.
        content = _strip_java_comments(_read(jf))
        if "@FicohsaResilience" not in content:
            continue
        uses = True
        matched_any = False
        for m in annot_re.finditer(content):
            matched_any = True
            args, mods, method, params = m.group(1), m.group(2), m.group(3), m.group(4)
            attrs = _parse_annotation_attrs(args)
            where = f"{jf.name}:{method}"

            # 1) Modo deprecado (estático): label / paramName / paramLabel
            for attr in ("label", "paramName", "paramLabel"):
                if attr in attrs:
                    iss.append(f"{where}: modo deprecado ({attr}) — usar modo dinámico")

            # 2) instanceName con patrón cb-<sistema>-<capacidad>
            inst = attrs.get("instanceName", "")
            if inst.startswith("cb-"):
                iss.append(f"{where}: instanceName '{inst}' usa cb-<sistema>-<capacidad> "
                           f"(debe ser el nombre del método/operación)")

            # 3) perRegion=true: NO se valida la firma del método.
            # La resolución del sourceBank por región es responsabilidad de la librería
            # (ResilienceAspect), no del micro. El decorador solo declara la intención de
            # circuit breaker por región; cómo se obtiene el sourceBank lo maneja la lib.
            # Por eso aquí solo verificamos que el decorador esté bien implementado
            # (modo, instanceName, resilienceConfigParam, visibilidad), no la firma.

            # 4) resilienceConfigParam="X" exige el parámetro X en la firma
            rcp = attrs.get("resilienceConfigParam", "")
            if rcp:
                if not re.search(rf'\b{re.escape(rcp)}\b', params):
                    iss.append(f"{where}: resilienceConfigParam=\"{rcp}\" pero no existe ese parámetro en el método")

            # 5) el método anotado debe ser público (AOP proxy)
            if "public" not in mods:
                iss.append(f"{where}: el método con @FicohsaResilience debe ser público (limitación de Spring AOP)")

            # 6) debe declarar modo dinámico o estático (no anotación vacía)
            has_dynamic = bool(inst or rcp or attrs.get("perRegion") == "true")
            has_static = any(a in attrs for a in ("label", "paramName", "paramLabel"))
            if not has_dynamic and not has_static:
                iss.append(f"{where}: @FicohsaResilience sin instanceName/resilienceConfigParam ni modo estático")

        if not matched_any:
            # La anotación aparece pero el parser no pudo asociarla a un método (formato atípico).
            iss.append(f"{jf.name}: @FicohsaResilience presente pero no se pudo analizar la firma del método")

    # 7) No debe haber configuración resilience4j.* en application.yml (viene de AWS PS).
    if uses:
        yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
        if re.search(r'^\s*resilience4j\s*:', yml, re.MULTILINE):
            iss.append("application.yml define resilience4j.* (la config debe venir de AWS Parameter Store)")

    if not uses:
        return ComplianceResult("resilience", None, [], [])  # N/A
    if not iss:
        pos.append("@FicohsaResilience bien implementado (modo dinámico, instanceName, resilienceConfigParam y visibilidad correctos)")
    return ComplianceResult("resilience", len(iss) == 0, pos, iss)


def check_mappers(repo_root) -> ComplianceResult:
    pos, iss = [], []
    mappers = []
    for jf in _iter_java(repo_root):
        content = _read(jf)
        if "@Mapper" not in content:
            continue
        # Solo interfaces/clases @Mapper de MapStruct (no @Mapper de otros paquetes).
        if not re.search(r'@Mapper\b', content):
            continue
        mappers.append(jf.name)
        # componentModel = "spring" es obligatorio para que el mapper sea bean Spring.
        m = re.search(r'@Mapper\s*\(([^)]*)\)', content)
        args = m.group(1) if m else ""
        if 'componentModel' not in args or not re.search(r'componentModel\s*=\s*"spring"', args):
            iss.append(f"{jf.name}: @Mapper sin componentModel = \"spring\" (no se registra como bean)")
    if "mapstruct" not in _all_gradle(repo_root):
        iss.append("mapstruct NO está en el catálogo")
    else:
        pos.append("mapstruct en catálogo")
    if mappers:
        pos.append(f"{len(mappers)} mapper(s) MapStruct")
    else:
        iss.append("sin mappers MapStruct")
    return ComplianceResult("mappers", len(iss) == 0, pos, iss)


def check_envelope(repo_root) -> ComplianceResult:
    """Valida el envelope de request según webflux-router (RestComponent):
      - Endpoints con body deben usar RestComponent.post/put con
        ParameterizedTypeReference<RequestModel<D>> (no la sobrecarga con Class<D>).
      - Prohibido getRequestType() (patrón antiguo).
      - Si hay RouterFunction pero no se usa RestComponent, es router manual (desviación).
    Verificado contra la API real de com.ficohsa.lib.router.component.RestComponent."""
    pos, iss = [], []
    uses_envelope = False
    router_files = []
    uses_rest_component = False
    for jf in _iter_java(repo_root):
        content = _read(jf)
        if "RequestModel" in content or "ParameterizedTypeReference" in content:
            uses_envelope = True
        if "getRequestType()" in content:
            iss.append(f"{jf.name}: getRequestType() (patrón antiguo; usar RequestModel<D>)")
        if "RestComponent" in content:
            uses_rest_component = True
        # Detectar routers de NEGOCIO (entry-points) que definan RouterFunction.
        # Se excluyen los routers de documentación OpenAPI/springdoc (@RouterOperations),
        # que usan RouterFunctions.route solo para exponer el schema, no para servir tráfico.
        is_openapi_doc = ("springdoc" in content or "@RouterOperations" in content
                          or "openapi" in str(jf).lower() or jf.name.lower().startswith("openapi"))
        if "RouterFunction" in content and "/test/" not in str(jf) and not is_openapi_doc:
            router_files.append((jf, content))

    for jf, content in router_files:
        # RestComponent.post/put con Class<D> en vez de RequestModel<D> = envelope incompleto.
        # (get/delete sin body usan Function<ServerRequest,...> y no aplican.)
        for mm in re.finditer(r'\.(post|put)\s*\(\s*[^,]+,\s*([A-Za-z0-9_<>.]+)\s*(?:\.class)?', content):
            verb, arg2 = mm.group(1), mm.group(2)
            if arg2.endswith(".class") or (arg2[:1].isupper() and "ParameterizedTypeReference" not in content[mm.start():mm.end()+80] and "RequestModel" not in content[mm.start():mm.end()+80]):
                # Heurística: si en esa llamada no aparece RequestModel/ParameterizedTypeReference cerca.
                seg = content[mm.start():mm.end()+120]
                if "RequestModel" not in seg and "ParameterizedTypeReference" not in seg:
                    iss.append(f"{jf.name}: RestComponent.{verb}(...) usa Class<D> sin RequestModel<D> "
                               f"(el body debe deserializarse como RequestModel<D>)")
        # Router manual sin RestComponent (no usa el arquetipo de router).
        if "RestComponent" not in content and "RouterFunctions.route" in content:
            iss.append(f"{jf.name}: RouterFunction manual sin RestComponent (usar webflux-router)")

    if iss:
        return ComplianceResult("envelope", False, pos, iss)
    if uses_envelope:
        pos.append("RequestModel<D> en uso")
        if uses_rest_component:
            pos.append("RestComponent (webflux-router) en uso")
        return ComplianceResult("envelope", True, pos, [])
    return ComplianceResult("envelope", None, [], [])  # N/A


def check_caller_service(repo_root) -> ComplianceResult:
    """Valida la observabilidad de llamadas salientes y la propagación de Caller-Service:
      - Caller-Service NO debe setearse manualmente (webflux-web-client lo propaga solo).
      - Los adapters HTTP salientes (usan WebClientComponent) deben llevar @LogExternalCall.
        Esta exigencia aplica SOLO a micros tipo Wrapper (en composición/producto/sistema
        cada librería loguea internamente y @LogExternalCall no se exige por adapter).
      - @LogExternalCall debe tener el provider resoluble: atributo provider="..." en la
        anotación, o un parámetro 'provider' en el método (runbook webflux-logging §4).
    Verificado contra webflux-web-client (WebClientAdapter propaga Caller-Service vía la
    constante AppContext.CALLER_SERVICE) y el aspecto ExternalCallLoggingAspect."""
    pos, iss = [], []
    adapters_ok = 0
    # @LogExternalCall solo se exige en micros tipo Wrapper.
    is_wrapper = detect_clasificacion(os.path.basename(str(repo_root))) == "Wrapper"
    # Regex: @LogExternalCall(args?) seguido de la firma del método siguiente.
    lec_re = re.compile(
        r'@LogExternalCall\s*(?:\(([^)]*)\))?\s*'
        r'(?:@\w+(?:\([^)]*\))?\s*)*'
        r'(?:public|protected|private|\s|static|final)*\s*(?:<[^>]+>\s*)?'
        r'[\w.<>,\[\]\s]+?\s+(\w+)\s*\(([^)]*)\)',
        re.DOTALL,
    )
    for jf in _iter_java(repo_root):
        content = _read(jf)
        # 1) Caller-Service RE-PROPAGADO desde el AppContext entrante (prohibido, Req 57).
        #    webflux-web-client ya propaga automáticamente el Caller-Service del contexto;
        #    re-ponerlo a mano desde context.callerService()/AppContext.CALLER_SERVICE es la
        #    violación. En cambio, FIJAR la identidad propia del micro con una constante/literal
        #    (p. ej. Map.of("Caller-Service", CALLER_SERVICE) donde CALLER_SERVICE="<dominio>-comp-<metodo>")
        #    es CORRECTO: es cómo el micro se identifica ante los downstream (lineamiento 06).
        if "Caller-Service" in content or "AppContext.CALLER_SERVICE" in content:
            # Señales de que el valor proviene del contexto entrante (lo que Req 57 prohíbe).
            _ctx_caller_re = re.compile(
                r'(?:\w+\.)?callerService\s*\(\)|getCallerService\s*\(\)|AppContext\.CALLER_SERVICE',
                re.IGNORECASE)
            for i, line in enumerate(content.splitlines(), 1):
                mentions_header = ("Caller-Service" in line or "AppContext.CALLER_SERVICE" in line)
                sets_header = mentions_header and (".set(" in line or ".put(" in line
                                                   or "Map.of(" in line or ".header(" in line)
                if sets_header and _ctx_caller_re.search(line):
                    iss.append(f"{jf.name}:{i} Caller-Service re-propagado del contexto (lo propaga la librería, Req 57)")

        # 2) Adapters HTTP salientes deben llevar @LogExternalCall (SOLO wrappers).
        is_http_adapter = jf.name.endswith("Adapter.java") and "WebClientComponent" in content
        if is_wrapper and is_http_adapter and "@LogExternalCall" not in content:
            iss.append(f"{jf.name}: adapter HTTP saliente sin @LogExternalCall")

        # 3) provider resoluble en cada @LogExternalCall (SOLO wrappers: es donde la
        #    anotación se exige; en otros tipos no se penaliza su presencia/ausencia).
        if is_wrapper:
            for m in lec_re.finditer(content):
                args, method, params = (m.group(1) or ""), m.group(2), m.group(3)
                has_provider_attr = bool(re.search(r'\bprovider\s*=', args))
                has_provider_param = bool(re.search(r'\bprovider\b', params))
                if not has_provider_attr and not has_provider_param:
                    iss.append(f"{jf.name}:{method}: @LogExternalCall sin provider (ni atributo ni parámetro) "
                               f"— quedará vacío en el log (cache MISS)")
                else:
                    adapters_ok += 1

    # 4) FORMATO del valor caller-service (lineamiento 06-caller-service.md):
    #    <service_domain>-<tipo-api>-<metodo>, minúsculas, sin versión vN.
    for cs_value, origin in _collect_caller_service_values(repo_root):
        ok, reason = _validate_caller_service_format(cs_value, repo_root)
        if ok:
            pos.append(f"caller-service '{cs_value}' cumple el formato ({origin})")
        else:
            iss.append(f"caller-service '{cs_value}' ({origin}): {reason}")

    if not iss:
        if adapters_ok:
            pos.append(f"Caller-Service automático; {adapters_ok} método(s) con @LogExternalCall(provider) resoluble")
        else:
            pos.append("Caller-Service automático; sin llamadas externas anotadas")
    return ComplianceResult("caller_service", len(iss) == 0, pos, iss)


# Tipología de API válida (lineamiento 06) y mapeo desde detect_clasificacion().
CALLER_SERVICE_TYPES = {"sys", "product", "comp", "exp", "util"}
_CLASIF_TO_TIPO = {
    "Sistema": "sys", "Producto": "product", "Composición": "comp",
    "Experiencia": "exp", "Utilidad": "util",
}


def _collect_caller_service_values(repo_root):
    """Recolecta los valores de caller-service declarados en el micro:
      - Constante Java `CALLER_SERVICE = "..."`.
      - Bloque ficohsa.logging.caller-services del application.yml (valores tras ':').
    Retorna lista de (valor, origen)."""
    found = []
    for jf in _iter_java(repo_root):
        content = _read(jf)
        for m in re.finditer(r'\bCALLER_SERVICE\w*\s*=\s*"([^"]+)"', content):
            found.append((m.group(1), f"{jf.name} (constante)"))
    yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
    # Bloque caller-services: solo las líneas del sub-bloque (indentación mayor a la de
    # la clave); las entradas son  "[/path]": valor. Se corta al bajar la indentación
    # para no capturar bloques hermanos (p. ej. 'rest:' con auto-self: false).
    lines = yml.splitlines()
    for i, line in enumerate(lines):
        mkey = re.match(r"^(\s*)caller-services:\s*$", line)
        if not mkey:
            continue
        base_indent = len(mkey.group(1))
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            indent = len(nxt) - len(nxt.lstrip())
            if indent <= base_indent:
                break
            # entrada de mapeo: "[/path]": valor  (el valor es el último token tras ':')
            mv = re.search(r'\]?"?\s*:\s*([A-Za-z0-9_\-]+)\s*$', nxt)
            if mv:
                found.append((mv.group(1).strip(), "application.yml (caller-services)"))
    return found


def _validate_caller_service_format(value, repo_root):
    """Valida el formato <service_domain>-<tipo-api>-<metodo> del lineamiento 06.
    Retorna (ok, motivo)."""
    if value != value.lower():
        return False, "debe estar en minúsculas"
    if " " in value:
        return False, "no debe contener espacios"
    if re.search(r"[^a-z0-9_\-]", value):
        return False, "solo se permiten letras minúsculas, dígitos, '_' y '-'"
    if re.search(r"\bv\d+\b", value):
        return False, "no debe incluir la versión del API (vN)"
    parts = value.split("-")
    if len(parts) != 3:
        return False, (f"debe tener 3 componentes separados por '-' "
                       f"(<service_domain>-<tipo-api>-<metodo>), tiene {len(parts)}")
    service_domain, tipo, metodo = parts
    if not service_domain:
        return False, "el service-domain está vacío"
    if tipo not in CALLER_SERVICE_TYPES:
        return False, (f"tipo-api '{tipo}' inválido "
                       f"(usar: {', '.join(sorted(CALLER_SERVICE_TYPES))})")
    if not metodo:
        return False, "el método está vacío"
    # Coherencia con la tipología real del micro (si es deducible).
    expected_tipo = _CLASIF_TO_TIPO.get(detect_clasificacion(os.path.basename(str(repo_root))))
    if expected_tipo and tipo != expected_tipo:
        return False, (f"tipo-api '{tipo}' no coincide con la clasificación del micro "
                       f"(esperado '{expected_tipo}')")
    return True, ""


def check_regionalizacion(repo_root) -> ComplianceResult:
    if "webflux-regionalization" not in _all_gradle(repo_root):
        return ComplianceResult("regionalizacion", None, [], [])  # N/A
    pos, iss = [], []
    for jf in _iter_java(repo_root):
        if jf.name.endswith("RegionalizationProperties.java") and "@ConfigurationProperties" in _read(jf):
            # El estado correcto (trimmed) conserva @ConfigurationProperties con solo
            # functionName (+ cache-local). Solo se marca como retirado si aún expone
            # claves "por operación": domain / default-version / retrieve.
            content = _read(jf)
            stale_keys = ("domain", "default-version", "defaultVersion", "retrieve")
            if any(re.search(rf"\b{re.escape(k)}\b", content) for k in stale_keys):
                iss.append(f"{jf.name}: @ConfigurationProperties por operación (retirado)")
            else:
                pos.append(f"{jf.name}: RegionalizationProperties trimmed (solo functionName)")
        if jf.name.endswith("RegionalizationSettings.java") and "interface" in _read(jf):
            iss.append(f"{jf.name}: interfaz de settings por operación (retirada)")

    for src, label in ((_find_app_yml(repo_root), "application.yml"), (_find_cm_yaml(repo_root), "cm.yaml")):
        txt = _read(src) if src else ""
        # Variables de identidad de negocio por operación (REGIONALIZATION_<OP>_COUNTRY/DOMAIN/METHOD/NAME).
        # Excluir la variable de la Lambda de regionalización (REGIONALIZATION_LAMBDA_NAME /
        # REGIONALIZATION_FUNCTION_NAME), que es infraestructura legítima y NO identidad por operación.
        for m in re.finditer(r"\bREGIONALIZATION_\w+_(?:COUNTRY|DOMAIN|METHOD|NAME)\b", txt):
            tok = m.group(0)
            if tok in ("REGIONALIZATION_LAMBDA_NAME", "REGIONALIZATION_FUNCTION_NAME"):
                continue
            iss.append(f"{label}: variables REGIONALIZATION_<OP>_* deben removerse")
            break

    yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
    # Acotar al bloque ficohsa.regionalization (indentado 2 espacios bajo 'ficohsa:').
    reg = re.search(r"^\s{2}regionalization:\s*\n((?:\s{3,}.*\n)+)", yml, re.MULTILINE)
    if reg:
        block = reg.group(1)
        # Claves retiradas ("por operación"): no deben aparecer.
        for stale in ("default-version", "defaultVersion", "retrieve", "domain"):
            if re.search(rf"^\s+{re.escape(stale)}\s*:", block, re.MULTILINE):
                iss.append(f"ficohsa.regionalization debe removerse '{stale}' (trimmed)")
        # function-name debe estar declarado (ARN de la Lambda; obligatorio). Spring Boot
        # relaxed binding acepta 'function-name' (kebab) y 'functionName' (camelCase).
        if re.search(r"^\s+(?:function-name|functionName)\s*:", block, re.MULTILINE):
            pos.append("ficohsa.regionalization.function-name declarado")
        else:
            iss.append("falta ficohsa.regionalization.function-name (ARN de la Lambda)")
        # cache-local.ttl-seconds, si está, debe ser numérico o ${VAR:numero}.
        mttl = re.search(r"ttl-seconds\s*:\s*(\S+)", block)
        if mttl:
            v = mttl.group(1)
            mdef = re.search(r"\$\{[^:}]*:(\d+)\}", v)
            if not (v.isdigit() or mdef):
                iss.append(f"ficohsa.regionalization.cache-local.ttl-seconds = '{v}' no es numérico")

    if not iss:
        pos.append("Regionalización con constantes in-code")
    return ComplianceResult("regionalizacion", len(iss) == 0, pos, iss)


def check_homologacion(repo_root) -> ComplianceResult:
    """Valida la config de homologación (webflux-homologator) si el micro la USA.
    Contrato real (verificado en código lib): prefijo ficohsa.homologator, único campo
    functionName (ARN de la Lambda). Aplica solo si el micro consume el componente o
    declara implementation de la librería; si solo hay config sin uso, retorna N/A."""
    all_gradle = _all_gradle(repo_root)
    uses_component = any(
        ("HomologatorComponent" in _read(jf) or "resolveHomologation" in _read(jf)
         or "getHomologatorData" in _read(jf))
        for jf in _iter_java(repo_root)
    )
    # 'implementation' real (no solo la entrada del catálogo libs.versions.toml).
    declares_impl = bool(re.search(r"(?:implementation|api)\b[^\n]*(?:homologator|ficohsa\.homologator)",
                                   all_gradle, re.IGNORECASE))
    if not uses_component and not declares_impl:
        return ComplianceResult("homologacion", None, [], [])  # N/A: no usa homologación

    pos, iss = [], []
    yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
    hom = re.search(r"^\s{2}homologator:\s*\n((?:\s{3,}.*\n)+)", yml, re.MULTILINE)
    if hom:
        if re.search(r"^\s+function-name\s*:", hom.group(1), re.MULTILINE):
            pos.append("ficohsa.homologator.function-name declarado")
        else:
            iss.append("falta ficohsa.homologator.function-name (ARN de la Lambda)")
    else:
        iss.append("el micro usa homologación pero falta el bloque ficohsa.homologator")
    if uses_component:
        pos.append("HomologatorComponent en uso")
    return ComplianceResult("homologacion", len(iss) == 0, pos, iss)


# Catálogo de tallas EKS (lineamiento 03-tallaje-microservicios-eks.md).
# {talla: (cpu_req, cpu_lim, mem_req, mem_lim)}
SIZING_CATALOG = {
    "XS": ("25m",  "150m",  "192Mi",  "256Mi"),
    "S":  ("50m",  "500m",  "512Mi",  "640Mi"),
    "M":  ("100m", "700m",  "768Mi",  "1024Mi"),
    "L":  ("150m", "1000m", "1024Mi", "1280Mi"),
    "XL": ("250m", "1500m", "1536Mi", "2048Mi"),
}
VALID_SIZING = set(SIZING_CATALOG)

# Valor EXACTO requerido para la variable 'java-options' del Variable Group (ni más, ni menos).
# La comparación normaliza solo espacios en blanco (trim + colapso de espacios internos);
# el contenido, el orden de las propiedades y las mayúsculas/minúsculas deben coincidir.
JAVA_OPTIONS_EXPECTED = (
    "-Djavax.net.ssl.trustStore=/etc/ssl/certs/ca-bundle/bundle.p12 "
    "-Djavax.net.ssl.trustStoreType=PKCS12 -Dfile.encoding=UTF-8"
)

# Nombres de variable en el Variable Group que contienen los resources aplicados.
_VG_RES_KEYS = {
    "cpu_req": "resources-request-cpu",
    "cpu_lim": "resources-limits-cpu",
    "mem_req": "resources-request-memory",
    "mem_lim": "resources-limits-memory",
}


def _norm_qty(q: str) -> str:
    return str(q).strip().replace(" ", "")


def check_sizing(variable_group: dict) -> ComplianceResult:
    """Valida el tallaje EKS del micro (lineamiento 03):
      1) Existe la variable ms-sizing con talla válida (XS/S/M/L/XL).
      2) Si el Variable Group trae los resources aplicados (resources-request/limits-*),
         que coincidan con el catálogo de la talla declarada.
    Sin Variable Group (p. ej. --single sin mapping), retorna NO ENCONTRADO."""
    if not variable_group:
        return ComplianceResult("sizing", "not_found", [],
                                ["Variable Group no disponible en vivo (exporta AZURE_DEVOPS_PAT para consultar Azure Library)"])
    # Búsqueda tolerante a variantes de nombre (ms-sizing / ms_sizing / MS_SIZING).
    key = next((k for k in variable_group
                if re.fullmatch(r"ms[-_ ]?sizing", k.strip(), re.IGNORECASE)), None)
    if not key:
        return ComplianceResult("sizing", False, [],
                                ["falta la variable ms-sizing en el Variable Group"])
    raw = str(variable_group.get(key, "")).strip()
    if raw == "***SECRET***":
        return ComplianceResult("sizing", "partial", [],
                                ["ms-sizing está marcada como secreta; no se puede validar la talla"])
    val = raw.upper()
    if val not in VALID_SIZING:
        return ComplianceResult("sizing", False, [],
                                [f"ms-sizing = '{raw}' no es una talla válida (XS/S/M/L/XL)"])

    pos = [f"ms-sizing = {val}"]
    iss = []
    # Coteja los resources del VG contra el catálogo de la talla, si están presentes.
    expected = dict(zip(("cpu_req", "cpu_lim", "mem_req", "mem_lim"), SIZING_CATALOG[val]))
    present = {k: variable_group.get(vk) for k, vk in _VG_RES_KEYS.items() if vk in variable_group}
    if present:
        for k, actual in present.items():
            exp = expected[k]
            if _norm_qty(actual) != _norm_qty(exp):
                iss.append(f"{_VG_RES_KEYS[k]} = {actual} no coincide con talla {val} (esperado {exp})")
        if not iss:
            pos.append(f"resources coinciden con la talla {val}")
    return ComplianceResult("sizing", len(iss) == 0, pos, iss)


# Variables genéricas de DESPLIEGUE/PIPELINE (ECS/EKS): no van en el cm.yaml del micro.
_VG_DEPLOY_VARS = {
    "ecr-repo-name", "irsa-role-name", "ms-ingress-group-name", "ms-ingress-path", "ms-port",
}
# Variables de resources por talla DEPRECADAS: el sizing EKS ahora se declara con la variable
# `ms-sizing` (XS/S/M/L/XL), que resuelve requests/limits desde el catálogo. Si aún aparecen
# en el Variable Group deben REMOVERSE. Cubre singular/plural (limit/limits, request/requests).
_VG_DEPRECATED_RESOURCE_RE = re.compile(
    r"^resources?[-_]?(request|requests|limit|limits)[-_]?(cpu|memory|mem)$", re.IGNORECASE)
# Placeholders de PLATAFORMA del cm.yaml: los inyecta el entorno/EKS/pipeline, no el VG del micro.
#   - ENV_TAG: lo asigna directamente el pipeline en ejecución (tag de la imagen/versión);
#     NO vive en el Variable Group ni en los transversales, así que no se compara contra ellos.
_VG_PLATFORM_PH = re.compile(r'^(env|env[-_]?tag|region|ms-name|eks-namespace|spring-application-json'
                             r'|.*-alb-.*|otel[-_].*)$', re.IGNORECASE)
_VG_ENV_RE = re.compile(r"-(dev|stg|stage|stagging|staging|uat|prd|prod)(?=[^A-Za-z0-9]|$)", re.IGNORECASE)
_VG_ENV_ALIAS = {"dev": "dev", "stg": "stg", "stage": "stg", "staging": "stg",
                 "stagging": "stg", "uat": "uat", "prd": "prd", "prod": "prd"}


def evaluate_vg_variable(key, val, cm_placeholders, vg_env="stg"):
    """Evalúa UNA variable del Variable Group contra los lineamientos.
    Devuelve (veredicto, motivo) donde veredicto ∈ {'ok','fail','na'}."""
    kl = str(key).strip().lower()
    sval = str(val)
    # 1) Ambiente: el VG es '<micro>-stg'; un valor con sufijo -dev/-uat/-prd está desalineado.
    if val != "***SECRET***":
        envs = {_VG_ENV_ALIAS.get(m.lower(), m.lower()) for m in _VG_ENV_RE.findall(sval)}
        mism = envs - {vg_env}
        if envs and mism:
            return "fail", f"ambiente {'/'.join(sorted(mism))} en VG {vg_env}"
    # 2) ms-sizing (lineamiento 03).
    if re.fullmatch(r"ms[-_ ]?sizing", kl):
        if val == "***SECRET***":
            return "fail", "ms-sizing marcada como secreta"
        return ("ok", f"talla {sval.upper()}") if sval.strip().upper() in VALID_SIZING else ("fail", "talla inválida")
    # 3) java-options: debe ser EXACTAMENTE el valor estándar (ni más, ni menos).
    #    Único valor aceptado (orden y contenido exactos; solo se tolera espacio en blanco
    #    externo y espacios múltiples entre tokens):
    #      -Djavax.net.ssl.trustStore=/etc/ssl/certs/ca-bundle/bundle.p12
    #      -Djavax.net.ssl.trustStoreType=PKCS12 -Dfile.encoding=UTF-8
    if re.fullmatch(r"java[-_ ]?options|java[-_ ]?tool[-_ ]?options", kl):
        if val == "***SECRET***":
            return "fail", "java-options marcada como secreta"
        normalized = re.sub(r"\s+", " ", sval).strip()
        if normalized == JAVA_OPTIONS_EXPECTED:
            return "ok", "java-options exacto"
        return "fail", f"java-options debe ser EXACTAMENTE '{JAVA_OPTIONS_EXPECTED}'"
    # 4) Resources por talla DEPRECADOS: reemplazados por ms-sizing. Deben removerse del VG.
    if _VG_DEPRECATED_RESOURCE_RE.match(kl):
        return "fail", "variable de resources deprecada (usar ms-sizing); remover del VG"
    # 5) Variables de despliegue/pipeline: no aplican al cm.yaml.
    if kl in _VG_DEPLOY_VARS:
        return "na", "variable de despliegue/pipeline"
    # 5) Correspondencia general cm.yaml ↔ VG.
    if cm_placeholders is None:
        return "na", "cm.yaml no disponible"
    if key in cm_placeholders:
        return "ok", "referenciada en cm.yaml"
    return "fail", "no referenciada en cm.yaml"


def check_variable_group_cm_match(variable_group: dict, cm_text: str,
                                  transversal_vars: dict = None, env: str = "stg") -> ComplianceResult:
    """Valida la alineación Azure Variable Group ↔ k8s/cm.yaml (gobierno de parámetros,
    runbook 02). Cada NO CUMPLE aquí SUMA al conteo global de criterios del micro.
    - Todo placeholder ${...} (no-plataforma) del cm.yaml debe existir en el VG propio O en
      un VG transversal (lib-urls-internal / libs-paths-internal). Si no está en ninguno → NO CUMPLE.
    - Toda variable del VG propio (salvo despliegue/plataforma) debería estar referenciada por el cm.yaml.
    - Reglas específicas: ambiente (sufijo del ambiente de validación), ms-sizing, java-options (TLS).
    - URLs internas resueltas desde un transversal deben ser https (http → NO CUMPLE)."""
    if not variable_group:
        return ComplianceResult("vg_cm_alineacion", "not_found", [],
                                ["Variable Group no disponible (exporta AZURE_DEVOPS_PAT para consultar Azure Library)"])
    transversal_vars = transversal_vars or {}
    cm_ph = set(re.findall(r'\$\{([^}]+)\}', cm_text or ""))
    pos, iss = [], []
    # a0) APP_VERSION debe asignarse SIEMPRE al placeholder del pipeline ${ENV_TAG}.
    #     El tag/versión de la imagen lo inyecta el pipeline en ejecución vía ENV_TAG;
    #     NO se compara contra el Variable Group. Cualquier otra asignación (p. ej.
    #     ${app-version}, ${image-tag}, ${env-tag} en minúsculas o un literal) es NO CUMPLE.
    _appver_bad_ph = None  # placeholder mal asignado a APP_VERSION (se omite en el bloque (a) para no duplicar hallazgo)
    _m_appver = re.search(r'^\s*APP_VERSION\s*:\s*(.+?)\s*$', cm_text or "", re.MULTILINE)
    if _m_appver:
        _appver_val = _m_appver.group(1).strip().strip('"').strip("'")
        if _appver_val == "${ENV_TAG}":
            pos.append("APP_VERSION: asignada a ${ENV_TAG} (inyectada por el pipeline)")
        else:
            iss.append(f"APP_VERSION debe asignarse a ${{ENV_TAG}} (inyectada por el pipeline), "
                       f"pero el cm.yaml usa '{_appver_val}'")
            _m_ph = re.fullmatch(r'\$\{([^}]+)\}', _appver_val)
            if _m_ph:
                _appver_bad_ph = _m_ph.group(1)
    # a) placeholders del cm.yaml (no-plataforma) que no estén ni en el VG propio ni en transversales
    for p in sorted(cm_ph):
        if _VG_PLATFORM_PH.match(p):
            continue
        if p == _appver_bad_ph:
            # Ya reportado como asignación incorrecta de APP_VERSION; no duplicar el hallazgo genérico.
            continue
        if p in variable_group:
            continue
        if p in transversal_vars:
            # Resuelto por un VG transversal. Si es una URL, debe ser https (regla lib-urls-internal).
            val = str(transversal_vars[p])
            if val.startswith("http://"):
                iss.append(f"${{{p}}} (transversal) usa http:// — las URLs internas deben ser https://")
            else:
                pos.append(f"${{{p}}}: resuelta por VG transversal")
            continue
        iss.append(f"cm.yaml referencia ${{{p}}} pero NO existe en el VG propio ni en los transversales")
    # b) evaluación por variable del VG propio
    for k in sorted(variable_group.keys()):
        verdict, reason = evaluate_vg_variable(k, variable_group.get(k), cm_ph, vg_env=env)
        if verdict == "fail":
            iss.append(f"{k}: {reason}")
        elif verdict == "ok":
            pos.append(f"{k}: {reason}")
    return ComplianceResult("vg_cm_alineacion", len(iss) == 0, pos, iss)


def check_dtos(repo_root) -> ComplianceResult:
    pos, iss = [], []
    dto_count = 0
    for jf in _iter_java(repo_root):
        if not jf.name.endswith("Dto.java"):
            continue
        content = _read(jf)
        dto_count += 1
        is_record = bool(re.search(r"\brecord\s+\w+\s*\(", content))
        if not is_record:
            iss.append(f"{jf.name}: no es un record")
            continue
        # Un DTO record no debe usar Lombok de MUTABILIDAD (@Data/@Setter): son
        # incompatibles con la inmutabilidad del record y señalan modelado incorrecto.
        # @Builder NO rompe la inmutabilidad (el record sigue sin setters y con campos
        # final); solo genera un builder, así que se permite (p. ej. records de muchos
        # campos donde el constructor canónico degradaría los tests). Ver D2 2.x.
        for lomb in ("@Data", "@Setter"):
            if re.search(rf'{re.escape(lomb)}\b', content):
                iss.append(f"{jf.name}: record con {lomb} de Lombok (usar el record puro)")
    if dto_count and not iss:
        pos.append(f"{dto_count} DTO(s) como record (anotaciones JSON preserve-if-present)")
    elif not dto_count:
        pos.append("sin DTOs (nada que validar)")
    return ComplianceResult("dtos", len(iss) == 0, pos, iss)


def check_cobertura(repo_root) -> ComplianceResult:
    pos, iss = [], []
    build = _find_build_gradle(repo_root)
    if not build:
        return ComplianceResult("cobertura", False, [], ["build.gradle NO encontrado"])
    content = _read(build)
    if "architectureConfig" not in content:
        iss.append("architectureConfig NO presente en build.gradle raíz")
    covs = []
    for m in re.findall(r"(?:minimum|coverage)[\w.]*\s*[=:]\s*(0?\.\d+|\d{1,3})", content):
        val = float(m)
        covs.append(int(val * 100) if val <= 1 else int(val))
    if covs:
        if 70 in covs or any(c < MIN_COVERAGE for c in covs):
            iss.append(f"cobertura {covs} — el mínimo es {MIN_COVERAGE}% por módulo (SUPERSEDE 70)")
        else:
            pos.append(f"cobertura {covs}")
    else:
        # PARCIAL: no bloquea CI pero se marca
        iss.append(f"umbral de cobertura no detectado (debe ser {MIN_COVERAGE}% por módulo)")
    if iss and "umbral de cobertura no detectado" in " ".join(iss) and len(iss) == 1:
        return ComplianceResult("cobertura", "partial", pos, iss)
    return ComplianceResult("cobertura", len(iss) == 0, pos, iss)


def check_configmap(repo_root) -> ComplianceResult:
    cm = _find_cm_yaml(repo_root)
    if not cm:
        return ComplianceResult("configmap", None, [], [])  # N/A
    content = _read(cm)
    pos, iss = [], []
    if re.search(r"SERVER_ADDRESS\s*:\s*0\.0\.0\.0", content):
        iss.append("SERVER_ADDRESS: 0.0.0.0 (literal prohibido)")
    if re.search(r'SERVER_PORT\s*:\s*["\']?8080', content):
        iss.append('SERVER_PORT: "8080" (literal prohibido)')
    for i, line in enumerate(content.splitlines(), 1):
        m = re.match(r'^\s*[\w-]*(PATH|URL|ENDPOINT)[\w-]*\s*:\s*(\S+)', line, re.IGNORECASE)
        if m and "${" not in m.group(2) and m.group(2) not in ('""', "''"):
            iss.append(f"línea {i}: path/url hardcodeado sin ${{...}}")
    if "LOGGING_MASK_FIELDS" not in content:
        iss.append("falta LOGGING_MASK_FIELDS en cm.yaml")

    # Consistencia con application.yml (runbook 02: el ConfigMap define las constantes
    # del micro). Toda env var SIN default usada en application.yml debe estar en cm.yaml,
    # o el micro no arrancará. Las que tienen ${VAR:default} no son obligatorias.
    # Se EXCLUYEN variables de plataforma (observabilidad/telemetría) que NO se definen
    # en el ConfigMap del micro sino que las inyecta la plataforma (OTEL, etc.).
    yml = _read(_find_app_yml(repo_root)) if _find_app_yml(repo_root) else ""
    if yml:
        env_no_default = set(re.findall(r'\$\{([A-Z_][A-Z0-9_]*)\}', yml))  # ${VAR} sin ':'
        env_no_default = {v for v in env_no_default if not _is_platform_env_var(v)}
        cm_keys = set(re.findall(r'^\s+([A-Z_][A-Z0-9_]*)\s*:', content, re.MULTILINE))
        missing = sorted(env_no_default - cm_keys)
        if missing:
            iss.append(f"env vars sin default no definidas en cm.yaml: {', '.join(missing[:6])}"
                       + (" ..." if len(missing) > 6 else ""))
        else:
            pos.append("env vars sin default cubiertas por cm.yaml (excluidas las de plataforma)")

        # Observabilidad OTEL: el application.yml debe exportar traces y metrics al
        # collector de la plataforma vía ${OTEL_EXPORTER_OTLP_ENDPOINT}.
        otel = _check_otel_endpoints(yml)
        pos.extend(otel["pos"])
        iss.extend(otel["iss"])

    if not iss:
        pos.append("cm.yaml usa placeholders")
    return ComplianceResult("configmap", len(iss) == 0, pos, iss)


# Variables de plataforma/telemetría que NO se definen en el ConfigMap del micro:
# las inyecta el entorno (observabilidad OTEL, región AWS, etc.). No cuentan para la
# regla de paridad cm.yaml↔application.yml (CFG-01).
# AWS_REGION es excepción explícita a CFG-01: la provee el runtime de AWS/EKS, igual
# que las OTEL_*; debe vivir solo en application.yml, no replicarse en cm.yaml.
_PLATFORM_ENV_PREFIXES = ("OTEL_", "OTLP_")
_PLATFORM_ENV_EXACT = {"OTEL_EXPORTER_OTLP_ENDPOINT", "AWS_REGION"}


def _is_platform_env_var(name: str) -> bool:
    return name in _PLATFORM_ENV_EXACT or name.startswith(_PLATFORM_ENV_PREFIXES)


def _check_otel_endpoints(yml: str) -> dict:
    """Valida la config de observabilidad OTEL en el application.yml:
      - traces:  endpoint = ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces
      - metrics: url      = ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics
    Ambos deben apuntar al collector de la plataforma vía la env var estándar."""
    pos, iss = [], []
    has_traces = re.search(r'\$\{OTEL_EXPORTER_OTLP_ENDPOINT\}\s*/\s*v1/traces', yml) \
        or re.search(r'\$\{OTEL_EXPORTER_OTLP_ENDPOINT\}/v1/traces', yml)
    has_metrics = re.search(r'\$\{OTEL_EXPORTER_OTLP_ENDPOINT\}/v1/metrics', yml)
    if has_traces:
        pos.append("OTEL traces → ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces")
    else:
        iss.append("falta el endpoint de traces OTEL: ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces en application.yml")
    if has_metrics:
        pos.append("OTEL metrics → ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics")
    else:
        iss.append("falta la URL de metrics OTEL: ${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics en application.yml")
    return {"pos": pos, "iss": iss}


def check_credenciales(repo_root) -> ComplianceResult:
    gp = repo_root / "gradle.properties"
    if not gp.exists():
        return ComplianceResult("credenciales", None, [], [])
    sensitive = ["azuredo_user", "azuredo_pass", "azuredo_url", "azureUser", "azurePass"]
    placeholder = re.compile(r'^\$\(.+\)$')
    pos, iss = [], []
    for line_no, raw in enumerate(_read(gp).splitlines(), 1):
        stripped = raw.strip()
        is_comment = stripped.startswith("#")
        effective = stripped.lstrip("#").strip()
        m = re.match(r'^([\w.]+)\s*=\s*(.+)$', effective)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if key not in sensitive or placeholder.match(value):
            continue
        iss.append(f"línea {line_no}: {key} " + ("comentada con valor real" if is_comment else "valor real expuesto"))
    if not iss:
        pos.append("credenciales parametrizadas")
    return ComplianceResult("credenciales", len(iss) == 0, pos, iss)


def check_excepciones(repo_root) -> ComplianceResult:
    pos, iss = [], []
    for jf in _iter_java(repo_root):
        content = _read(jf)
        m = re.search(r'^\s*package\s+([\w.]+)\s*;', content, re.MULTILINE)
        pkg = m.group(1) if m else ""
        if re.search(r'\.exception(\.|$)', pkg) and "com.ficohsa.lib" not in pkg:
            if re.search(r'class\s+\w+\s+extends\s+\w*Exception', content):
                iss.append(f"{jf.name}: excepción custom del proyecto ({pkg})")
    if not iss:
        pos.append("sin excepciones custom del proyecto")
    return ComplianceResult("excepciones", len(iss) == 0, pos, iss)


ALL_CHECKS = [
    check_arquetipo,
    check_main_gradle,
    check_librerias_ficohsa,
    check_jackson3,
    check_logging,
    check_resilience,
    check_mappers,
    check_envelope,
    check_caller_service,
    check_regionalizacion,
    check_homologacion,
    check_dtos,
    check_cobertura,
    check_configmap,
    check_credenciales,
    check_excepciones,
]


# ═══════════════════════════════════════════════════════════════════════════════
# FLUJO END-TO-END — CLONE MASIVO + MAPPING HUs/VG + ET/EF + EXCEL CONSOLIDADO
# (portado de compliance_pipeline_v3.py; PAT vía variable de entorno, no hardcodeado)
# ═══════════════════════════════════════════════════════════════════════════════

import base64
import glob
import time
import subprocess
import urllib.request
import urllib.parse

# ── Configuración Azure DevOps ────────────────────────────────────────────────
# El PAT NUNCA se hardcodea. Se resuelve, en orden de precedencia:
#   1) variable de entorno AZURE_DEVOPS_PAT
#   2) macOS Keychain:  security add-generic-password -a "$USER" -s AZURE_DEVOPS_PAT -w "<pat>"
#   3) archivo local .azure_pat o .env (AZURE_DEVOPS_PAT=<pat>) en el workspace (git-ignored)
# Así cada compañero lo configura UNA sola vez y no lo exporta en cada terminal.

def _resolve_azure_pat() -> str:
    # 1) entorno
    pat = os.environ.get("AZURE_DEVOPS_PAT", "").strip()
    if pat:
        return pat
    # 2) macOS Keychain
    try:
        import subprocess as _sp
        r = _sp.run(["security", "find-generic-password", "-s", "AZURE_DEVOPS_PAT", "-w"],
                    capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    # 3) archivo local en el workspace (junto a scripts/ o su padre)
    here = Path(os.path.dirname(os.path.abspath(__file__)))
    for base in (here, here.parent):
        for fname in (".azure_pat", ".env"):
            fpath = base / fname
            if fpath.exists():
                try:
                    txt = fpath.read_text(encoding="utf-8", errors="replace")
                    if fname == ".azure_pat":
                        val = txt.strip()
                        if val:
                            return val
                    else:
                        for line in txt.splitlines():
                            m = re.match(r'\s*AZURE_DEVOPS_PAT\s*=\s*"?([^"\n]+?)"?\s*$', line)
                            if m:
                                return m.group(1).strip()
                except Exception:
                    pass
    return ""


AZURE_PAT = _resolve_azure_pat()
ORG = os.environ.get("AZURE_DEVOPS_ORG", "DevopsFicohsa")
PROJECT = os.environ.get("AZURE_DEVOPS_PROJECT",
                         "NOVA%20-%20Modernizaci%C3%B3n%20Capa%20Integraci%C3%B3n")
BASE_DIR = os.environ.get("MS_REPOS_DIR", str(Path.home() / "Downloads" / "ms-repos"))
OUTPUT_DIR = os.path.join(BASE_DIR, "compliance_reports")
MAPPING_FILE = os.path.join(BASE_DIR, "micro_hu_mapping.json")
ETEF_DIR = os.path.join(BASE_DIR, "etef_content")


def _azure_headers():
    """Construye los headers de Azure DevOps. Falla claro si no hay PAT."""
    if not AZURE_PAT:
        print("ERROR: falta el PAT de Azure DevOps.\n"
              "       Expórtalo antes de correr:\n"
              "         export AZURE_DEVOPS_PAT=\"<tu-personal-access-token>\"", file=sys.stderr)
        sys.exit(2)
    creds = base64.b64encode(f":{AZURE_PAT}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}


def api_call(url, method="GET", data=None):
    req = urllib.request.Request(url, headers=_azure_headers(), method=method)
    if data:
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def has_source_code(repo_path):
    return any(os.path.exists(os.path.join(repo_path, f))
               for f in ("build.gradle", "settings.gradle", "pom.xml"))


def detect_clasificacion(repo_name):
    """Producto / Composición / Wrapper / Sistema / Experiencia / Lambda / Utilidad."""
    name = repo_name.lower()
    if "wrapper" in name or "-wpr-" in name:
        return "Wrapper"
    if name.endswith("-comp") or ("-comp-" in name and not name.startswith("fn-")):
        return "Composición"
    if name.endswith("-exp") or "-exp-" in name:
        return "Experiencia"
    if name.endswith("-sys") or name.endswith("-system") or "-sys-" in name:
        return "Sistema"
    if name.startswith("fn-"):
        return "Lambda"
    if name.endswith("-util") or "-util-" in name:
        return "Utilidad"
    return "Producto"


def switch_to_staging(repo_path):
    """Intenta cambiar al branch staging (o stagging) y actualizar."""
    for branch in ("staging", "stagging"):
        try:
            r = subprocess.run(["git", "fetch", "--depth", "1", "origin", branch],
                               cwd=repo_path, capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                subprocess.run(["git", "checkout", "-B", branch, "FETCH_HEAD"],
                               cwd=repo_path, capture_output=True, text=True, timeout=10)
                return True
        except Exception:
            pass
    return False


def detect_repo_branch(repo_path):
    """Rama git actual del micro (la rama de la que se tomó el código).
    Determina el ambiente contra el que se valida (dev/stg/uat/prd)."""
    try:
        r = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                           cwd=repo_path, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            branch = r.stdout.strip()
            if branch and branch != "HEAD":
                return branch
        # HEAD desprendido (checkout por FETCH_HEAD): intentar inferir de refs remotos.
        r2 = subprocess.run(["git", "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
                            cwd=repo_path, capture_output=True, text=True, timeout=10)
        if r2.returncode == 0:
            refs = [x.strip().split("/")[-1] for x in r2.stdout.splitlines() if x.strip()]
            for pref in ("develop", "staging", "stagging", "uat", "main", "master"):
                if pref in refs:
                    return pref
    except Exception:
        pass
    return ""


def fetch_variable_group_by_name(group_name):
    """Consulta EN VIVO un Variable Group por su nombre EXACTO en Azure DevOps Library.
    Retorna dict {id, name, variables} o None si no existe / no hay acceso."""
    if not AZURE_PAT:
        print("🔑  Falta AZURE_DEVOPS_PAT: no se puede consultar Azure Library en vivo.\n"
              "       Expórtalo:  export AZURE_DEVOPS_PAT=\"<tu-personal-access-token>\"",
              file=sys.stderr)
        return None
    q = urllib.parse.quote(group_name)
    url = (f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/distributedtask/variablegroups"
           f"?groupName={q}&api-version=7.0")
    res = api_call(url)
    if res is None:
        print("🔑  Azure rechazó la autenticación (¿PAT inválido o expirado?).\n"
              "       Verifica el PAT (debe tener scope de lectura sobre Variable Groups/Library).",
              file=sys.stderr)
        return None
    if res.get("count", 0) == 0:
        return None
    vg = res["value"][0]
    variables = {k: ("***SECRET***" if v.get("isSecret") else v.get("value", ""))
                 for k, v in vg.get("variables", {}).items()}
    return {"id": vg["id"], "name": vg["name"], "variables": variables}


# Ambiente FIJO de validación de la capa Azure/Variable Group. El VG de referencia es SIEMPRE
# el de staging ('<micro>-stg' y los transversales '-stg'), independiente de la rama del repo.
# (La capa AWS —DynamoDB/Parameter Store— sí usa el env derivado de la rama.)
# Sobreescribible con la variable de entorno VG_ENV.
VG_ENV = os.environ.get("VG_ENV", "stg")


def fetch_variable_group_live(repo_name, env=None):
    """Consulta el Variable Group propio del micro '<micro>-<env>'. Por defecto usa el
    ambiente de validación VG_ENV (staging). Retorna {id, name, variables} o None."""
    return fetch_variable_group_by_name(f"{repo_name}-{env or VG_ENV}")


# Variable Groups TRANSVERSALES compartidos (URLs y paths internos). Usan el mismo VG_ENV.
# Sus variables NO se muestran en el reporte, pero SÍ se usan para resolver placeholders del
# cm.yaml (un placeholder que vive aquí no es un NO CUMPLE del VG propio).
TRANSVERSAL_VG_PATTERNS = ("lib-urls-internal-xrs-{env}", "libs-paths-internal-xrs-{env}")


def fetch_transversal_variable_groups(env=None):
    """Descarga los VG transversales del ambiente de validación (VG_ENV por defecto).
    Retorna {var_name: value} combinado (de todos los grupos) o {} si no hay acceso."""
    env = env or VG_ENV
    combined = {}
    for pat in TRANSVERSAL_VG_PATTERNS:
        vg = fetch_variable_group_by_name(pat.format(env=env))
        if vg:
            combined.update(vg.get("variables", {}))
    return combined


# ── PASO 1: CLONE ─────────────────────────────────────────────────────────────

def step1_clone_repos():
    print("\n" + "═" * 70)
    print("  PASO 1: CLONAR REPOS ms-* + SWITCH A STAGING")
    print("═" * 70)
    os.makedirs(BASE_DIR, exist_ok=True)

    url = f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/git/repositories?api-version=7.0"
    result = api_call(url)
    if not result:
        print("  ERROR: No se pudo obtener la lista de repos")
        return
    repos = [r for r in result.get("value", []) if r["name"].startswith("ms-")]
    print(f"  Repos ms-* en Azure: {len(repos)}")

    cloned = skipped = failed = 0
    for i, repo in enumerate(sorted(repos, key=lambda x: x["name"]), 1):
        name = repo["name"]
        repo_path = os.path.join(BASE_DIR, name)
        if os.path.exists(repo_path):
            skipped += 1
        else:
            remote_url = repo["remoteUrl"].replace("DevopsFicohsa@", f"{AZURE_PAT}@")
            try:
                r = subprocess.run(["git", "clone", "--depth", "1", remote_url, repo_path],
                                   capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    cloned += 1
                else:
                    failed += 1
                    print(f"  [WARN] Falló clone de {name}: {r.stderr.strip()[:120]}")
            except subprocess.TimeoutExpired:
                failed += 1
                print(f"  [WARN] Timeout clonando {name} (>120s), se omite")
                if os.path.exists(repo_path):
                    subprocess.run(["rm", "-rf", repo_path], capture_output=True)
            except Exception as e:
                failed += 1
                print(f"  [WARN] Error clonando {name}: {e}")
        if i % 50 == 0:
            print(f"  [{i}/{len(repos)}] Clonados: {cloned} | Existentes: {skipped} | Fallidos: {failed}")

    print(f"  Total: {cloned} clonados, {skipped} ya existían, {failed} fallidos/omitidos")
    print("\n  Cambiando todos a staging...")
    all_dirs = sorted(glob.glob(os.path.join(BASE_DIR, "ms-*")))
    ok = sum(1 for d in all_dirs if os.path.isdir(d) and switch_to_staging(d))
    print(f"  {ok}/{len(all_dirs)} en staging")


# ── PASO 2: BUILD JSON (HUs + Variable Groups) ────────────────────────────────

def extract_links(description):
    if not description:
        return [], []
    href = re.findall(r'href="([^"]+)"', description)
    plain = re.findall(r'(https?://[^\s<"\']+)', description)
    all_urls = list(set(href + plain))
    et = [u for u in all_urls if "/et-" in urllib.parse.unquote(u).lower() or "/et " in urllib.parse.unquote(u).lower()]
    ef = [u for u in all_urls if "/ef-" in urllib.parse.unquote(u).lower() or "/ef " in urllib.parse.unquote(u).lower()]
    return et, ef


def step2_build_json():
    print("\n" + "═" * 70)
    print("  PASO 2: CONSTRUIR JSON (HUs + Variable Groups)")
    print("═" * 70)
    mapping = {}

    print("\n  2A. User Stories con Custom.Repo...")
    wiql_url = f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/wit/wiql?api-version=7.0"
    query = {"query": "SELECT [System.Id] FROM workitems WHERE [System.WorkItemType] = 'User Story' "
                      "AND [Custom.Repo] <> '' ORDER BY [Custom.Repo] ASC"}
    req = urllib.request.Request(wiql_url, data=json.dumps(query).encode(),
                                 headers=_azure_headers(), method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        wiql = json.loads(resp.read().decode())
    all_ids = [wi["id"] for wi in wiql.get("workItems", [])]
    print(f"    User Stories: {len(all_ids)}")

    all_items = []
    for i in range(0, len(all_ids), 200):
        batch = all_ids[i:i + 200]
        ids_str = ",".join(str(x) for x in batch)
        url = f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/wit/workitems?ids={ids_str}&api-version=7.0"
        res = api_call(url)
        if res and "value" in res:
            all_items.extend(res["value"])
        time.sleep(0.3)
    print(f"    Descargadas: {len(all_items)}")

    for wi in all_items:
        fields = wi.get("fields", {})
        repo = fields.get("Custom.Repo", "").strip()
        if not repo:
            continue
        mapping.setdefault(repo, {"repo": repo, "hus": []})
        mapping[repo]["hus"].append(_hu_from_workitem(wi))

    print("\n  2B. Variable Groups (-stg)...")
    local = sorted(os.path.basename(d) for d in glob.glob(os.path.join(BASE_DIR, "ms-*")) if os.path.isdir(d))
    vg_found = 0
    for i, repo_name in enumerate(local, 1):
        vg_name = urllib.parse.quote(f"{repo_name}-stg")
        url = (f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/distributedtask/variablegroups"
               f"?groupName={vg_name}&api-version=7.0")
        res = api_call(url)
        if res and res.get("count", 0) > 0:
            vg = res["value"][0]
            variables = {k: ("***SECRET***" if v.get("isSecret") else v.get("value", ""))
                         for k, v in vg.get("variables", {}).items()}
            mapping.setdefault(repo_name, {"repo": repo_name, "hus": []})
            mapping[repo_name]["variable_group"] = {"id": vg["id"], "name": vg["name"], "variables": variables}
            vg_found += 1
        if i % 50 == 0:
            print(f"    [{i}/{len(local)}] VG: {vg_found}")
        time.sleep(0.15)
    print(f"    Total Variable Groups: {vg_found}")

    output = {
        "metadata": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_microservices": len(mapping),
            "total_user_stories": sum(len(m["hus"]) for m in mapping.values()),
            "variable_groups_found": vg_found,
        },
        "microservices": mapping,
    }
    with open(MAPPING_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\n  ✓ JSON guardado: {MAPPING_FILE}")
    return mapping


# ── PASO 3: DOWNLOAD ET/EF ────────────────────────────────────────────────────

# ── Catálogo de versiones del feed de Azure Artifacts (en vivo, cacheado) ──────
# Nombre del feed Maven y project. Configurables por entorno.
ARTIFACTS_FEED = os.environ.get("AZURE_ARTIFACTS_FEED", "nova-modernizacion")
ARTIFACTS_PROJECT_ID = os.environ.get("AZURE_ARTIFACTS_PROJECT_ID",
                                      "e590dde4-d106-4589-8a2a-f4fa51d868ea")
_FEED_VERSIONS_CACHE = None   # {artifactId: version_mas_alta}


def _version_key(v: str):
    """Clave de orden semántico para versiones tipo '1.2.0' / '2.0.1-rc'. Ignora
    sufijos no numéricos para comparar la parte X.Y.Z."""
    nums = re.findall(r'\d+', v or "")
    return tuple(int(x) for x in nums[:4]) if nums else (0,)


def fetch_feed_versions(force=False):
    """Consulta Azure Artifacts (feed Maven) y devuelve {artifactId: ultima_version}.
    Se cachea por ejecución. Si no hay PAT/red, retorna {} (el check cae al catálogo
    estático LIB_MIN_VERSIONS). Solo considera versiones estables (sin -SNAPSHOT) salvo
    que no exista ninguna estable."""
    global _FEED_VERSIONS_CACHE
    if _FEED_VERSIONS_CACHE is not None and not force:
        return _FEED_VERSIONS_CACHE
    _FEED_VERSIONS_CACHE = {}
    if not AZURE_PAT:
        return _FEED_VERSIONS_CACHE
    url = (f"https://feeds.dev.azure.com/{ORG}/{ARTIFACTS_PROJECT_ID}/_apis/packaging/feeds/"
           f"{ARTIFACTS_FEED}/packages?protocolType=Maven&$top=500&api-version=7.1-preview.1")
    res = api_call(url)
    if not res or "value" not in res:
        return _FEED_VERSIONS_CACHE
    for p in res.get("value", []):
        name = p.get("name", "")          # ej "com.ficohsa.lib:webflux-resilience"
        artifact = name.split(":")[-1]
        versions = [v.get("version", "") for v in p.get("versions", []) if v.get("version")]
        if not versions:
            continue
        stable = [v for v in versions if "-" not in v] or versions
        best = max(stable, key=_version_key)
        _FEED_VERSIONS_CACHE[artifact] = best
    return _FEED_VERSIONS_CACHE


def latest_lib_version(artifact: str):
    """Última versión publicada del artefacto en el feed; si no se puede consultar,
    cae al catálogo estático LIB_MIN_VERSIONS. Retorna (version, fuente)."""
    feed = fetch_feed_versions()
    if artifact in feed:
        return feed[artifact], "feed"
    if artifact in LIB_MIN_VERSIONS:
        return LIB_MIN_VERSIONS[artifact], "catálogo"
    return None, "desconocido"


def fetch_wiki_page(wiki_url):
    match = re.search(r'dev\.azure\.com/([^/]+)/([^/]+)/_wiki/wikis/([^/]+)/(\d+)/(.+?)(?:\?|$)', wiki_url)
    if not match:
        return None
    org = match.group(1)
    project = urllib.parse.quote(urllib.parse.unquote(match.group(2)), safe="")
    wiki_name = urllib.parse.quote(urllib.parse.unquote(match.group(3)), safe="")
    page_id = match.group(4)
    api_url = (f"https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wiki_name}/pages/"
               f"{page_id}?includeContent=true&api-version=7.0")
    res = api_call(api_url)
    return res.get("content", "") if res else None


def _person_name(value):
    """Campo identidad de Azure Boards (dict con displayName, o str) -> nombre."""
    if isinstance(value, dict):
        return (value.get("displayName") or value.get("uniqueName") or "").strip()
    return (value or "").strip() if isinstance(value, str) else ""


def _hu_from_workitem(wi):
    """Construye el dict de HU usado por el pipeline a partir de un work item de Azure.
    El desarrollador sale de Custom.Desarrollador y, si está vacío, de System.AssignedTo."""
    fields = wi.get("fields", {})
    et, ef = extract_links(fields.get("System.Description", ""))
    return {"id": wi["id"], "title": fields.get("System.Title", ""),
            "state": fields.get("System.State", ""), "tags": fields.get("System.Tags", ""),
            "developer": (_person_name(fields.get("Custom.Desarrollador"))
                          or _person_name(fields.get("System.AssignedTo"))),
            "et_links": et, "ef_links": ef,
            "azure_url": f"https://dev.azure.com/{ORG}/{PROJECT}/_workitems/edit/{wi['id']}"}


def fetch_hus_by_ids(hu_ids):
    """Descarga en vivo HUs concretas por ID (flag --hu)."""
    if not AZURE_PAT or not hu_ids:
        return []
    ids_str = ",".join(str(x) for x in hu_ids)
    res = api_call(f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/wit/workitems?ids={ids_str}&api-version=7.0")
    return [_hu_from_workitem(wi) for wi in (res or {}).get("value", [])]


def fetch_hus_for_micro(repo_name, download_docs=True):
    """Equivalente a los pasos 2A+3 del pipeline, pero para UN micro: busca sus User
    Stories en Azure Boards por Custom.Repo = <repo_name>, extrae links ET/EF y (si
    download_docs) descarga el contenido de la wiki a ETEF_DIR. Devuelve la lista de HUs
    (con et_links/ef_links y, si se descargaron, et_content_file/ef_content_file)."""
    if not AZURE_PAT:
        return []
    wiql_url = f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/wit/wiql?api-version=7.0"
    safe_repo = repo_name.replace("'", "''")

    def _wiql_ids(where_clause):
        """Ejecuta un WIQL y devuelve la lista de IDs (o [] si falla)."""
        q = {"query": ("SELECT [System.Id] FROM workitems "
                       "WHERE [System.WorkItemType] = 'User Story' "
                       f"AND {where_clause}")}
        try:
            req = urllib.request.Request(wiql_url, data=json.dumps(q).encode(),
                                         headers=_azure_headers(), method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                w = json.loads(resp.read().decode())
            return [wi["id"] for wi in w.get("workItems", [])]
        except Exception as e:
            print(f"⚠️  No se pudo consultar HUs de '{repo_name}': {e}", file=sys.stderr)
            return []

    terms = {repo_name, repo_name.replace("_", "-")}

    def _discover(field):
        seen = []
        for term in terms:
            safe_term = term.replace("'", "''")
            for _id in _wiql_ids(f"[{field}] CONTAINS '{safe_term}'"):
                if _id not in seen:
                    seen.append(_id)
        return seen

    # 1) Mecanismo principal: HUs con Custom.Repo = <repo_name>.
    ids = _wiql_ids(f"[Custom.Repo] = '{safe_repo}'")

    # 1b) HUs cuyo TÍTULO contiene el nombre del micro se aceptan SIEMPRE, aunque
    #     Custom.Repo esté vacío y aunque otras HUs sí lo tengan (p. ej. HU 123863
    #     "Micro ms-ifs-corr-correspondence_email_mgmt-product" con Custom.Repo = None
    #     y la única con ET descargable). Se verifican luego con límite de palabra
    #     para no mezclar 'ms-x-wrapper' con 'ms-x-wrapper-v2'.
    title_extra = []
    if ids:
        title_extra = [i for i in _discover("System.Title") if i not in ids]
        ids = ids + title_extra

    # 2) Fallback: si ninguna HU tiene Custom.Repo poblado, descubrir por el TÍTULO y,
    #    si tampoco, por la DESCRIPCIÓN. Muchas HUs no llenan Custom.Repo pero mencionan
    #    el micro en el título o traen el "Enlace ET" junto al nombre del repo en la
    #    descripción. Se busca por el nombre del repo y por su forma con guion medio
    #    (brokered_product_admin ↔ brokered-product-admin).
    if not ids:
        ids = _discover("System.Title")
        src = "título"
        if not ids:
            ids = _discover("System.Description")
            src = "descripción"
        if not ids:
            # 3) Parte FUNCIONAL del nombre (sin el prefijo ms-<dom1>-<dom2>-): cubre el caso
            #    en que el repo cambió de dominio (p. ej. '-comp-' → '-wpr-') pero la HU sigue
            #    referenciando el nombre funcional. Ej: 'ms-ic-wpr-data_warehouse-wrapper' →
            #    'data_warehouse-wrapper'. Se prueba la forma con '_' y con '-'.
            m = re.match(r"^ms-[a-z0-9]+-[a-z0-9]+-(.+)$", repo_name, re.IGNORECASE)
            functional = m.group(1) if m else repo_name
            terms = {functional, functional.replace("_", "-")}
            ids = _discover("System.Description") if functional != repo_name else []
            src = "nombre funcional en descripción"
        if ids:
            print(f"ℹ️  Custom.Repo vacío para '{repo_name}'; "
                  f"se descubrieron {len(ids)} HU(s) por {src} (fallback).")

    if not ids:
        print(f"ℹ️  No hay User Stories con Custom.Repo = '{repo_name}' "
              f"ni coincidencias por título en Azure Boards.")
        return []
    ids_str = ",".join(str(x) for x in ids[:200])
    res = api_call(f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/wit/workitems?ids={ids_str}&api-version=7.0")
    hus = [_hu_from_workitem(wi) for wi in (res or {}).get("value", [])]
    if title_extra:
        name_re = re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in terms)
                             + r")(?![\w-])", re.IGNORECASE)
        hus = [h for h in hus if h["id"] not in title_extra or name_re.search(h["title"])]
        added = [h["id"] for h in hus if h["id"] in title_extra]
        if added:
            print(f"ℹ️  + {len(added)} HU(s) sin Custom.Repo con el micro en el título: "
                  + ", ".join(f"#{i}" for i in added))
    print(f"📋  HUs de '{repo_name}': {len(hus)} (ET links: {sum(len(h['et_links']) for h in hus)}, "
          f"EF links: {sum(len(h['ef_links']) for h in hus)})")
    if download_docs:
        os.makedirs(ETEF_DIR, exist_ok=True)
        for hu in hus:
            for kind, key in (("et_links", "et_content_file"), ("ef_links", "ef_content_file")):
                for url in hu.get(kind, []):
                    safe = re.sub(r'[^\w\-.]', "_", urllib.parse.unquote(url.split("/")[-1]))[:100]
                    fp = os.path.join(ETEF_DIR, f"{safe}.md")
                    if not (os.path.exists(fp) and os.path.getsize(fp) > 10):
                        content = fetch_wiki_page(url)
                        if content:
                            Path(fp).write_text(content, encoding="utf-8")
                    if os.path.exists(fp):
                        hu[key] = fp
    return hus


def step3_download_etef(mapping):
    print("\n" + "═" * 70)
    print("  PASO 3: DESCARGAR CONTENIDO ET/EF")
    print("═" * 70)
    os.makedirs(ETEF_DIR, exist_ok=True)
    all_urls = set()
    for ms in mapping.values():
        for hu in ms.get("hus", []):
            all_urls.update(hu.get("et_links", []))
            all_urls.update(hu.get("ef_links", []))
    print(f"  URLs únicas ET/EF: {len(all_urls)}")

    downloaded = cached = failed = 0
    for i, url in enumerate(sorted(all_urls), 1):
        safe = re.sub(r'[^\w\-.]', "_", urllib.parse.unquote(url.split("/")[-1]))[:100]
        fp = os.path.join(ETEF_DIR, f"{safe}.md")
        if os.path.exists(fp) and os.path.getsize(fp) > 10:
            cached += 1
            continue
        content = fetch_wiki_page(url)
        if content:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(content)
            downloaded += 1
        else:
            failed += 1
        if i % 50 == 0:
            print(f"    [{i}/{len(all_urls)}] Desc: {downloaded} | Cache: {cached} | Fallidos: {failed}")
        time.sleep(0.2)
    # Guardar referencias a los archivos de contenido ET/EF en el mapping
    for ms in mapping.values():
        for hu in ms.get("hus", []):
            for kind, key in (("et_links", "et_content_file"), ("ef_links", "ef_content_file")):
                for url in hu.get(kind, []):
                    safe = re.sub(r'[^\w\-.]', "_", urllib.parse.unquote(url.split("/")[-1]))[:100]
                    fp = os.path.join(ETEF_DIR, f"{safe}.md")
                    if os.path.exists(fp):
                        hu[key] = fp
    print(f"  Resultado: {downloaded} descargados, {cached} cache, {failed} fallidos")


# ── PASO 4: ANALIZAR ──────────────────────────────────────────────────────────

def _enrich_with_catalogs(analyses):
    """Enriquece cada análisis con los catálogos CSV (por método)."""
    by_m, by_r = load_catalog()
    api_by_m, api_by_r = load_catalog_api()
    for a in analyses:
        for method in a.methods:
            if by_m or by_r:
                e = match_catalog_for_method(method, a.name, by_m, by_r)
                if e:
                    a.catalog_data[method] = e
            if api_by_m or api_by_r:
                e = match_catalog_for_method(method, a.name, api_by_m, api_by_r)
                if e:
                    a.catalog_api_data[method] = e


def step4_analyze(mapping):
    print("\n" + "═" * 70)
    print("  PASO 4: ANÁLISIS DE COMPLIANCE (arquetipo SB4)")
    print("═" * 70)
    all_analyses = []
    all_repos = sorted(glob.glob(os.path.join(BASE_DIR, "ms-*")))
    with_code = [r for r in all_repos if os.path.isdir(r) and has_source_code(r)]
    print(f"  Repos con código local: {len(with_code)}")
    for i, repo_path in enumerate(with_code, 1):
        repo_name = os.path.basename(repo_path)
        ms_data = mapping.get(repo_name, {})
        try:
            all_analyses.append(analyze_microservice(repo_path, ms_data))
        except Exception as e:
            print(f"    ✗ Error en {repo_name}: {e}")
        if i % 25 == 0:
            print(f"    [{i}/{len(with_code)}] Analizados: {len(all_analyses)}")

    # Repos solo en JSON (sin código local, con VG)
    only_json = [n for n in mapping
                 if n.startswith("ms-")
                 and not os.path.exists(os.path.join(BASE_DIR, n, "build.gradle"))
                 and not os.path.exists(os.path.join(BASE_DIR, n, "settings.gradle"))
                 and mapping[n].get("variable_group")]
    print(f"  Repos solo en JSON (sin código, con VG): {len(only_json)}")
    for n in only_json:
        try:
            all_analyses.append(analyze_limited(n, mapping[n]))
        except Exception as e:
            print(f"    ✗ Error limitado en {n}: {e}")

    print("\n  Cargando catálogos CSV...")
    _enrich_with_catalogs(all_analyses)
    print(f"  Total analizados: {len(all_analyses)}")
    return all_analyses


def step5_generate_reports(analyses, individual_format="html", no_individual=False):
    """analyses: lista de MicroAnalysis (análisis rico). Genera HTML/Excel individual + Excel consolidado."""
    print("\n" + "═" * 70)
    print("  PASO 5: GENERAR REPORTES (Individual + Consolidado)")
    print("═" * 70)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not no_individual:
        count = 0
        for a in analyses:
            if not a.path:
                continue  # sin código local → solo va en el consolidado
            try:
                if individual_format == "json":
                    generate_individual_json_analysis(a, OUTPUT_DIR)
                elif individual_format == "excel":
                    generate_individual_excel(a, OUTPUT_DIR)
                else:
                    generate_individual_html_analysis(a, OUTPUT_DIR)
                count += 1
            except Exception as e:
                print(f"    ✗ Error reporte individual {a.name}: {e}")
        print(f"  Reportes individuales ({individual_format.upper()}): {count}")
    consolidated = generate_consolidated_excel_rich(analyses, OUTPUT_DIR)
    if consolidated:
        print(f"  ✓ CONSOLIDADO (Excel, 5 hojas): {consolidated}")
    return consolidated


def _load_mapping():
    if os.path.exists(MAPPING_FILE):
        try:
            with open(MAPPING_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("microservices", {})
        except Exception:
            return {}
    return {}


# ═══════════════════════════════════════════════════════════════════════════════
# HOMOLOGACIÓN CON v3 — ANÁLISIS RICO (métodos, HU/ET/EF, catálogos, hexagonal,
# reportes HTML/Excel individuales y consolidado de 5 hojas), adaptado a SB4.
# ═══════════════════════════════════════════════════════════════════════════════

import csv
import glob as _glob

CATALOG_CSV = os.environ.get("CATALOG_CSV", os.path.join(BASE_DIR, "Hoja de micros - Catalogo.csv"))
CATALOG_API_CSV = os.environ.get("CATALOG_API_CSV", os.path.join(BASE_DIR, "CatalogoAPI.csv"))
_THIS_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
HEX_VALIDATOR_PATH = os.environ.get("HEX_VALIDATOR_PATH", str(_THIS_DIR / "validation-hexagonal-v3.py"))

# ── Catálogo de librerías Ficohsa (destino SB4): key → artefacto webflux-* ──────
# Alineado con LIB_MIN_VERSIONS (antes faltaban aws-s3 y homologator, y varios artefactos).
# Alineado 1:1 con LIB_MIN_VERSIONS (solo repos lib-java-webflux_* con artefacto webflux-*).
ALL_FICOHSA_LIBS_SB4 = {
    "core":                       "webflux-core",
    "router":                     "webflux-router",
    "exception":                  "webflux-exception",
    "logging":                    "webflux-logging",
    "web-client":                 "webflux-web-client",
    "resilience":                 "webflux-resilience",
    "regionalization":            "webflux-regionalization",
    "homologator":                "webflux-homologator",
    "aws-lambda":                 "webflux-aws-lambda",
    "aws-parameter":              "webflux-aws-parameter",
    "aws-secrets":                "webflux-aws-secrets",
    "aws-s3":                     "webflux-aws-s3",
    "aws-dynamo":                 "webflux-aws-dynamo",
    "bitmap":                     "webflux-bitmap",
    "generate-hash":              "webflux-generate-hash",
    "identifier-generator":       "webflux-identifier-generator",
    "auth-filter-spring-core":    "webflux-auth-filter-spring-core",
    "auth-lambda-resolver-core":  "webflux-auth-lambda-resolver-core",
    "authorization-filter-core":  "webflux-authorization-filter-core",
}


def _find_file(base_path, filename):
    for f in Path(base_path).rglob(filename):
        s = str(f)
        if "/.git/" not in s and "/build/" not in s:
            return str(f)
    return None


def _find_files(base_path, pattern):
    return [str(f) for f in Path(base_path).rglob(pattern)
            if "/.git/" not in str(f) and "/build/" not in str(f)]


def count_lines_of_code(base_path):
    total = 0
    for f in Path(base_path).rglob("*.java"):
        s = str(f)
        if any(x in s for x in ("/.git/", "/build/", "/test/", "/src/test/")):
            continue
        try:
            total += sum(1 for ln in f.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
        except Exception:
            pass
    return total


# ── Detección de endpoints/métodos (portado de v3, simplificado a patrones robustos) ──

def detect_methods(base_path):
    """Detecta las operaciones/endpoints expuestos. Devuelve lista de paths, o placeholder."""
    methods = []
    scan = []
    infra = os.path.join(base_path, "infrastructure")
    if os.path.isdir(infra):
        for root, _dirs, files in os.walk(infra):
            if any(sk in root for sk in ("/test/", "/driven-adapters/", "/driven/", "/helpers/", "/helper/")):
                continue
            scan += [os.path.join(root, f) for f in files if f.endswith(".java")]
    for pat in ("RouterRest.java", "*Router*.java", "*Controller*.java"):
        for rf in _find_files(base_path, pat):
            if "/test/" not in rf and rf not in scan:
                scan.append(rf)

    # Resuelve el valor de una clave de config leída por @Value("${clave:default}")
    # contra el application.yml del micro (toma el default si lo hay, o el valor literal).
    _yml_path = _find_file(base_path, "application.yml") or _find_file(base_path, "application.yaml")
    _yml_txt = _read(_yml_path) if _yml_path else ""

    def _resolve_config_value(config_key):
        # 1) default embebido en el propio @Value: ${KEY:/default}
        # 2) valor en application.yml (última hoja de la clave, con o sin ${ENV:default})
        leaf = config_key.split(".")[-1].replace("-", "[-_]?")
        m = re.search(rf"\b{leaf}\s*:\s*(?:\$\{{[^:}}]+:([^}}]*)\}}|\"?(/[^\"\s]+)\"?)", _yml_txt)
        if m:
            return (m.group(1) or m.group(2) or "").strip()
        return ""

    for fp in scan:
        content = _read(fp)
        if not content:
            continue
        constants = {}
        for cm in re.finditer(r'(?:private|public)?\s*static\s+final\s+String\s+(\w+)\s*=\s*"([^"]+)"', content):
            constants[cm.group(1)] = cm.group(2)
        # Variables inyectadas por @Value("${clave:default}") private String var;
        for vm in re.finditer(r'@Value\s*\(\s*"\$\{([^}]+)\}"\s*\)\s*(?:private|public|protected)?\s*(?:final\s+)?String\s+(\w+)', content):
            spec, var = vm.group(1), vm.group(2)
            key = spec.split(":")[0]
            default_in_value = spec.split(":", 1)[1] if ":" in spec else ""
            val = default_in_value.strip() or _resolve_config_value(key)
            if val:
                constants[var] = val
        # .post/get/put/delete/patch("/literal/path")
        for p in re.findall(r'\.(?:post|put|get|delete|patch)\s*\(\s*"([^"]+)"', content, re.IGNORECASE):
            if "/" in p and len(p) > 5 and not p.startswith("http"):
                methods.append(p)
        # POST("/path") predicates (RouterFunctions)
        for m in re.finditer(r'(?:POST|PUT|GET|DELETE|PATCH)\s*\(\s*"(/[^"]+)"', content):
            methods.append(m.group(1))
        # CONST + "/suffix"
        for m in re.finditer(r'\.(?:post|put|get|delete|patch)\s*\(\s*(\w+)\s*\+\s*"([^"]+)"', content, re.IGNORECASE):
            base = constants.get(m.group(1), "")
            if base:
                methods.append(base.rstrip("/") + m.group(2))
        # @GetMapping/@PostMapping
        for m in re.findall(r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', content):
            if m and len(m) > 2:
                methods.append(m)

    # Fallback: rutas en application.yml
    if not methods:
        yml = _find_file(base_path, "application.yml") or _find_file(base_path, "application.yaml")
        if yml:
            for rm in re.finditer(r':\s*"(/[a-zA-Z][a-zA-Z0-9\-_/{}.]+)"', _read(yml)):
                path = rm.group(1)
                if path.count("/") >= 3 and not any(x in path.lower() for x in ("/actuator", "/swagger", "/api-docs")):
                    methods.append(path)

    methods = list(dict.fromkeys(m.strip() for m in methods))
    excl = ("/swagger", "/actuator", "/api-docs", "/health", "/info", "/metrics", "/v3/api-docs", "__openapi")
    methods = [m for m in methods if not any(x in m.lower() for x in excl) and m.count("/") >= 3]
    return methods or ["(sin endpoints detectados)"]


# ── Matcheo HU / ET / EF ──────────────────────────────────────────────────────

def find_hu_for_method(method, hus):
    if not hus:
        return None
    parts = [p for p in method.strip("/").split("/") if p and len(p) > 4 and not re.match(r"^v\d$", p) and "{" not in p]
    best, best_score = None, 0
    for hu in hus:
        title = (hu.get("title", "") or "").lower()
        desc = (hu.get("description", "") or "").lower()
        score = 0
        for i, seg in enumerate(parts):
            s = seg.lower()
            if s in title or s.replace("-", " ") in title:
                score += (i + 1) * 2
            elif s in desc:
                score += 1
        if score > best_score:
            best, best_score = hu, score
    if best and best_score >= 2:
        return best
    if parts:
        last = parts[-1].lower()
        for hu in hus:
            if last in (hu.get("title", "") or "").lower():
                return hu
    return None


def _hu_doc_text(hu_match):
    if not hu_match:
        return ""
    txt = (hu_match.get("title", "") or "")
    for key in ("et_content_file", "ef_content_file"):
        fp = hu_match.get(key)
        if fp and os.path.exists(fp):
            txt += "\n" + _read(fp)
    return txt.lower()


def doc_mentions_criterion(hu_match, keywords):
    txt = _hu_doc_text(hu_match)
    return any(k.lower() in txt for k in keywords)


# ── Catálogos CSV ─────────────────────────────────────────────────────────────

def load_catalog(csv_path=None):
    csv_path = csv_path or CATALOG_CSV
    by_method, by_repo = {}, {}
    if not os.path.exists(csv_path):
        return by_method, by_repo
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            last = {"repo": "", "proy": "", "micro": ""}
            for row in reader:
                repo = (row.get("Repo") or "").strip()
                if repo and repo != "#N/A":
                    last["repo"] = repo
                else:
                    repo = last["repo"]
                proyecto = (row.get("Proyecto") or "").strip() or last["proy"]
                last["proy"] = proyecto
                method = (row.get("Metodo") or "").strip()
                entry = {
                    "proyecto": proyecto,
                    "clasificacion": (row.get("Clasificacion") or "").strip(),
                    "descripcion_metodo": (row.get("Descripcion del método") or row.get("Descripcion del metodo") or "").strip(),
                    "backend_destino": (row.get("Backend destino") or "").strip(),
                    "business_area": (row.get("Business Area") or "").strip(),
                    "business_domain": (row.get("Business Domain") or "").strip(),
                    "service_domain": (row.get("Service Domain") or "").strip(),
                }
                if repo and method:
                    by_method[(repo, method)] = entry
                if repo:
                    by_repo.setdefault(repo, []).append(entry)
    except Exception:
        pass
    return by_method, by_repo


def load_catalog_api(csv_path=None):
    csv_path = csv_path or CATALOG_API_CSV
    by_method, by_repo = {}, {}
    if not os.path.exists(csv_path):
        return by_method, by_repo
    encoding = "utf-8"
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            f.read()
    except UnicodeDecodeError:
        encoding = "latin-1"
    try:
        with open(csv_path, "r", encoding=encoding, errors="ignore") as f:
            reader = csv.DictReader(f)
            last_repo = ""
            for row in reader:
                repo = (row.get("Nombre y URL Repositorio") or "").strip()
                if repo:
                    last_repo = repo
                else:
                    repo = last_repo
                method = re.sub(r'^(?:GET|POST|PUT|DELETE|PATCH)\s*:?\s*', "", (row.get("Metodo") or "").strip())
                entry = {
                    "analista": (row.get("Analista Responsable") or row.get("Analista") or "").strip(),
                    "arquitecto": (row.get("Arquitecto Responsable") or row.get("Arquitecto") or "").strip(),
                    "mapping_id": (row.get("Mapping ID") or row.get("MappingId") or "").strip(),
                    "estado_metodo": (row.get("Estado método") or row.get("Estado metodo") or "").strip(),
                }
                if repo and method:
                    by_method[(repo, method)] = entry
                if repo:
                    by_repo.setdefault(repo, []).append(entry)
    except Exception:
        pass
    return by_method, by_repo


def match_catalog_for_method(method, repo_name, by_method, by_repo):
    entry = by_method.get((repo_name, method))
    if entry:
        return entry
    repo_entries = by_repo.get(repo_name, [])
    method_parts = method.rstrip("/").split("/")
    best, best_score = None, 0
    for (r, cm), e in by_method.items():
        if r != repo_name:
            continue
        cparts = cm.rstrip("/").split("/")
        score = 0
        for mp, cp in zip(reversed(method_parts), reversed(cparts)):
            if mp == cp:
                score += 1
            else:
                break
        if score > best_score:
            best, best_score = e, score
    if best and best_score >= 2:
        return best
    for e in repo_entries:
        if e.get("clasificacion"):
            return e
    return repo_entries[0] if repo_entries else {}


# ── Integración con el validador hexagonal SB4 (validation-hexagonal-v3.py) ─────

_hex_mod = None


def _get_hex_validator():
    global _hex_mod
    if _hex_mod is not None:
        return _hex_mod
    if not os.path.exists(HEX_VALIDATOR_PATH):
        print(f"  ⚠️  Validador hexagonal no encontrado: {HEX_VALIDATOR_PATH}")
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("validation_hexagonal_v3", HEX_VALIDATOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _hex_mod = mod
    return mod


def run_hexagonal_validation(base_path):
    """Corre validation-hexagonal-v3.py sobre el repo. Retorna (errors, warnings, details)."""
    mod = _get_hex_validator()
    if not mod:
        return 0, 0, [{"type": "WARNING", "rule": "MISSING_VALIDATOR",
                       "message": "validation-hexagonal-v3.py no encontrado", "file": "-", "line": None}]
    try:
        result = mod.validate_repo(Path(base_path))
        details = [{"type": v.severity.value, "file": v.file, "message": v.message,
                    "rule": v.rule, "line": v.line} for v in result.violations]
        return len(result.errors), len(result.warnings), details
    except Exception as e:
        return 0, 0, [{"type": "WARNING", "rule": "VALIDATOR_ERROR",
                       "message": str(e), "file": "-", "line": None}]


# ── Checks por método (adaptados a SB4) ───────────────────────────────────────

def check_method_idempotency(handler_file, usecase_files, method, hu_match=None):
    pos, iss = [], []
    found = False
    for uc in usecase_files:
        c = _read(uc)
        if any(k in c for k in ("idempoten", "Idempoten", "IdempotencyGateway", "X-Idempotency", "EventBridge")):
            found = True
            pos.append(f"UseCase con idempotencia ({os.path.basename(uc)})")
            break
    if handler_file and not found:
        if any(k in _read(handler_file) for k in ("idempoten", "X-Idempotency")):
            found = True
            pos.append("Handler con idempotencia")
    if "retrieve" in method.lower() or "/get" in method.lower():
        return ComplianceResult("Idempotencia (método)", None, ["retrieve — no requiere"], [])
    if found:
        return ComplianceResult("Idempotencia (método)", True, pos, [])
    if hu_match and doc_mentions_criterion(hu_match, ["idempoten", "idempotency"]):
        return ComplianceResult("Idempotencia (método)", False, [], ["ET/EF menciona idempotencia pero no se detecta"])
    return ComplianceResult("Idempotencia (método)", None, [], ["No requerida por doc — no aplica"])


def check_method_resilience(handler_file, usecase_files, method, base_path=None):
    """SB4: @FicohsaResilience dinámico (perRegion=true) o CircuitBreaker en usecase/adapter.
    En arquitectura hexagonal la resiliencia de las llamadas salientes se declara en los
    driven-adapters, no en el use case; por eso se incluyen los *Adapter.java del proyecto."""
    pos, iss = [], []
    files = list(usecase_files) + ([handler_file] if handler_file else [])
    text = "\n".join(_read(f) for f in files if f)
    # Incluir los driven-adapters del proyecto: la resiliencia de llamadas salientes
    # se anota en los *Adapter.java (no en el use case).
    if base_path:
        adapters = "\n".join(_read(f) for f in _find_files(base_path, "*Adapter.java"))
        text = text + "\n" + adapters
    if "@FicohsaResilience" in text:
        pos.append("@FicohsaResilience presente")
        for attr in ("label", "paramName", "paramLabel"):
            if re.search(rf'@FicohsaResilience\s*\([^)]*\b{attr}\s*=', text, re.DOTALL):
                iss.append(f"modo deprecado ({attr})")
        m = re.search(r'instanceName\s*=\s*"(cb-[\w-]+)"', text)
        if m:
            iss.append(f"instanceName '{m.group(1)}' cb-<sistema> (debe ser nombre de método)")
        return ComplianceResult("Resilience (método)", len(iss) == 0, pos, iss)
    if any(k in text for k in ("CircuitBreaker", "ReactiveCircuitBreaker", "ResilienceExecutor")):
        return ComplianceResult("Resilience (método)", True, ["Circuit breaker presente"], [])
    return ComplianceResult("Resilience (método)", False, [], ["No se detecta @FicohsaResilience ni circuit breaker"])


def check_method_error_handling(handler_file, usecase_files, method, base_path):
    """SB4: manejo reactivo (onErrorMap/onErrorResume) + BusinessCoreException (librería)."""
    pos, iss = [], []
    files = list(usecase_files) + ([handler_file] if handler_file else [])
    text = "\n".join(_read(f) for f in files if f)
    adapters = "\n".join(_read(f) for f in _find_files(base_path, "*Adapter.java"))
    has_reactive = any(k in text or k in adapters for k in ("onErrorResume", "onErrorMap", "onErrorReturn"))
    has_bce = "BusinessCoreException" in text or "BusinessCoreException" in adapters
    if has_reactive:
        pos.append("manejo de errores reactivo (onErrorMap/onErrorResume)")
    else:
        iss.append("sin manejo de errores reactivo")
    if has_bce:
        pos.append("usa BusinessCoreException (librería)")
    return ComplianceResult("Manejo de errores (método)", len(iss) == 0, pos, iss)


def _build_handler_map(base_path):
    handler_map = {}
    routers = _find_files(base_path, "RouterRest.java")
    if not routers:
        return handler_map
    content = _read(routers[0])
    # Nota: entre la ruta y el handler puede haber un ParameterizedTypeReference<...>(){}
    # (patrón RestComponent de la librería router), cuyos paréntesis rompían un [^)]*?.
    # Se usa [\s\S]*? (no voraz) para cruzar esos paréntesis hasta el 'XxxHandler::'.
    for route, hvar in re.findall(
            r'\.(?:post|get|put|delete|patch)\s*\(\s*"([^"]+)"[\s\S]*?(\w+Handler)\s*::', content):
        handler_map[route] = hvar
    return handler_map


def _find_handler_and_usecase_for_method(method, handler_map, base_path):
    handler_file, usecase_files = "", []
    hvar = handler_map.get(method, "")
    if not hvar:
        for route, hv in handler_map.items():
            if method in route or route in method:
                hvar = hv
                break
    if hvar:
        cls = hvar[0].upper() + hvar[1:]
        matches = _find_files(base_path, f"{cls}.java")
        if matches:
            handler_file = matches[0]
    if not handler_file:
        for part in reversed(method.strip("/").split("/")):
            if len(part) > 3:
                hs = _find_files(base_path, f"*{part}*Handler.java")
                if hs:
                    handler_file = hs[0]
                    break
    if handler_file:
        hc = _read(handler_file)
        ifaces = re.findall(r'private\s+final\s+(I\w+UseCase)\s+', hc) or \
                 re.findall(r'import\s+com\.ficohsa\.ports\.\w+\.(I\w+UseCase)', hc)
        for iface in ifaces:
            impl = iface[1:]
            ucs = _find_files(base_path, f"{impl}.java")
            usecase_files.extend(u for u in ucs if "/usecase/" in u.replace("\\", "/"))
        if not usecase_files:
            hname = os.path.basename(handler_file).replace("Handler.java", "")
            usecase_files = _find_files(base_path, f"{hname}UseCase.java")
    return handler_file, usecase_files


# ── MicroAnalysis (estructura rica homologada con v3) ──────────────────────────

@dataclass
class MicroAnalysis:
    name: str
    path: str
    methods: list = field(default_factory=list)
    results: list = field(default_factory=list)            # criterios micro (ComplianceResult)
    method_results: dict = field(default_factory=dict)     # {method: [ComplianceResult]}
    ficohsa_libs_present: dict = field(default_factory=dict)
    ficohsa_libs_missing: dict = field(default_factory=dict)
    spring_boot_version: str = ""
    lines_of_code: int = 0
    hu_id: str = ""
    hu_title: str = ""
    hu_dev: str = ""                                   # desarrollador de la HU (Custom.Desarrollador / AssignedTo)
    variable_group: dict = field(default_factory=dict)
    aws_results: list = field(default_factory=list)   # resultados AWS en vivo (DynamoDB/ParamStore/Secrets)
    aws_env: str = ""                                  # ambiente derivado (dev/stg/uat/prd)
    aws_table: str = ""                                # tabla DynamoDB usada
    et_results: list = field(default_factory=list)     # resultados de validación de la ET (dicts)
    et_source: str = ""                                # de dónde se obtuvo la ET (ruta/URL/HU)
    source_branch: str = ""                            # rama git de la que se tomó el código fuente
    source_commit: str = ""                            # commit corto del código analizado
    vg_env: str = "stg"                                # ambiente del Variable Group (derivado de la rama)
    micro_lib_versions: dict = field(default_factory=dict)  # {artifact: version que usa el micro}
    hus: list = field(default_factory=list)
    catalog_data: dict = field(default_factory=dict)
    catalog_api_data: dict = field(default_factory=dict)
    clasificacion: str = ""
    migration_state: str = "unknown"
    hex_errors: int = 0
    hex_warnings: int = 0
    hex_details: list = field(default_factory=list)

    @property
    def critical_failures(self):
        # "Crítico" = criterios de CRITICAL_CRITERIA que NO CUMPLEN. Otros criterios
        # (p. ej. sizing) pueden fallar sin bloquear el resultado global.
        return [r for r in self.results if r.criterion in CRITICAL_CRITERIA and r.status == "NO CUMPLE"]


# Etiqueta legible de cada criterio micro (para reportes)
_CRIT_LABEL = {
    "arquetipo": "Arquetipo", "librerias_ficohsa": "Librerías Ficohsa",
    "jackson3": "Jackson 3", "logging": "Logs", "resilience": "Resilience",
    "mappers": "MapStruct Mappers", "envelope": "Request Envelope",
    "caller_service": "Caller-Service / @LogExternalCall", "regionalizacion": "Regionalización",
    "homologacion": "Homologación",
    "dtos": "DTOs (record)", "cobertura": "Cobertura 85%", "configmap": "ConfigMap (k8s)",
    "credenciales": "Credenciales gradle", "excepciones": "Sin excepciones custom",
    "migracion_sb4": "Migración SB4", "sizing": "Tallaje (ms-sizing)",
    "vg_cm_alineacion": "Variable Group ↔ cm.yaml",
    "aws_recursos": "Recursos AWS (DynamoDB/Param/Secrets)",
    "main_gradle": "main.gradle (estándar)",
}


def _detect_libs_present(repo_root):
    """Deriva present/missing sobre el catálogo SB4 usando _detect_ficohsa_libs."""
    detected = _detect_ficohsa_libs(repo_root)
    present, missing = {}, {}
    for key, artifact in ALL_FICOHSA_LIBS_SB4.items():
        # presente si el artefacto webflux-* o su forma legacy (sin prefijo) aparece
        legacy = artifact.replace("webflux-", "")
        if artifact in detected or legacy in detected or any(a == legacy or a == artifact for a in detected):
            present[key] = artifact
        else:
            missing[key] = artifact
    return present, missing


def analyze_microservice(base_path, ms_data=None):
    """Análisis rico de un micro: métodos, criterios micro SB4, por-método, HU/ET/EF, hexagonal."""
    base_path = str(base_path)
    ms_data = ms_data or {}
    name = os.path.basename(os.path.abspath(base_path))
    a = MicroAnalysis(name=name, path=base_path)
    a.clasificacion = detect_clasificacion(name)
    vg = ms_data.get("variable_group", {})
    a.variable_group = vg.get("variables", {}) if vg else {}
    a.hus = ms_data.get("hus", [])
    a.spring_boot_version = _spring_boot_version(Path(base_path)) or "No detectada"
    a.lines_of_code = count_lines_of_code(base_path)
    a.migration_state = detect_migration_state(Path(base_path))
    a.ficohsa_libs_present, a.ficohsa_libs_missing = _detect_libs_present(Path(base_path))
    a.micro_lib_versions = _resolve_micro_lib_versions(Path(base_path))
    a.methods = detect_methods(base_path)

    hu0 = find_hu_for_method(a.methods[0], a.hus) if a.hus else None
    if hu0 is None and a.hus:
        hu0 = a.hus[0]   # sin match por endpoint: se reporta la primera HU del micro
    a.hu_id = str(hu0["id"]) if hu0 else ""
    a.hu_title = hu0.get("title", "") if hu0 else ""
    a.hu_dev = hu0.get("developer", "") if hu0 else ""

    # Criterios a nivel micro = ALL_CHECKS de v5 (SB4), con relabel SB3 igual que analyze_micro
    state = a.migration_state
    if state == "sb3":
        a.results.append(ComplianceResult("migracion_sb4", "not_found", [],
            ["Repositorio aún NO migrado a Spring Boot 4 (ejecutar el TD antes de validar el arquetipo SB4)"]))
    for check in ALL_CHECKS:
        try:
            res = check(Path(base_path))
        except Exception as e:
            res = ComplianceResult(check.__name__.replace("check_", ""), False, [], [f"Error: {e}"])
        if state == "sb3" and res.compliant is False and res.criterion in _SB4_ONLY_CRITERIA:
            res = ComplianceResult(res.criterion, "not_found", res.positives,
                                   ["[pendiente de migración SB4] " + i for i in res.issues])
        a.results.append(res)

    # Tallaje EKS: valida la variable ms-sizing del Variable Group (lineamiento 03).
    a.results.append(check_sizing(a.variable_group))
    # Alineación Variable Group ↔ cm.yaml (gobierno de parámetros). Suma al conteo global.
    # Incluye los VG transversales (urls/paths internos) para resolver placeholders compartidos.
    _cm_p = _find_cm_yaml(Path(base_path))
    _transv = (ms_data or {}).get("transversal_vars", {})
    _vg_env = (ms_data or {}).get("vg_env", "stg")
    a.vg_env = _vg_env
    a.results.append(check_variable_group_cm_match(
        a.variable_group, _read(_cm_p) if _cm_p else "", _transv, env=_vg_env))

    # Validación hexagonal (adjunta a nivel análisis)
    a.hex_errors, a.hex_warnings, a.hex_details = run_hexagonal_validation(base_path)

    # Checks por método
    handler_map = _build_handler_map(base_path)
    for method in a.methods:
        mhu = find_hu_for_method(method, a.hus)
        hf, ucs = _find_handler_and_usecase_for_method(method, handler_map, base_path)
        checks = [
            check_method_idempotency(hf, ucs, method, mhu),
            check_method_resilience(hf, ucs, method, base_path),
        ]
        if a.clasificacion in ("Composición", "Experiencia", "Utilidad"):
            checks.append(ComplianceResult("Manejo de errores (método)", None,
                                           [f"N/A para {a.clasificacion}"], []))
        else:
            checks.append(check_method_error_handling(hf, ucs, method, base_path))
        a.method_results[method] = checks

    return a


def analyze_limited(repo_name, ms_data):
    """Repos sin código local: solo VG + HUs."""
    a = MicroAnalysis(name=repo_name, path="")
    vg = ms_data.get("variable_group", {})
    a.variable_group = vg.get("variables", {}) if vg else {}
    a.hus = ms_data.get("hus", [])
    a.clasificacion = detect_clasificacion(repo_name)
    a.methods = ["(sin código local)"]
    hu0 = a.hus[0] if a.hus else None
    a.hu_id = str(hu0["id"]) if hu0 else ""
    a.hu_title = hu0.get("title", "") if hu0 else ""
    a.hu_dev = hu0.get("developer", "") if hu0 else ""
    for crit in ("arquetipo", "librerias_ficohsa", "jackson3", "logging", "resilience",
                 "mappers", "envelope", "caller_service", "regionalizacion", "dtos",
                 "cobertura", "configmap"):
        a.results.append(ComplianceResult(crit, None, [], ["Sin código local"]))
    # Tallaje EKS: sí se puede validar aquí porque el VG está disponible.
    a.results.append(check_sizing(a.variable_group))
    # ET/EF desde la HU
    et_ok, et_pos, et_iss = True, [], []
    if hu0:
        if hu0.get("et_links"):
            et_pos.append("ET presente")
        else:
            et_iss.append("Sin link a ET"); et_ok = False
        if hu0.get("ef_links"):
            et_pos.append("EF presente")
        else:
            et_iss.append("Sin link a EF"); et_ok = False
    else:
        et_iss.append("Sin HU asociada"); et_ok = False
    a.results.append(ComplianceResult("et_ef", et_ok, et_pos, et_iss))
    return a


# ── % de cumplimiento (excluye criterios no ponderables) ───────────────────────

EXCLUIDOS_PCT = {"regionalizacion", "migracion_sb4"}


def _analysis_pct(a):
    applicable = [r for r in a.results if r.compliant in (True, False) and r.criterion not in EXCLUIDOS_PCT]
    for checks in a.method_results.values():
        applicable += [r for r in checks if r.compliant in (True, False)]
    if not applicable:
        return 0.0
    ok = sum(1 for r in applicable if r.compliant is True)
    return round(ok / len(applicable) * 100, 1)


# ── Reporte HTML individual ────────────────────────────────────────────────────

def _ver_ge(a_ver: str, b_ver: str) -> bool:
    """True si a_ver >= b_ver (comparación semántica tolerante)."""
    def parts(v):
        nums = re.findall(r"\d+", str(v))
        return [int(x) for x in nums] or [0]
    pa, pb = parts(a_ver), parts(b_ver)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa)); pb += [0] * (n - len(pb))
    return pa >= pb


def generate_individual_html_analysis(a: MicroAnalysis, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    pct = _analysis_pct(a)
    status_color = "#16a34a" if pct >= 85 else ("#d97706" if pct >= 60 else "#dc2626")
    badge = {"CUMPLE": "#16a34a", "NO CUMPLE": "#dc2626", "N/A": "#64748b",
             "NO ENCONTRADO": "#0284c7", "PARCIAL": "#d97706"}

    def rows(results):
        out = ""
        for r in results:
            label = _CRIT_LABEL.get(r.criterion, r.criterion)
            detail = "<br>".join(f"✓ {p}" for p in r.positives)
            if r.issues:
                detail += ("<br>" if detail else "") + r.observation_summary
            out += (f'<tr><td>{label}</td><td><span style="background:{badge.get(r.status,"#666")};'
                    f'color:white;padding:2px 8px;border-radius:4px;font-size:12px">{r.status}</span></td>'
                    f'<td style="font-size:12px">{detail or "—"}</td></tr>')
        return out

    method_sections = ""
    for method, checks in a.method_results.items():
        method_sections += f'<h3 style="margin-top:16px">🔗 {method}</h3><table><thead><tr><th>Criterio</th><th>Estado</th><th>Detalle</th></tr></thead><tbody>{rows(checks)}</tbody></table>'

    # Librerías: versión del feed (LIB_MIN_VERSIONS) vs versión que usa el micro.
    libs_rows = ""
    for key, art in {**a.ficohsa_libs_present, **a.ficohsa_libs_missing}.items():
        presente = key in a.ficohsa_libs_present
        _lv, _lf = latest_lib_version(art)
        feed_ver = _lv or LIB_MIN_VERSIONS.get(art, "—")
        # versión que usa el micro: busca por artefacto webflux-* o su forma legacy
        legacy = art.replace("webflux-", "")
        micro_ver = a.micro_lib_versions.get(art) or a.micro_lib_versions.get(legacy) or ("—" if not presente else "?")
        # cumple: presente y (versión del micro >= feed, o catálogo sin versión resoluble)
        if not presente:
            cmp_html = '<span style="background:#64748b;color:white;padding:2px 8px;border-radius:4px;font-size:12px">NO UTILIZADA</span>'
        elif micro_ver in ("?", "—"):
            cmp_html = '<span style="background:#d97706;color:white;padding:2px 8px;border-radius:4px;font-size:12px">REVISAR</span>'
        else:
            ok = _ver_ge(micro_ver, feed_ver) if feed_ver not in ("—",) else True
            cmp_html = (f'<span style="background:{"#16a34a" if ok else "#dc2626"};color:white;'
                        f'padding:2px 8px;border-radius:4px;font-size:12px">{"CUMPLE" if ok else "DESACTUALIZADA"}</span>')
        libs_rows += (f'<tr><td>{key}</td><td style="font-family:monospace;font-size:12px">com.ficohsa.lib:{art}</td>'
                      f'<td style="font-family:monospace">{feed_ver}</td>'
                      f'<td style="font-family:monospace">{micro_ver}</td><td>{cmp_html}</td></tr>')

    hex_section = ""
    if a.hex_details:
        hitems = "".join(f'<li style="font-size:12px">[{d["type"]}] {d["rule"]} — {d["file"]}{":"+str(d["line"]) if d.get("line") else ""}: {d["message"]}</li>'
                         for d in a.hex_details[:200])
        hex_section = f'<ul>{hitems}</ul>'
    else:
        hex_section = '<p class="ts">Sin detalles de validación hexagonal.</p>'

    import html as _html

    # ── Pestaña AWS (DynamoDB / Parameter Store / Secrets, en vivo) ──────────────
    aws_badge = {"ok": "#16a34a", "fail": "#dc2626", "na": "#64748b",
                 "no_creds": "#d97706", "error": "#dc2626"}
    aws_label = {"ok": "OK", "fail": "NO CUMPLE", "na": "N/A",
                 "no_creds": "SIN CREDENCIALES", "error": "ERROR"}
    if a.aws_results:
        aws_rows = ""
        dynamo_records = []
        for r in a.aws_results:
            st = r.get("status", "na")
            det = _html.escape(str(r.get("detail", "") or ""))
            pos = "".join(f"<div style='color:#16a34a'>✓ {_html.escape(str(p))}</div>" for p in r.get("positives", []))
            iss = "".join(f"<div style='color:#dc2626'>✗ {_html.escape(str(i))}</div>" for i in r.get("issues", []))
            body = (det + ("<br>" if det and (pos or iss) else "") + pos + iss) or "—"
            aws_rows += (f'<tr><td>{_html.escape(str(r.get("check","")))}</td>'
                         f'<td><span style="background:{aws_badge.get(st,"#666")};color:white;'
                         f'padding:2px 8px;border-radius:4px;font-size:12px">{aws_label.get(st,st.upper())}</span></td>'
                         f'<td style="font-size:12px">{body}</td></tr>')
            dynamo_records.extend(r.get("records", []) or [])
        # Registro(s) DynamoDB cargado(s): se muestran como JSON formateado.
        import json as _json
        if dynamo_records:
            recs_html = ""
            for it in dynamo_records:
                pk = it.get("countryDomaParamKey") or it.get("pk") or ""
                sk = it.get("versionVigenciaKey") or it.get("sk") or ""
                pretty = _html.escape(_json.dumps(it, indent=2, ensure_ascii=False, default=str))
                recs_html += (f'<details open style="margin-bottom:8px"><summary style="cursor:pointer;font-family:monospace;font-size:12px">'
                              f'📄 {_html.escape(str(pk))} {("| "+_html.escape(str(sk))) if sk else ""}</summary>'
                              f'<pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:12px">{pretty}</pre></details>')
            records_block = f'<h4 style="margin:14px 0 6px">Registro(s) DynamoDB cargado(s) ({len(dynamo_records)})</h4>{recs_html}'
        else:
            records_block = '<p class="ts">No se cargó ningún registro DynamoDB (micro sin parametrización, o sin constantes REGIONALIZATION_* para ubicarlo).</p>'
        aws_tab = (f'<p class="ts">Ambiente: <strong>{a.aws_env or "-"}</strong> | '
                   f'Tabla DynamoDB: <code>{_html.escape(a.aws_table or "-")}</code> | '
                   f'Fuente: AWS en vivo (Parameter Store / Secrets Manager / DynamoDB)</p>'
                   f'<table><thead><tr><th>Check</th><th>Estado</th><th>Detalle</th></tr></thead>'
                   f'<tbody>{aws_rows}</tbody></table>'
                   f'{records_block}')
    else:
        aws_tab = ('<p class="ts">No se ejecutaron validaciones AWS en vivo (modo <code>--no-aws</code> '
                   'o sin sesión SSO activa). Ejecuta <code>aws sso login --profile &lt;perfil&gt;</code> '
                   'y corre sin <code>--no-aws</code> para poblar esta pestaña.</p>')

    # ── Pestaña Azure / Variable Group (Library de Azure DevOps) ─────────────────
    if a.variable_group:
        _VALID_SIZING = {"XS", "S", "M", "L", "XL"}
        # Variables genéricas de DESPLIEGUE/PIPELINE (ECS/EKS): no van en el cm.yaml del micro
        # (las usa el pipeline para desplegar el pod). No se evalúan como correspondencia.
        # Usa la MISMA lógica que el criterio contado (check_variable_group_cm_match /
        # evaluate_vg_variable) para que el HTML y el conteo global sean consistentes.
        _cm_path = _find_cm_yaml(Path(a.path)) if a.path else None
        _cm_text = _read(_cm_path) if _cm_path else ""
        _cm_placeholders = set(re.findall(r'\$\{([^}]+)\}', _cm_text))
        # El aviso y el detalle salen del criterio YA calculado (vg_cm_alineacion), que
        # considera los VG transversales — así el banner no contradice la columna por fila.
        _vg_result = next((r for r in a.results if r.criterion == "vg_cm_alineacion"), None)
        _vg_issues = list(_vg_result.issues) if _vg_result else []
        _badge = {"ok": "#16a34a", "fail": "#dc2626", "na": "#64748b"}
        _vtxt = {"ok": "CUMPLE", "fail": "NO CUMPLE", "na": "—"}
        def _vg_rule(key, val):
            verdict, reason = evaluate_vg_variable(key, val, _cm_placeholders if _cm_text else None, vg_env=a.vg_env)
            txt = _vtxt[verdict] + (f" ({reason})" if reason and verdict != "na" else "")
            return (f'<span style="background:{_badge[verdict]};color:white;padding:2px 8px;'
                    f'border-radius:4px;font-size:12px">{txt}</span>')
        vg_rows = ""
        for k in sorted(a.variable_group.keys()):
            raw = a.variable_group.get(k)
            v = "***SECRET***" if raw == "***SECRET***" else _html.escape(str(raw))
            vg_rows += (f'<tr><td style="font-family:monospace;font-size:12px">{_html.escape(str(k))}</td>'
                        f'<td style="font-size:12px">{v}</td><td>{_vg_rule(k, raw)}</td></tr>')
        warn_log = ""
        if _vg_issues:
            lis = "".join(f"<li>{_html.escape(i)}</li>" for i in _vg_issues)
            warn_log = (f'<div style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;'
                        f'padding:10px 14px;border-radius:8px;margin-bottom:10px"><strong>❌ NO CUMPLE — '
                        f'Variable Group ↔ cm.yaml ({len(_vg_issues)} hallazgo/s):</strong>'
                        f'<ul style="margin:6px 0 0">{lis}</ul></div>')
        elif _vg_result and _vg_result.compliant is True:
            warn_log = ('<div style="background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;'
                        'padding:10px 14px;border-radius:8px;margin-bottom:10px">✅ CUMPLE — '
                        'correspondencia Variable Group ↔ cm.yaml (incluye VG transversales).</div>')
        n_vg_ok = sum(1 for k in a.variable_group if k in _cm_placeholders)
        vg_tab = (f'{warn_log}'
                  f'<p class="ts">Variable Group <code>{a.name}-{a.vg_env}</code> consultado en vivo en Azure DevOps Library '
                  f'({len(a.variable_group)} variables; {n_vg_ok} referenciadas por el <code>cm.yaml</code>). '
                  f'Placeholders del cm.yaml compartidos se resuelven en VG transversales '
                  f'(<code>lib-urls-internal-xrs-{a.vg_env}</code> / <code>libs-paths-internal-xrs-{a.vg_env}</code>, no mostrados). '
                  f'Los secretos se muestran como <code>***SECRET***</code>. '
                  f'La columna evalúa: ambiente (sufijo = <code>{a.vg_env}</code>), '
                  f'<code>ms-sizing</code>, <code>java-options</code> (TLS), y la correspondencia general cm.yaml ↔ VG.</p>'
                  f'<div class="tablewrap"><table class="azure-table"><thead><tr><th>Variable</th><th>Valor</th><th>Cumple lineamiento</th></tr></thead><tbody>{vg_rows}</tbody></table></div>')
    else:
        vg_tab = ('<p class="ts">Variable Group no disponible. Exporta <code>AZURE_DEVOPS_PAT</code> '
                  '(o configúralo en Keychain / .azure_pat) para consultar la Azure DevOps Library en vivo.</p>')

    # ── Pestaña Especificación Técnica (ET) ─────────────────────────────────────
    et_badge = {"ok": "#16a34a", "fail": "#dc2626", "na": "#64748b", "warn": "#d97706"}
    et_label = {"ok": "OK", "fail": "NO CUMPLE", "na": "N/A", "warn": "ADVERTENCIA"}
    _ET_CHECK_LABEL = {
        "et_estructura": "Estructura de la ET (plantilla)",
        "et_caller_service": "Caller-service en la ET (formato)",
        "et_enmascarado": "Enmascarado en la ET (estándares)",
        "et_vs_clasificacion": "ET ↔ clasificación del micro",
        "et_vs_endpoints": "ET ↔ endpoints del código",
        "et_vs_caller_service": "ET ↔ caller-service del código",
        "et_vs_enmascarado": "ET ↔ campos cifrados del micro",
        "et": "Especificación Técnica",
    }
    if a.et_results and not (len(a.et_results) == 1 and a.et_results[0].get("check") == "et"
                             and a.et_results[0].get("status") == "na"):
        et_rows = ""
        for r in a.et_results:
            st = r.get("status", "na")
            label = _ET_CHECK_LABEL.get(r.get("check", ""), r.get("check", ""))
            det = _html.escape(str(r.get("detail", "") or ""))
            pos = "".join(f"<div style='color:#16a34a'>✓ {_html.escape(str(p))}</div>" for p in r.get("positives", [])[:8])
            iss = "".join(f"<div style='color:#dc2626'>✗ {_html.escape(str(i))}</div>" for i in r.get("issues", []))
            body = (det + ("<br>" if det and (pos or iss) else "") + pos + iss) or "—"
            et_rows += (f'<tr><td>{_html.escape(label)}</td>'
                        f'<td><span style="background:{et_badge.get(st,"#666")};color:white;'
                        f'padding:2px 8px;border-radius:4px;font-size:12px">{et_label.get(st,st.upper())}</span></td>'
                        f'<td style="font-size:12px">{body}</td></tr>')
        et_tab = (f'<p class="ts">Fuente de la ET: <code>{_html.escape(a.et_source or "-")}</code>. '
                  f'Plano A = ET bien formada (plantilla + lineamientos). '
                  f'Plano B = la ET coincide con lo desarrollado en el código.</p>'
                  f'<table><thead><tr><th>Validación</th><th>Estado</th><th>Detalle</th></tr></thead>'
                  f'<tbody>{et_rows}</tbody></table>')
    else:
        et_tab = (f'<p class="ts">No se validó la ET: <code>{_html.escape(a.et_source or "sin ET")}</code>. '
                  f'Pásala con <code>--et &lt;ruta.md&gt;</code> o <code>--et-url &lt;url-wiki&gt;</code>, '
                  f'o deja que se autodescubra desde los <code>et_links</code> de las HUs del micro.</p>')
    n_et_fail = sum(1 for r in a.et_results if r.get("status") in ("fail",))
    n_et_ok = sum(1 for r in a.et_results if r.get("status") == "ok")

    n_aws_fail = sum(1 for r in a.aws_results if r.get("status") == "fail")
    n_aws_ok = sum(1 for r in a.aws_results if r.get("status") == "ok")

    # ── Línea de "Fuente del análisis" por pestaña (trazabilidad) ───────────────
    def _src(txt):
        return (f'<div style="background:#eef2ff;border-left:3px solid #6366f1;color:#3730a3;'
                f'padding:6px 10px;border-radius:4px;margin-bottom:10px;font-size:12px">'
                f'📍 <strong>Fuente del análisis:</strong> {txt}</div>')

    def _linkify(text, label=None):
        """Convierte una URL en <a>. Si text contiene una URL embebida, la extrae."""
        m = re.search(r'(https?://[^\s<>"\')]+)', text or "")
        if not m:
            return _html.escape(text or "-")
        url = m.group(1)
        shown = label or url
        return (text.replace(url, f'<a href="{_html.escape(url)}" target="_blank" '
                f'rel="noopener" style="color:#4f46e5">{_html.escape(shown)}</a>')
                if label is None else
                f'<a href="{_html.escape(url)}" target="_blank" rel="noopener" style="color:#4f46e5">{_html.escape(shown)}</a>')

    _branch = _html.escape(a.source_branch or "-")
    # URL del repositorio en Azure DevOps (a la rama analizada).
    _repo_url = (f"https://dev.azure.com/{ORG}/{PROJECT}/_git/{a.name}"
                 + (f"?version=GB{urllib.parse.quote(a.source_branch)}" if a.source_branch and a.source_branch != "(desconocida)" else ""))
    _repo_link = f'<a href="{_html.escape(_repo_url)}" target="_blank" rel="noopener" style="color:#4f46e5">{a.name}</a>'
    src_code = _src(f"Código fuente — repo {_repo_link}, rama <code>{_branch}</code>"
                    + (f" @ <code>{_html.escape(a.source_commit)}</code>" if a.source_commit else ""))
    src_metodos = _src(f"Endpoints y handlers del código (rama <code>{_branch}</code>)")
    src_aws = _src(f"AWS en vivo (cuenta Integration Composition) — DynamoDB <code>{_html.escape(a.aws_table or '-')}</code>, "
                   f"Parameter Store y Secrets Manager, ambiente <code>{a.aws_env or '-'}</code>")
    src_azure = _src(f"Azure DevOps Library en vivo — Variable Group <code>{a.name}-{a.vg_env}</code> + transversales")
    src_libs = _src(f"Azure Artifacts (feed <code>{ARTIFACTS_FEED}</code>, última versión en vivo) ↔ versiones declaradas en el repo (rama <code>{_branch}</code>)")
    src_hex = _src(f"Validador hexagonal (<code>validation-hexagonal-v3.py</code>) sobre el código (rama <code>{_branch}</code>)")
    _et_src_html = _linkify(a.et_source, "ver ET en Wiki") if (a.et_source and "http" in a.et_source) else f"<code>{_html.escape(a.et_source or 'no encontrada')}</code>"
    src_et = _src(f"Especificación Técnica: {_et_src_html} ↔ código del micro")

    html = f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Compliance v5 SB4 — {a.name}</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:20px;background:#f8fafc;color:#1e293b}}
h1{{color:#0f172a}} h2,h3{{color:#334155}} .status{{display:inline-block;padding:4px 16px;border-radius:20px;color:white;font-weight:bold;background:{status_color}}}
.cards{{display:flex;gap:16px;margin:16px 0;flex-wrap:wrap}} .card{{background:white;border-radius:8px;padding:12px 20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.card .n{{font-size:26px;font-weight:bold}} .card .l{{font-size:13px;color:#64748b}}
.tablewrap{{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;margin-bottom:12px;border-radius:8px}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:0}}
th{{background:#1e293b;color:white;padding:8px 12px;text-align:left;font-size:13px;white-space:nowrap}} td{{padding:6px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;vertical-align:top;word-break:break-word}}
.azure-table td:first-child,.azure-table th:first-child{{min-width:200px}} .azure-table td:nth-child(2){{max-width:340px}}
.ts{{color:#64748b;font-size:12px}} code{{background:#eef2ff;padding:1px 5px;border-radius:4px;font-size:12px}}
.tabs{{display:flex;gap:4px;flex-wrap:wrap;margin:18px 0 0}} .tabs button{{border:0;background:#e2e8f0;color:#334155;padding:9px 16px;
border-radius:8px 8px 0 0;cursor:pointer;font-size:14px;font-weight:600}} .tabs button.active{{background:white;color:#0f172a;box-shadow:0 -2px 4px rgba(0,0,0,.05)}}
.panel{{display:none;background:white;border-radius:0 8px 8px 8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.1)}} .panel.active{{display:block}}
.pill{{display:inline-block;background:#64748b;color:white;border-radius:10px;padding:0 7px;font-size:11px;margin-left:5px}}</style></head><body>
<h1>🛡️ Compliance v5 — Ficohsa WebFlux (Spring Boot 4)</h1>
<p>📦 <strong>{_repo_link}</strong> | Clasificación: {a.clasificacion} | Estado migración: <strong>{a.migration_state.upper()}</strong></p>
<p class="ts">🌱 Rama: <code>{_html.escape(a.source_branch or '-')}</code>{(' @ <code>'+_html.escape(a.source_commit)+'</code>') if a.source_commit else ''} | Spring Boot: {a.spring_boot_version} | LOC: {a.lines_of_code} | HU: {a.hu_id or '-'} | Dev: {_html.escape(a.hu_dev or '-')} | Estado: <span class="status">{pct}%</span></p>
<div class="cards">
<div class="card"><div class="n" style="color:#16a34a">{sum(1 for r in a.results if r.compliant is True)}</div><div class="l">CUMPLE</div></div>
<div class="card"><div class="n" style="color:#dc2626">{sum(1 for r in a.results if r.compliant is False)}</div><div class="l">NO CUMPLE</div></div>
<div class="card"><div class="n" style="color:#0284c7">{sum(1 for r in a.results if r.compliant == 'not_found')}</div><div class="l">NO ENCONTRADO</div></div>
<div class="card"><div class="n" style="color:#64748b">{sum(1 for r in a.results if r.compliant is None)}</div><div class="l">N/A</div></div>
<div class="card"><div class="n" style="color:#0284c7">{n_aws_ok}/{len(a.aws_results)}</div><div class="l">AWS OK</div></div>
</div>
<div class="tabs">
<button class="tab-btn active" data-tab="resumen">Criterios MS</button>
<button class="tab-btn" data-tab="metodos">Por método</button>
<button class="tab-btn" data-tab="aws">AWS en vivo<span class="pill">{len(a.aws_results)}</span></button>
<button class="tab-btn" data-tab="azure">Azure / Variable Group<span class="pill">{len(a.variable_group)}</span></button>
<button class="tab-btn" data-tab="libs">Librerías Ficohsa</button>
<button class="tab-btn" data-tab="hex">Hexagonal<span class="pill">{a.hex_errors}e/{a.hex_warnings}w</span></button>
<button class="tab-btn" data-tab="et">Especificación Técnica<span class="pill">{len(a.et_results)}</span></button>
</div>
<div class="panel active" id="resumen"><h3>Criterios a nivel microservicio</h3>{src_code}
<div class="tablewrap"><table><thead><tr><th>Criterio</th><th>Estado</th><th>Detalle</th></tr></thead><tbody>{rows(a.results)}</tbody></table></div></div>
<div class="panel" id="metodos"><h3>Criterios por método</h3>{src_metodos}{method_sections or '<p class="ts">Sin métodos con checks.</p>'}</div>
<div class="panel" id="aws"><h3>Validaciones AWS en vivo</h3>{src_aws}{aws_tab}</div>
<div class="panel" id="azure"><h3>Azure DevOps — Variable Group</h3>{src_azure}{vg_tab}</div>
<div class="panel" id="libs"><h3>Librerías Ficohsa</h3>{src_libs}
<p class="ts">Versión actual = última publicada en Azure Artifacts (feed <code>{ARTIFACTS_FEED}</code> en vivo; fallback al catálogo si no hay acceso). Versión del micro = la declarada en el repo evaluado.</p>
<div class="tablewrap"><table><thead><tr><th>Librería</th><th>Módulo</th><th>Versión actual (feed)</th><th>Versión del micro</th><th>Cumple lineamiento</th></tr></thead><tbody>{libs_rows}</tbody></table></div></div>
<div class="panel" id="hex"><h3>Validación hexagonal — {a.hex_errors} errores, {a.hex_warnings} advertencias</h3>{src_hex}{hex_section}</div>
<div class="panel" id="et"><h3>📄 Especificación Técnica (ET) — {n_et_ok} OK / {n_et_fail} NO CUMPLE</h3>{src_et}{et_tab}</div>
<script>
document.querySelectorAll('.tab-btn').forEach(function(b){{b.addEventListener('click',function(){{
  document.querySelectorAll('.tab-btn').forEach(function(x){{x.classList.remove('active')}});
  document.querySelectorAll('.panel').forEach(function(x){{x.classList.remove('active')}});
  b.classList.add('active'); document.getElementById(b.dataset.tab).classList.add('active');
}})}});
</script>
</body></html>"""
    fp = os.path.join(output_dir, f"{a.name}_compliance.html")
    Path(fp).write_text(html, encoding="utf-8")
    return fp


def _analysis_to_dict(a: MicroAnalysis):
    return {
        "microservicio": a.name, "path": a.path, "clasificacion": a.clasificacion,
        "migration_state": a.migration_state, "spring_boot_version": a.spring_boot_version,
        "lines_of_code": a.lines_of_code, "hu_id": a.hu_id, "hu_title": a.hu_title, "hu_dev": a.hu_dev,
        "source_branch": a.source_branch, "source_commit": a.source_commit,
        "repo_url": f"https://dev.azure.com/{ORG}/{PROJECT}/_git/{a.name}" + (
            f"?version=GB{urllib.parse.quote(a.source_branch)}"
            if a.source_branch and a.source_branch != "(desconocida)" else ""),
        "methods": a.methods, "porcentaje": _analysis_pct(a),
        "hexagonal": {"errors": a.hex_errors, "warnings": a.hex_warnings, "details": a.hex_details},
        "aws": {"env": a.aws_env, "dynamo_table": a.aws_table, "checks": a.aws_results},
        "especificacion_tecnica": {"fuente": a.et_source, "checks": a.et_results},
        "azure_variable_group": a.variable_group,
        "librerias_ficohsa": {"presentes": list(a.ficohsa_libs_present.keys()),
                              "faltantes": list(a.ficohsa_libs_missing.keys())},
        "criterios_micro": [
            {"criterio": r.criterion, "estado": r.status, "cumple": r.compliant,
             "positivos": r.positives, "issues": r.issues, "observacion": r.observation_summary}
            for r in a.results
        ],
        "criterios_por_metodo": {
            method: [{"criterio": r.criterion, "estado": r.status, "cumple": r.compliant,
                      "positivos": r.positives, "issues": r.issues} for r in checks]
            for method, checks in a.method_results.items()
        },
        "catalogo": a.catalog_data,
        "catalogo_api": a.catalog_api_data,
    }


def generate_individual_json_analysis(a: MicroAnalysis, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    fp = os.path.join(output_dir, f"{a.name}_compliance.json")
    Path(fp).write_text(json.dumps(_analysis_to_dict(a), ensure_ascii=False, indent=2), encoding="utf-8")
    return fp


# ── Markdown individual (reporte legible, mismos datos que el JSON) ─────────────

# Etiquetas legibles por nombre interno de criterio (para el reporte markdown).
_CRITERIO_LABEL = {
    "arquetipo": "Arquetipo (estructura SB4)",
    "main_gradle": "main.gradle (estándar)",
    "librerias_ficohsa": "Librerías Ficohsa",
    "jackson3": "Jackson 3",
    "logging": "Logs (webflux-logging)",
    "resilience": "Resilience (@FicohsaResilience)",
    "mappers": "MapStruct Mappers",
    "envelope": "Request Envelope",
    "caller_service": "Caller-Service / @LogExternalCall",
    "regionalizacion": "Regionalización",
    "homologacion": "Homologación",
    "dtos": "DTOs (record)",
    "cobertura": "Cobertura 85%",
    "configmap": "ConfigMap (k8s)",
    "credenciales": "Credenciales gradle",
    "excepciones": "Sin excepciones custom",
    "sizing": "Tallaje (ms-sizing)",
    "vg_cm_alineacion": "Variable Group ↔ cm.yaml",
}
# Criterios considerados CRÍTICOS (alineado con CRITICAL_CRITERIA del pipeline).
_CRITICAL_FOR_MD = CRITICAL_CRITERIA


def _crit_label(name):
    return _CRITERIO_LABEL.get(name, name)


def _clean_et_source(fuente):
    """Limpia la fuente de la ET: 'HU #62715 (https://...)' -> 'HU #62715'."""
    if not fuente:
        return ""
    return re.sub(r"\s*\(https?://.*$", "", fuente).strip()


def generate_individual_markdown(a: MicroAnalysis, output_dir):
    """Genera un reporte .md DETALLADO a partir del mismo dict que alimenta el JSON:
    metadatos, resumen de criterios con criticidad, detalle (positivos + issues) de cada
    criterio, criterios por método, librerías, hexagonal, AWS, ET y Variable Group."""
    os.makedirs(output_dir, exist_ok=True)
    d = _analysis_to_dict(a)
    L = []
    icon = {"CUMPLE": "✅", "NO CUMPLE": "❌", "NO ENCONTRADO": "🔎",
            "PARCIAL": "🟡", "N/A": "➖"}.get
    st_icon = {"ok": "✅", "fail": "❌", "na": "➖", "warn": "🟡"}.get

    hex_ = d.get("hexagonal", {}) or {}
    boot = d.get("spring_boot_version", "") or "-"
    estado_mig = (d.get("migration_state", "") or "").upper() or "-"
    criterios = d.get("criterios_micro", []) or []
    n_fail = sum(1 for c in criterios if c.get("estado") == "NO CUMPLE")
    n_fail_crit = sum(1 for c in criterios
                      if c.get("estado") == "NO CUMPLE" and c.get("criterio") in _CRITICAL_FOR_MD)
    n_nf = sum(1 for c in criterios if c.get("estado") == "NO ENCONTRADO")
    n_ok = sum(1 for c in criterios if c.get("estado") == "CUMPLE")
    et_fuente = _clean_et_source((d.get("especificacion_tecnica") or {}).get("fuente") or "")

    # ── Encabezado ──
    L.append(f"# Reporte de Compliance — `{d.get('microservicio','')}`\n")
    L.append(f"> Generado el {datetime.now().strftime('%Y-%m-%d %H:%M')} · "
             f"pipeline `compliance_pipeline_v5.py` (modo `--single`).\n")
    L.append("| Campo | Valor |")
    L.append("|---|---|")
    L.append(f"| Microservicio | `{d.get('microservicio','')}` |")
    L.append(f"| Clasificación | {d.get('clasificacion','') or '-'} |")
    L.append(f"| Estado migración | {estado_mig} — Spring Boot {boot} |")
    L.append(f"| Rama / Commit | `{d.get('source_branch','') or '-'}` / `{d.get('source_commit','') or '-'}` |")
    L.append(f"| Repositorio | {d.get('repo_url','') or '-'} |")
    L.append(f"| LOC | {d.get('lines_of_code','') or '-'} |")
    hu = d.get("hu_id") or ""
    hu_title = d.get("hu_title") or ""
    hu_cell = (f"#{hu}" + (f" — {hu_title}" if hu_title else "")) if hu else (et_fuente or "-")
    L.append(f"| HU asociada | {hu_cell} |")
    L.append(f"| Desarrollador (HU) | {d.get('hu_dev') or '-'} |")
    L.append(f"| Validación hexagonal | {hex_.get('errors',0)} errores / {hex_.get('warnings',0)} warnings |")
    L.append(f"| **Cumplimiento global** | **{d.get('porcentaje','')} %** |")
    resultado = "FALLÓ" if n_fail else "PASÓ"
    extra = f" ({n_fail} NO CUMPLE, {n_fail_crit} crítico(s))" if n_fail else ""
    L.append(f"| **Resultado** | **{resultado}{extra}** |")
    L.append("")

    # ── Conteo ──
    L.append(f"**Criterios:** {n_ok} CUMPLE · {n_fail} NO CUMPLE · {n_nf} NO ENCONTRADO "
             f"(de {len(criterios)} evaluados).\n")

    # ── Resumen de criterios con criticidad ──
    L.append("## Resumen de criterios (nivel microservicio)\n")
    L.append("| # | Criterio | Crítico | Estado | Observación |")
    L.append("|---|---|:---:|:---:|---|")
    for i, c in enumerate(criterios, 1):
        est = c.get("estado", "")
        crit = "🔴" if c.get("criterio") in _CRITICAL_FOR_MD else ""
        obs = (c.get("observacion") or "").replace("\n", " ").replace("|", "\\|")
        if len(obs) > 160:
            obs = obs[:157] + "…"
        L.append(f"| {i} | {_crit_label(c.get('criterio',''))} | {crit} | {icon(est,'')} {est} | {obs} |")
    L.append("")

    # ── Detalle completo de cada criterio ──
    L.append("## Detalle por criterio\n")
    for c in criterios:
        est = c.get("estado", "")
        crit_tag = " · 🔴 CRÍTICO" if c.get("criterio") in _CRITICAL_FOR_MD else ""
        L.append(f"### {icon(est,'')} {_crit_label(c.get('criterio',''))} — {est}{crit_tag}")
        pos = c.get("positivos") or []
        iss = c.get("issues") or []
        if pos:
            L.append("**Cumple:**")
            for p in pos:
                L.append(f"- {p}")
        if iss:
            L.append("**Hallazgos / acción:**")
            for x in iss:
                L.append(f"- {x}")
        if not pos and not iss:
            L.append("_(sin observaciones)_")
        L.append("")

    # ── Criterios por método ──
    met = d.get("criterios_por_metodo") or {}
    if met:
        L.append("## Criterios por método\n")
        for method, checks in met.items():
            L.append(f"### `{method}`\n")
            L.append("| Criterio | Estado | Detalle |")
            L.append("|---|:---:|---|")
            for ck in checks:
                est = ck.get("estado", "")
                det = " ".join((ck.get("positivos") or []) + (ck.get("issues") or []))
                det = det.replace("\n", " ").replace("|", "\\|")
                L.append(f"| {ck.get('criterio','')} | {icon(est,'')} {est} | {det} |")
            L.append("")

    # ── Librerías Ficohsa ──
    libs = d.get("librerias_ficohsa") or {}
    if libs.get("presentes") or libs.get("faltantes"):
        L.append("## Librerías Ficohsa\n")
        if libs.get("presentes"):
            L.append(f"**Presentes ({len(libs['presentes'])}):** " + ", ".join(f"`{x}`" for x in libs["presentes"]))
        if libs.get("faltantes"):
            L.append(f"\n**No usadas ({len(libs['faltantes'])}):** " + ", ".join(f"`{x}`" for x in libs["faltantes"]))
        L.append("")

    # ── Validación hexagonal (detalle) ──
    details = hex_.get("details") or []
    L.append("## Validación hexagonal\n")
    L.append(f"{hex_.get('errors',0)} errores · {hex_.get('warnings',0)} warnings.\n")
    if details:
        L.append("| Severidad | Regla | Archivo | Mensaje |")
        L.append("|---|---|---|---|")
        for v in details[:50]:
            msg = str(v.get("message", "")).replace("\n", " ").replace("|", "\\|")
            L.append(f"| {v.get('type','')} | {v.get('rule','')} | {v.get('file','')} | {msg} |")
        if len(details) > 50:
            L.append(f"\n_(+{len(details)-50} violaciones adicionales)_")
        L.append("")

    # ── AWS ──
    aws = d.get("aws") or {}
    if aws.get("checks"):
        L.append("## Validaciones AWS\n")
        L.append(f"Ambiente: `{aws.get('env','') or '-'}` · Tabla DynamoDB: `{aws.get('dynamo_table','') or '-'}`\n")
        L.append("| Check | Estado | Detalle |")
        L.append("|---|:---:|---|")
        for ck in aws["checks"]:
            det = str(ck.get("detail", "")).replace("\n", " ").replace("|", "\\|")
            L.append(f"| {ck.get('check','')} | {st_icon(ck.get('status',''),'')} | {det} |")
        L.append("")

    # ── Especificación Técnica (ET) ──
    et = d.get("especificacion_tecnica") or {}
    if et.get("checks"):
        L.append("## Especificación Técnica (ET)\n")
        if et_fuente:
            L.append(f"Fuente: {et_fuente}\n")
        L.append("| Check | Estado | Detalle |")
        L.append("|---|:---:|---|")
        for ck in et["checks"]:
            det = str(ck.get("detail", "")).replace("\n", " ").replace("|", "\\|")
            L.append(f"| {ck.get('check','')} | {st_icon(ck.get('status',''),'')} | {det} |")
        L.append("")

    # ── Variable Group (Azure Library) ──
    vg = d.get("azure_variable_group") or {}
    if vg:
        L.append("## Variable Group (Azure DevOps Library)\n")
        L.append(f"{len(vg)} variables (secretos mostrados como `***SECRET***`).\n")
        L.append("| Variable | Valor |")
        L.append("|---|---|")
        for k in sorted(vg.keys()):
            val = str(vg[k]).replace("\n", " ").replace("|", "\\|")
            if len(val) > 120:
                val = val[:117] + "…"
            L.append(f"| `{k}` | {val} |")
        L.append("")

    L.append("---")
    L.append(f"*Generado desde `{a.name}_compliance.json` · pipeline `compliance_pipeline_v5.py`.*")

    fp = os.path.join(output_dir, f"{a.name}_compliance.md")
    Path(fp).write_text("\n".join(L) + "\n", encoding="utf-8")
    return fp


# ── Excel individual (5 hojas: Resumen, Cumple, No Cumple, Librerías, ET) ───────

def generate_individual_excel(a: MicroAnalysis, output_dir):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        return None
    os.makedirs(output_dir, exist_ok=True)
    wb = Workbook()
    fills = {"CUMPLE": PatternFill("solid", fgColor="DCFCE7"), "NO CUMPLE": PatternFill("solid", fgColor="FEE2E2"),
             "N/A": PatternFill("solid", fgColor="F1F5F9"), "NO ENCONTRADO": PatternFill("solid", fgColor="E0F2FE"),
             "PARCIAL": PatternFill("solid", fgColor="FEF9C3")}
    hfill = PatternFill("solid", fgColor="1E293B")
    hfont = Font(color="FFFFFF", bold=True)

    # Hoja Resumen: matriz criterio x método
    ws = wb.active
    ws.title = "Resumen"
    crit_labels = [_CRIT_LABEL.get(r.criterion, r.criterion) for r in a.results]
    headers = ["Microservicio", "Método/HU"] + crit_labels
    for c, h in enumerate(headers, 1):
        cell = ws.cell(1, c, h); cell.fill = hfill; cell.font = hfont
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    row = 2
    micro_by_crit = {r.criterion: r for r in a.results}
    for method in (a.methods or ["-"]):
        ws.cell(row, 1, a.name)
        ws.cell(row, 2, method)
        for j, r in enumerate(a.results):
            cell = ws.cell(row, 3 + j, r.status)
            cell.fill = fills.get(r.status, fills["N/A"])
        row += 1
    for i, w in enumerate([40, 30] + [16] * len(crit_labels), 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    # Hoja Cumple / No Cumple
    for title, want in (("Cumple", True), ("No Cumple", False)):
        sh = wb.create_sheet(title)
        sh.cell(1, 1, "Criterio").fill = hfill
        sh.cell(1, 1).font = hfont
        sh.cell(1, 2, "Explicación").fill = hfill
        sh.cell(1, 2).font = hfont
        r = 2
        for res in a.results:
            if res.compliant is want:
                sh.cell(r, 1, _CRIT_LABEL.get(res.criterion, res.criterion))
                sh.cell(r, 2, (res.explanation_compliant if want else res.observation_summary))
                r += 1
        sh.column_dimensions["A"].width = 30
        sh.column_dimensions["B"].width = 90

    # Hoja Librerías
    sh = wb.create_sheet("Librerías Ficohsa")
    for c, h in enumerate(["Librería", "Módulo", "Estado"], 1):
        sh.cell(1, c, h).fill = hfill
        sh.cell(1, c).font = hfont
    r = 2
    for key, art in {**a.ficohsa_libs_present, **a.ficohsa_libs_missing}.items():
        sh.cell(r, 1, key)
        sh.cell(r, 2, f"com.ficohsa.lib:{art}")
        sh.cell(r, 3, "presente" if key in a.ficohsa_libs_present else "falta")
        r += 1
    sh.column_dimensions["A"].width = 18
    sh.column_dimensions["B"].width = 40
    sh.column_dimensions["C"].width = 12

    # Hoja Especificación Técnica (ET)
    sh = wb.create_sheet("Especificación Técnica")
    _et_label = {"et_estructura": "Estructura de la ET (plantilla)",
                 "et_caller_service": "Caller-service en la ET (formato)",
                 "et_enmascarado": "Enmascarado en la ET (estándares)",
                 "et_vs_clasificacion": "ET ↔ clasificación del micro",
                 "et_vs_endpoints": "ET ↔ endpoints del código",
                 "et_vs_caller_service": "ET ↔ caller-service del código",
                 "et_vs_enmascarado": "ET ↔ campos cifrados del micro",
                 "et": "Especificación Técnica"}
    _et_status = {"ok": "CUMPLE", "fail": "NO CUMPLE", "na": "N/A", "warn": "PARCIAL"}
    sh.cell(1, 1, f"Fuente ET: {a.et_source or '-'}").font = Font(italic=True, color="475569")
    for c, h in enumerate(["Validación", "Estado", "Detalle"], 1):
        cell = sh.cell(2, c, h); cell.fill = hfill; cell.font = hfont
    r = 3
    for res in (a.et_results or []):
        st = _et_status.get(res.get("status", "na"), res.get("status", "").upper())
        label = _et_label.get(res.get("check", ""), res.get("check", ""))
        det = res.get("detail", "") or ""
        extra = []
        extra += [f"✓ {p}" for p in res.get("positives", [])[:8]]
        extra += [f"✗ {i}" for i in res.get("issues", [])]
        body = det + (("\n" + "\n".join(extra)) if extra else "")
        sh.cell(r, 1, label)
        cell = sh.cell(r, 2, st); cell.fill = fills.get(st, fills["N/A"])
        c3 = sh.cell(r, 3, body); c3.alignment = Alignment(wrap_text=True, vertical="top")
        r += 1
    sh.column_dimensions["A"].width = 34
    sh.column_dimensions["B"].width = 14
    sh.column_dimensions["C"].width = 90

    fp = os.path.join(output_dir, f"{a.name}_compliance.xlsx")
    wb.save(fp)
    return fp


# ── Excel consolidado (5 hojas) — matriz SB4 por micro ─────────────────────────

# Pesos por grupo de criterios SB4 (para la hoja de cumplimiento ponderado)
CRITERION_WEIGHTS = {
    "arquetipo": 15, "librerias_ficohsa": 13, "jackson3": 10, "logging": 12,
    "resilience": 10, "mappers": 8, "envelope": 6, "caller_service": 6,
    "regionalizacion": 5, "cobertura": 8, "configmap": 7,
}
PROD_READY_THRESHOLD = 80
_CONSOLIDATED_CRIT_ORDER = ["arquetipo", "librerias_ficohsa", "jackson3", "logging", "resilience",
                            "mappers", "envelope", "caller_service", "regionalizacion", "dtos",
                            "cobertura", "configmap", "credenciales", "excepciones"]


def generate_consolidated_excel_rich(analyses, output_dir):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.comments import Comment
    except ImportError:
        print("  ⚠️  openpyxl no instalado — se omite el Excel consolidado (pip3 install openpyxl)")
        return None

    os.makedirs(output_dir, exist_ok=True)
    wb = Workbook()
    hfill = PatternFill("solid", fgColor="1E293B")
    hfont = Font(color="FFFFFF", bold=True, size=10)
    fills = {"CUMPLE": PatternFill("solid", fgColor="DCFCE7"), "NO CUMPLE": PatternFill("solid", fgColor="FEE2E2"),
             "N/A": PatternFill("solid", fgColor="F1F5F9"), "NO ENCONTRADO": PatternFill("solid", fgColor="E0F2FE"),
             "PARCIAL": PatternFill("solid", fgColor="FEF9C3")}
    thin = Side(style="thin", color="E2E8F0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    def _hdr(ws, headers):
        for c, h in enumerate(headers, 1):
            cell = ws.cell(1, c, h)
            cell.fill = hfill; cell.font = hfont; cell.border = border
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    crit_labels = [_CRIT_LABEL.get(c, c) for c in _CONSOLIDATED_CRIT_ORDER]

    # SHEET 1 — Matriz Cumplimiento
    ws1 = wb.active
    ws1.title = "Matriz Cumplimiento"
    _hdr(ws1, ["#", "Microservicio", "Clasificación", "Método/HU", "HU ID", "Desarrollador", "Versión SB",
               "LOC", "Estado migración"] + crit_labels + ["% Cumplimiento"])
    row = 2
    for idx, a in enumerate(sorted(analyses, key=lambda x: x.name), 1):
        by_crit = {r.criterion: r for r in a.results}
        pct = _analysis_pct(a)
        for method in (a.methods or ["-"]):
            base = [idx, a.name, a.clasificacion, method, a.hu_id or "-", a.hu_dev or "-",
                    a.spring_boot_version, a.lines_of_code, a.migration_state.upper()]
            for c, v in enumerate(base, 1):
                cell = ws1.cell(row, c, v); cell.border = border
            for j, crit in enumerate(_CONSOLIDATED_CRIT_ORDER):
                r = by_crit.get(crit)
                st = r.status if r else "N/A"
                cell = ws1.cell(row, len(base) + 1 + j, st)
                cell.fill = fills.get(st, fills["N/A"]); cell.border = border
                cell.alignment = Alignment(horizontal="center")
                if r and r.issues:
                    try:
                        cell.comment = Comment(r.observation_summary[:900], "compliance_v5")
                    except Exception:
                        pass
            pcell = ws1.cell(row, len(base) + 1 + len(crit_labels), f"{pct}%")
            pcell.border = border
            row += 1
    ws1.freeze_panes = "E2"
    for i, w in enumerate([5, 40, 14, 30, 8, 28, 12, 8, 14] + [15] * len(crit_labels) + [14], 1):
        ws1.column_dimensions[get_column_letter(i)].width = w

    # SHEET 2 — Observaciones
    ws2 = wb.create_sheet("Observaciones")
    _hdr(ws2, ["#", "Microservicio", "HU ID", "Desarrollador"] + crit_labels)
    row = 2
    for idx, a in enumerate(sorted(analyses, key=lambda x: x.name), 1):
        by_crit = {r.criterion: r for r in a.results}
        ws2.cell(row, 1, idx); ws2.cell(row, 2, a.name); ws2.cell(row, 3, a.hu_id or "-")
        ws2.cell(row, 4, a.hu_dev or "-")
        for j, crit in enumerate(_CONSOLIDATED_CRIT_ORDER):
            r = by_crit.get(crit)
            ws2.cell(row, 5 + j, r.observation_summary if r else "")
        row += 1
    for i, w in enumerate([5, 40, 8, 28] + [40] * len(crit_labels), 1):
        ws2.column_dimensions[get_column_letter(i)].width = w

    # SHEET 3 — Librerías por Micro
    ws3 = wb.create_sheet("Librerías por Micro")
    lib_keys = list(ALL_FICOHSA_LIBS_SB4.keys())
    _hdr(ws3, ["#", "Microservicio"] + lib_keys + ["Total"])
    row = 2
    for idx, a in enumerate(sorted(analyses, key=lambda x: x.name), 1):
        ws3.cell(row, 1, idx); ws3.cell(row, 2, a.name)
        present = 0
        for j, key in enumerate(lib_keys):
            ok = key in a.ficohsa_libs_present
            present += 1 if ok else 0
            cell = ws3.cell(row, 3 + j, "✓" if ok else "✗")
            cell.fill = fills["CUMPLE"] if ok else fills["NO CUMPLE"]
            cell.alignment = Alignment(horizontal="center")
        ws3.cell(row, 3 + len(lib_keys), f"{present}/{len(lib_keys)}")
        row += 1
    for i, w in enumerate([5, 40] + [10] * len(lib_keys) + [8], 1):
        ws3.column_dimensions[get_column_letter(i)].width = w

    # SHEET 4 — Estadísticas por criterio
    ws4 = wb.create_sheet("Estadísticas")
    _hdr(ws4, ["Criterio", "Cumple", "No Cumple", "No Encontrado", "N/A", "% Cumplimiento"])
    row = 2
    for crit in _CONSOLIDATED_CRIT_ORDER:
        c = nc = nf = na = 0
        for a in analyses:
            r = next((x for x in a.results if x.criterion == crit), None)
            if not r:
                na += 1
            elif r.compliant is True:
                c += 1
            elif r.compliant is False:
                nc += 1
            elif r.compliant == "not_found":
                nf += 1
            else:
                na += 1
        pct = round(c / (c + nc) * 100, 1) if (c + nc) else 0
        ws4.cell(row, 1, _CRIT_LABEL.get(crit, crit))
        for k, v in enumerate([c, nc, nf, na, f"{pct}%"], 2):
            ws4.cell(row, k, v)
        row += 1
    for i, w in enumerate([32, 10, 12, 15, 8, 16], 1):
        ws4.column_dimensions[get_column_letter(i)].width = w

    # SHEET 5 — Cumplimiento ponderado + estado producción
    ws5 = wb.create_sheet("Cumplimiento")
    weight_labels = [f"{_CRIT_LABEL.get(c, c)} ({w}%)" for c, w in CRITERION_WEIGHTS.items()]
    _hdr(ws5, ["#", "Microservicio", "Clasificación", "Estado migración"] + weight_labels +
         ["% Ponderado", "Estado Producción"])
    row = 2
    for idx, a in enumerate(sorted(analyses, key=lambda x: x.name), 1):
        by_crit = {r.criterion: r for r in a.results}
        earned = applicable = 0
        ws5.cell(row, 1, idx); ws5.cell(row, 2, a.name)
        ws5.cell(row, 3, a.clasificacion); ws5.cell(row, 4, a.migration_state.upper())
        for j, (crit, weight) in enumerate(CRITERION_WEIGHTS.items()):
            r = by_crit.get(crit)
            st = r.status if r else "N/A"
            cell = ws5.cell(row, 5 + j, st)
            cell.fill = fills.get(st, fills["N/A"]); cell.border = border
            cell.alignment = Alignment(horizontal="center")
            if st in ("CUMPLE", "NO CUMPLE"):
                applicable += weight
                if st == "CUMPLE":
                    earned += weight
        pct = round(earned / applicable * 100, 1) if applicable else 0
        if not a.path:
            prod = "NO IMPLEMENTADO (sin código)"
        elif a.migration_state == "sb3":
            prod = "PENDIENTE MIGRACIÓN SB4"
        elif pct >= PROD_READY_THRESHOLD:
            prod = "LISTO para producción"
        elif pct >= 60:
            prod = "PARCIALMENTE LISTO"
        else:
            prod = "NO LISTO"
        pc = ws5.cell(row, 5 + len(weight_labels), f"{pct}%"); pc.border = border
        sc = ws5.cell(row, 6 + len(weight_labels), prod); sc.border = border
        row += 1
    ws5.freeze_panes = "C2"
    for i, w in enumerate([5, 40, 14, 14] + [16] * len(weight_labels) + [12, 26], 1):
        ws5.column_dimensions[get_column_letter(i)].width = w

    ts = datetime.now(timezone(timedelta(hours=-6))).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"compliance_consolidado_SB4_{ts}.xlsx")
    wb.save(path)
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_et_content(args, ms_data):
    """Obtiene el contenido Markdown de la ET del micro, en orden de prioridad:
      1) --et <ruta.md>  (archivo local).
      2) --et-url <url>  (página de Wiki de Azure).
      3) autodescubierta: primer et_link de las HUs del micro (fetch_wiki_page).
    Retorna (contenido, origen) o ("", motivo)."""
    # 1) archivo local
    et_path = getattr(args, "et", None)
    if et_path:
        p = Path(et_path)
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace"), f"archivo {p.name}"
        return "", f"no existe el archivo ET: {et_path}"
    # 2) URL explícita
    et_url = getattr(args, "et_url", None)
    if et_url:
        c = fetch_wiki_page(et_url)
        if c:
            return c, f"URL {et_url[:60]}"
        return "", f"no se pudo traer la ET de la URL: {et_url}"
    # 3) autodescubierta desde las HUs del micro
    for hu in ms_data.get("hus", []):
        for link in hu.get("et_links", []):
            c = fetch_wiki_page(link)
            if c:
                return c, f"HU #{hu.get('id','?')} ({link[:50]})"
    return "", "sin ET (ni --et, ni --et-url, ni et_links en las HUs del micro)"


def _run_et_validation(a, args, ms_data):
    """Resuelve la ET y ejecuta run_et_checks, guardando el resultado en el análisis."""
    try:
        from et_checks import run_et_checks
    except Exception as e:
        a.et_results = [{"check": "et", "status": "na",
                         "detail": f"módulo et_checks no disponible: {e}",
                         "positives": [], "issues": []}]
        return
    content, source = _resolve_et_content(args, ms_data)
    a.et_source = source
    if not content:
        a.et_results = [{"check": "et", "status": "na", "detail": source,
                         "positives": [], "issues": []}]
        print(f"📄  ET: {source}")
        return
    print(f"📄  ET encontrada ({source}); validando contra el código…")
    a.et_results = run_et_checks(content, str(a.path), a.name)


def _run_single(args):
    repo_root = Path(args.single)
    if not repo_root.exists():
        print(f"ERROR: la ruta no existe: {repo_root}", file=sys.stderr)
        sys.exit(1)
    repo_name = repo_root.resolve().name

    # ── Ambiente en vivo: derivado de la RAMA del micro (no se pasa a mano) ──────
    # develop→dev, staging→stg, uat→uat, main/master→prd.
    from aws_checks import env_from_branch, resolve_dynamo_table, run_aws_checks
    branch = detect_repo_branch(str(repo_root))
    derived = env_from_branch(branch)
    if getattr(args, "env", None):
        # --env explícito tiene prioridad sobre la derivación por rama.
        env = args.env
        if derived and derived != env:
            print(f"🌱  Rama: {branch} (→{derived}) pero se fuerza --env={env}.")
        else:
            print(f"🌱  Ambiente forzado por --env={env} (rama: {branch or '(desprendida)'}).")
    elif derived:
        env = derived
        print(f"🌱  Rama: {branch}  →  ambiente: {env}")
    else:
        # Ramas de trabajo (feature/*, bugfix/*, etc.) o no reconocidas: se validan
        # contra 'dev' por defecto (es donde se prueba el desarrollo). Se avisa para
        # que el usuario pueda forzar otro ambiente con --env si lo necesita.
        env = "dev"
        print(f"🌱  Rama '{branch or '(desprendida)'}' no mapea a un ambiente conocido "
              f"(develop→dev, staging→stg, uat→uat, main→prd); uso ambiente por defecto: dev.\n"
              f"    Si necesitas otro ambiente, pásalo con --env <dev|stg|uat|prd>.",
              file=sys.stderr)

    # ── Ambiente de INFRAESTRUCTURA (Azure VG + AWS Param/Secrets/DynamoDB) ──────
    # Regla (Frank Camilo): si la rama es staging/uat/main(prd), la infra se valida en
    # SU ambiente; para CUALQUIER otra rama (develop, feature/*, feat/*, atx-*, etc.) la
    # infra se valida contra DEV (-dev). Las validaciones estáticas (código) no dependen
    # del ambiente y se dan sobre la rama tal cual. Como 'env' ya se derivó así arriba
    # (staging→stg, uat→uat, main→prd, resto→dev), el VG usa EXACTAMENTE ese mismo env.
    # Sobreescribible con --env. (VG_ENV queda como fallback si no hubiese env.)
    infra_env = env or VG_ENV

    # ── SIEMPRE EN VIVO: refrescar el Variable Group desde Azure DevOps Library ──
    # No se usa caché para el tallaje/VG; si falta el PAT, api_call aborta con guía.
    print(f"🔄  Consultando Variable Group '{repo_name}-{infra_env}' en Azure DevOps Library…")
    vg_live = fetch_variable_group_live(repo_name, infra_env)
    # VG transversales (urls/paths internos) del mismo ambiente de infraestructura —
    # se usan para resolver placeholders del cm.yaml, NO se muestran en el reporte.
    transversal_vars = fetch_transversal_variable_groups(infra_env)
    if transversal_vars:
        print(f"🔗  VG transversales: {len(transversal_vars)} variables (urls/paths internos, {infra_env}).")
    if vg_live is None:
        print(f"⚠️  No se encontró el Variable Group '{repo_name}-{infra_env}' en Azure "
              f"(o no hay acceso). El criterio de Tallaje quedará como NO ENCONTRADO.",
              file=sys.stderr)
    else:
        print(f"✅  Variable Group en vivo: {len(vg_live['variables'])} variables.")

    # Enriquecer con HU del mapping (si existe), pero el VG SIEMPRE es el de en vivo:
    # nunca se usa el Variable Group cacheado (evita falsos positivos por caché viejo).
    ms_data = dict(_load_mapping().get(repo_name, {}))
    ms_data.pop("variable_group", None)  # descarta cualquier VG cacheado
    if vg_live is not None:
        ms_data["variable_group"] = vg_live
    # HUs + ET/EF EN VIVO (equivalente pasos 2A+3 del pipeline, acotado a este micro):
    # busca las User Stories por Custom.Repo y descarga el contenido de ET/EF.
    if not getattr(args, "no_etef", False):
        print(f"📥  Buscando HUs y descargando ET/EF de '{repo_name}' en Azure Boards…")
        hus_live = fetch_hus_for_micro(repo_name, download_docs=True)
        if hus_live:
            ms_data["hus"] = hus_live   # reemplaza el caché por lo descargado en vivo
    # --hu: fuerza la(s) HU(s) del reporte (p. ej. HUs sin Custom.Repo poblado).
    if getattr(args, "hu", None):
        forced = fetch_hus_by_ids(args.hu)
        if forced:
            print("📌  HU forzada por --hu: " + ", ".join(
                f"#{h['id']} (dev: {h.get('developer') or '-'})" for h in forced))
            ms_data["hus"] = forced
        else:
            print(f"⚠️  No se pudo descargar la HU indicada en --hu: {args.hu}", file=sys.stderr)
    ms_data["transversal_vars"] = transversal_vars   # para el check VG↔cm.yaml (no se muestra)
    ms_data["vg_env"] = infra_env                       # ambiente de infra del VG (staging/uat/prd o dev)

    # Análisis rico (métodos, HU/ET/EF, hexagonal, por-método)
    a = analyze_microservice(str(repo_root), ms_data)
    _enrich_with_catalogs([a])

    # Trazabilidad del código fuente: rama + commit analizados.
    a.source_branch = branch or "(desconocida)"
    try:
        _rc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_root),
                             capture_output=True, text=True, timeout=10)
        a.source_commit = _rc.stdout.strip() if _rc.returncode == 0 else ""
    except Exception:
        a.source_commit = ""

    # ── Validación de la Especificación Técnica (ET) ────────────────────────────
    # Resuelve la ET en orden: --et <ruta> → --et-url <url> → autodescubierta de los
    # et_links de las HUs del micro (mismo mecanismo que el pipeline completo).
    _run_et_validation(a, args, ms_data)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Validaciones externas AWS: SIEMPRE EN VIVO (env derivado de la rama) ─────
    # Se corren ANTES de generar los reportes para que el HTML/JSON incluyan la
    # pestaña AWS. Parameter Store + Secrets Manager + DynamoDB. --no-aws las salta.
    if not getattr(args, "no_aws", False):
        table = resolve_dynamo_table(env, getattr(args, "dynamo_table", None))
        a.aws_env = env
        a.aws_table = table
        print(f"\n{'─'*66}\n  VALIDACIONES AWS EN VIVO (env={env}, tabla={table})\n{'─'*66}")
        icon = {"ok": "✅", "fail": "❌", "na": "➖", "no_creds": "🔑", "error": "⚠️ "}
        try:
            for r in run_aws_checks(str(repo_root), repo_name, env, table):
                a.aws_results.append(r)   # <-- se guarda para el reporte
                print(f"{icon.get(r['status'],'•')}  {r['check']}: {r['status'].upper()}"
                      + (f" — {r['detail']}" if r.get('detail') else ""))
                for p in r.get("positives", []):
                    print(f"      ✓ {p}")
                for i in r.get("issues", []):
                    print(f"      ✗ {i}")
        except Exception as e:
            print(f"⚠️  Validaciones AWS omitidas: {e}")
        # Consolida los AWS checks en UN criterio que SÍ suma a los totales/tarjetas.
        _aws_fail = [r for r in a.aws_results if r.get("status") in ("fail", "error")]
        if a.aws_results:
            if _aws_fail:
                a.results.append(ComplianceResult(
                    "aws_recursos", False,
                    [f"{r['check']}: {r['status']}" for r in a.aws_results if r.get("status") == "ok"],
                    [f"{r['check']}: {r.get('detail') or r['status']}" for r in _aws_fail]))
            else:
                a.results.append(ComplianceResult(
                    "aws_recursos", True,
                    [f"{r['check']}: {r['status']}" for r in a.aws_results], []))

    # ── Generación de reportes (ya con AWS + Variable Group en el análisis) ──────
    if args.format in ("console", "all"):
        _print_analysis_console(a)
    if args.format in ("json", "all"):
        print(f"📝  JSON: {generate_individual_json_analysis(a, str(output_dir))}")
    if args.format in ("html", "all"):
        print(f"🌐  HTML: {generate_individual_html_analysis(a, str(output_dir))}")
    if args.format in ("markdown", "all"):
        print(f"📝  Markdown: {generate_individual_markdown(a, str(output_dir))}")
    if args.format in ("excel", "all"):
        xlsx = generate_individual_excel(a, str(output_dir))
        print(f"📊  Excel: {xlsx}" if xlsx else "📊  Excel omitido (instala openpyxl)")

    if args.fail_on_critical and a.critical_failures:
        sys.exit(1)


def _print_analysis_console(a: MicroAnalysis):
    icon = {"CUMPLE": "✅", "NO CUMPLE": "❌", "N/A": "➖", "NO ENCONTRADO": "🔎", "PARCIAL": "⚠️ "}
    print(f"\n{'═'*66}")
    print(f"  Compliance v5 SB4 : {a.name}  ({a.clasificacion})")
    print(f"  Estado migración  : {a.migration_state.upper()}  |  Spring Boot: {a.spring_boot_version}  |  LOC: {a.lines_of_code}")
    print(f"  HU: {a.hu_id or '-'}  |  Dev: {a.hu_dev or '-'}  |  Hexagonal: {a.hex_errors} err / {a.hex_warnings} warn  |  Cumplimiento: {_analysis_pct(a)}%")
    print(f"{'═'*66}\n  CRITERIOS A NIVEL MICROSERVICIO")
    for r in a.results:
        label = _CRIT_LABEL.get(r.criterion, r.criterion)
        print(f"\n{icon.get(r.status,'•')}  {label}: {r.status}")
        for p in r.positives:
            print(f"      ✓ {p}")
        if r.issues:
            print(f"    → {r.observation_summary}")
    if a.method_results:
        print(f"\n{'─'*66}\n  CRITERIOS POR MÉTODO")
        for method, checks in a.method_results.items():
            print(f"\n  🔗 {method}")
            for r in checks:
                print(f"     {icon.get(r.status,'•')} {r.criterion}: {r.status}"
                      + (f" — {r.observation_summary}" if r.issues else ""))
    crit = a.critical_failures
    print(f"\n{'═'*66}\nRESULTADO: {'APROBÓ' if not crit else 'FALLÓ'} ({len(crit)} críticos fallidos)\n{'═'*66}\n")


def _run_pipeline(args):
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║   PIPELINE DE COMPLIANCE v5 — FICOHSA MICROSERVICIOS (Spring Boot 4)  ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"  Base dir : {BASE_DIR}")
    print(f"  Output   : {OUTPUT_DIR}")
    start = time.time()

    # PASO 1: clone
    if not args.skip_clone and not args.only_excel:
        step1_clone_repos()
    else:
        print("\n  [SKIP] Paso 1: usando repos ya clonados")
        if not args.only_excel:
            all_dirs = sorted(glob.glob(os.path.join(BASE_DIR, "ms-*")))
            ok = sum(1 for d in all_dirs if os.path.isdir(d) and switch_to_staging(d))
            print(f"  {ok}/{len(all_dirs)} en staging")

    # PASO 2: JSON mapping
    if not args.skip_json and not args.only_excel:
        mapping = step2_build_json()
    else:
        print("\n  [SKIP] Paso 2: cargando JSON existente")
        mapping = _load_mapping()
        print(f"  Microservicios en JSON: {len(mapping)}")

    # PASO 3: ET/EF
    if not args.skip_etef and not args.only_excel:
        step3_download_etef(mapping)
    else:
        print("\n  [SKIP] Paso 3: ET/EF no descargados")

    # PASO 4: analizar (análisis rico: métodos, HU/ET/EF, hexagonal, catálogos)
    analyses = step4_analyze(mapping)

    # PASO 5: reportes
    if args.only_excel or args.no_individual:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        consolidated = generate_consolidated_excel_rich(analyses, OUTPUT_DIR)
        if consolidated:
            print(f"\n  ✓ CONSOLIDADO (Excel, 5 hojas): {consolidated}")
    else:
        fmt = args.format if args.format in ("json", "html", "excel") else "html"
        step5_generate_reports(analyses, fmt)

    elapsed = time.time() - start
    print(f"\n{'═' * 70}")
    print(f"  PIPELINE COMPLETADO en {elapsed/60:.1f} min | Micros: {len(analyses)} | Output: {OUTPUT_DIR}")
    print(f"{'═' * 70}")


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline de Compliance v5 — Microservicios Ficohsa (Spring Boot 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modos:
  1) Un solo micro (SIEMPRE EN VIVO: Azure Library + AWS PS/Secrets/DynamoDB):
       python3 compliance_pipeline_v5.py --single /ruta/al/micro
       python3 compliance_pipeline_v5.py --single /ruta/al/micro --format html --output /tmp
     - El AMBIENTE se deriva de la rama git (develop→dev, staging→stg, uat→uat, main→prd).
       Ramas de trabajo (feature/*, etc.) o no reconocidas usan 'dev' por defecto; --env lo fuerza.
     - El Variable Group se consulta en vivo en Azure Library (requiere AZURE_DEVOPS_PAT).
     - Las validaciones AWS corren siempre (requieren 'aws sso login'); usa --no-aws para saltarlas.
     - Tabla DynamoDB por defecto: ban-xrs-ic-ddb-support-get-params-{env}.
     Requisitos:  export AZURE_DEVOPS_PAT="<pat>"   y   aws sso login --profile <perfil-del-dominio>

  2) Pipeline completo (clone + HUs/VG + ET/EF + Excel consolidado):
       export AZURE_DEVOPS_PAT="<tu-pat>"
       python3 compliance_pipeline_v5.py --pipeline
       python3 compliance_pipeline_v5.py --pipeline --skip-clone --skip-json
       python3 compliance_pipeline_v5.py --pipeline --only-excel

Variables de entorno (pipeline):
  AZURE_DEVOPS_PAT      (obligatorio en --pipeline) Personal Access Token
  AZURE_DEVOPS_ORG      (default: DevopsFicohsa)
  AZURE_DEVOPS_PROJECT  (default: NOVA ... Capa Integración, url-encoded)
  MS_REPOS_DIR          (default: ~/Downloads/ms-repos)
        """)
    parser.add_argument("--single", metavar="PATH", help="Analiza un solo micro local (no requiere PAT)")
    parser.add_argument("--pipeline", action="store_true",
                        help="Ejecuta el flujo completo (clone masivo + HUs/VG + ET/EF + Excel)")
    parser.add_argument("--format", choices=["console", "json", "html", "markdown", "excel", "all"], default="console",
                        help="Formato de reporte (single: console/json/html/markdown/excel/all; pipeline: json/html/excel)")
    parser.add_argument("--output", default=".", help="Directorio de salida (modo --single)")
    parser.add_argument("--fail-on-critical", action="store_true",
                        help="Exit code 1 si algún criterio crítico NO CUMPLE (modo --single)")
    parser.add_argument("--no-aws", action="store_true",
                        help="[single] Desactiva las validaciones AWS en vivo (por defecto SÍ se ejecutan)")
    parser.add_argument("--no-etef", action="store_true",
                        help="[single] No busca HUs ni descarga ET/EF en vivo desde Azure Boards")
    parser.add_argument("--aws-checks", action="store_true",
                        help="[single] (obsoleto) las validaciones AWS ya corren siempre; se mantiene por compatibilidad")
    parser.add_argument("--env", default=None, choices=["dev", "stg", "uat", "prd"],
                        help="Fuerza el ambiente AWS (por defecto se DERIVA de la rama git del micro)")
    parser.add_argument("--dynamo-table", default=None,
                        help="[single] nombre exacto de la tabla DynamoDB (por defecto ban-xrs-ic-ddb-support-get-params-{env})")
    parser.add_argument("--et", default=None, metavar="PATH",
                        help="[single] ruta local a la ET (.md). Si se omite, se usa --et-url o los et_links de las HUs")
    parser.add_argument("--hu", default=None, type=int, nargs="+", metavar="ID",
                        help="[single] ID(s) de HU a usar en el reporte (si se omite, se buscan por Custom.Repo)")
    parser.add_argument("--et-url", default=None, metavar="URL",
                        help="[single] URL de la página de Wiki de Azure con la ET")
    # Flags del pipeline
    parser.add_argument("--skip-clone", action="store_true", help="[pipeline] usa repos ya clonados")
    parser.add_argument("--skip-json", action="store_true", help="[pipeline] usa el JSON existente")
    parser.add_argument("--skip-etef", action="store_true", help="[pipeline] no descarga ET/EF")
    parser.add_argument("--only-excel", action="store_true", help="[pipeline] solo regenera el Excel consolidado")
    parser.add_argument("--no-individual", action="store_true", help="[pipeline] solo consolidado, sin individuales")
    args = parser.parse_args()

    if args.single:
        _run_single(args)
    elif args.pipeline:
        _run_pipeline(args)
    else:
        parser.error("indica --single <ruta> (un micro) o --pipeline (flujo completo)")


if __name__ == "__main__":
    main()
