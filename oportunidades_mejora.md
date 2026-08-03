# Oportunidades de mejora

Las siguientes mejoras fueron identificadas durante las pruebas con
modelos reales, pero están fuera del alcance del MVP de la prueba técnica.

## Evidencia estructurada

Actualmente el agente registra la evidencia utilizada como texto.
Una evolución permitiría asociar cada evidencia directamente con un
campo de `VulnerabilityCase`, facilitando la verificación automática
de su origen.

## Fuentes externas verificables

El sistema podría incorporar herramientas para consultar fuentes
oficiales del fabricante, bases CVE o inventarios internos antes de
afirmar compatibilidad, aplicabilidad o fechas de fin de soporte.

## Guardrails técnicos adicionales

Podrían agregarse reglas deterministas para exigir un nuevo escaneo,
validar referencias al QID y detectar supuestos técnicos que requieren
confirmación humana.

## Human in the loop

Una interfaz permitiría que un especialista apruebe, modifique o rechace
las propuestas con estado `HUMAN_REVIEW` antes de persistirlas.

## Persistencia y trazabilidad

Una tabla dedicada podría conservar el plan completo, resultados de
auditoría, intentos, tiempos, modelo utilizado y decisiones humanas.

## Observabilidad y costos

En un entorno productivo se podrían registrar tokens, costos, latencia,
errores por agente y métricas de aprobación o corrección.

## Evaluación de calidad

Se podría construir un conjunto de casos evaluados por especialistas
para medir precisión de clasificación, calidad del plan y consistencia
del auditor.