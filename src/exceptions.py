class ApplicationError(Exception):
    """Error base controlado de la aplicación."""


class ConfigurationError(ApplicationError):
    """La configuración de la aplicación es inválida o incompleta."""


class AdapterError(ApplicationError):
    """Una fuente externa no pudo convertirse al modelo interno."""


class CatalogError(ApplicationError):
    """El catálogo de respuestas no pudo cargarse o validarse."""


class DataQualityError(ApplicationError):
    """El caso no tiene la calidad mínima necesaria para continuar."""


class PolicyValidationError(ApplicationError):
    """Una propuesta incumple una política determinista."""


class AgentExecutionError(ApplicationError):
    """Ocurrió un error durante la ejecución de un agente."""


class StructuredOutputError(AgentExecutionError):
    """La respuesta del modelo no cumple el esquema esperado."""