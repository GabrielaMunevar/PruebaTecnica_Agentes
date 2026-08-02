from copy import deepcopy

from src.adapters import row_to_vulnerability_case


def build_valid_sql_row() -> dict:
    """
    Simula una fila anonimizada de la vista SQL.
    """

    return {
        "VULNERABILITIES_ID": "DEMO-SQL-91721",
        "HOST_ID": 444,
        "IP_CD": "10.0.10.25",
        "DNS_DS": "srv-sql-demo-01",
        "NET_BIOS_DS": "SQLDEMO01",
        "PRODUCT_DS": "Microsoft SQL Server",
        "ENVIRONMENT_DS": "Producción",
        "CONDITION_DS": "Vigente",
        "HOST_GROUP_DS": "Soporte Windows",

        "OS_ID": 9,
        "OS_DS": (
            "Windows Server 2012 R2 "
            "Standard 64 bit Edition"
        ),

        "QID_ID": 8050,
        "QID_CD": "91721",
        "TITLE_DS": (
            "Microsoft SQL Server Elevation "
            "of Privilege Vulnerability"
        ),
        "THREAT_DS": (
            "An authenticated attacker may exploit "
            "the affected SQL Server."
        ),
        "IMPACT_DS": (
            "Successful exploitation may allow "
            "elevation of privilege."
        ),
        "SOLUTION_DS": (
            "Evaluate and install the security update "
            "recommended by the vendor."
        ),

        "CVE_CD": "CVE-2021-1636,CVE-2021-1636",
        "VENDOR_REFERENCE": "Microsoft Security Update",
        "BUGTRAQ_ID": None,
        "EXPLOITABILITY": "Functional exploit not verified",
        "ASSOCIATED_MALWARE": None,
        "PCI_VULN": "YES",

        "DETECTION_TYPE_ID": 2,
        "DETECTION_TYPE_DS": "QAGENT",

        "PORT_ID": 1067,
        "PORT_CD": "NA",
        "PROTOCOL_DS": "NA",

        "RISK_ID": 4,
        "RISK_CD": "4",
        "CVSS_DS": "Alto",

        "RESULT_DS": None,

        "FIRST_DT": "2025-08-11T14:15:00",
        "LAST_DT": "2026-06-04T19:03:00",
        "REOFFENDING_FLG": 1,
        "TIMES_DETECTED": 4111,

        "CURRENT_MANAGEMENT_DS": "ND",
        "CURRENT_GROUP_DS": "ND",
        "CURRENT_OBSERVATION_DS": "ND",

        "INSERT_DT": "2026-06-30T15:59:00",
        "INSERT_USER": "usrVULNS",

        "REQUIRED_REFERENCES_OK_FLG": 1,
        "HAS_INTERNAL_GROUP_FLG": 1,
        "HAS_QID_DETAIL_FLG": 1,
        "HAS_VENDOR_INFORMATION_FLG": 1,
        "HAS_CVE_DETAIL_FLG": 1,
    }


def test_valid_row_becomes_ready_for_ai() -> None:
    sql_row = build_valid_sql_row()

    case = row_to_vulnerability_case(sql_row)

    assert case.vulnerability_id == "DEMO-SQL-91721"

    assert case.asset.internal_group == "Soporte Windows"
    assert case.asset.environment == "Producción"

    assert case.vulnerability.qid == "91721"

    # El CVE repetido debe quedar una sola vez.
    assert case.vulnerability.cves == [
        "CVE-2021-1636",
    ]

    # NA se normaliza como ausencia de información.
    assert case.technical.port is None
    assert case.technical.protocol is None

    # ND se normaliza como ausencia de información.
    assert case.current_management_ds is None
    assert case.current_group_ds is None
    assert case.current_observation_ds is None

    assert case.detection.reoffending is True
    assert case.initial_status == "READY_FOR_AI"


def test_row_without_host_group_goes_to_data_quality_review() -> None:
    sql_row = deepcopy(build_valid_sql_row())

    sql_row["HOST_GROUP_DS"] = "ND"
    sql_row["HAS_INTERNAL_GROUP_FLG"] = 0

    case = row_to_vulnerability_case(sql_row)

    assert case.asset.internal_group is None

    assert (
        case.initial_status
        == "DATA_QUALITY_REVIEW"
    )