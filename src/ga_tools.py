"""
Google Analytics 4 tool implementations.
All tools accept a Credentials object and return structured dicts.
"""

from typing import Any, Optional
from google.oauth2.credentials import Credentials

# ─── Data API (read) ──────────────────────────────────────────────────────────

def run_report(
    credentials: Credentials,
    property_id: str,
    dimensions: list[str],
    metrics: list[str],
    date_ranges: list[dict],
    dimension_filter: Optional[dict] = None,
    limit: int = 10,
) -> dict[str, Any]:
    """
    Run a GA4 Data API report.

    Args:
        property_id: GA4 property ID (e.g. "123456789")
        dimensions: list of dimension names e.g. ["pagePath", "sessionSource"]
        metrics: list of metric names e.g. ["sessions", "conversions"]
        date_ranges: list of {"start_date": "7daysAgo", "end_date": "today"}
        dimension_filter: optional filter expression dict
        limit: max rows to return (default 10)

    Returns:
        dict with headers and rows
    """
    from google.analytics.data_v1beta import BetaAnalyticsDataClient
    from google.analytics.data_v1beta.types import (
        RunReportRequest,
        Dimension,
        Metric,
        DateRange,
        FilterExpression,
    )
    import json

    client = BetaAnalyticsDataClient(credentials=credentials)

    request = RunReportRequest(
        property=f"properties/{property_id}",
        dimensions=[Dimension(name=d) for d in dimensions],
        metrics=[Metric(name=m) for m in metrics],
        date_ranges=[DateRange(**dr) for dr in date_ranges],
        limit=limit,
    )

    if dimension_filter:
        request.dimension_filter = FilterExpression(
            **_build_filter(dimension_filter)
        )

    response = client.run_report(request)

    headers = {
        "dimensions": [dh.name for dh in response.dimension_headers],
        "metrics": [mh.name for mh in response.metric_headers],
    }
    rows = []
    for row in response.rows:
        rows.append({
            "dimensions": [dv.value for dv in row.dimension_values],
            "metrics": [mv.value for mv in row.metric_values],
        })

    return {
        "row_count": response.row_count,
        "headers": headers,
        "rows": rows,
        "metadata": {
            "currency_code": response.metadata.currency_code if response.metadata else None,
            "time_zone": response.metadata.time_zone if response.metadata else None,
        },
    }


def _build_filter(f: dict) -> dict:
    """Pass-through for filter expressions — users supply the raw dict."""
    return f


# ─── Admin API (read) ─────────────────────────────────────────────────────────

def get_account_summaries(credentials: Credentials) -> dict[str, Any]:
    """
    List all GA4 accounts and properties the user has access to.
    """
    from google.analytics.admin_v1alpha import AnalyticsAdminServiceClient

    client = AnalyticsAdminServiceClient(credentials=credentials)
    results = []

    for summary in client.list_account_summaries():
        account = {
            "account": summary.account,
            "display_name": summary.display_name,
            "properties": [],
        }
        for prop in summary.property_summaries:
            account["properties"].append({
                "property": prop.property,
                "display_name": prop.display_name,
                "property_type": prop.property_type.name,
                "parent": prop.parent,
            })
        results.append(account)

    return {"accounts": results, "count": len(results)}


# ─── Admin API (write) ────────────────────────────────────────────────────────

def add_referral_exclusion(
    credentials: Credentials,
    property_id: str,
    domain: str,
) -> dict[str, Any]:
    """
    Add a referral exclusion (e.g. "paypal.com") to a GA4 property.

    Args:
        property_id: GA4 property ID (numeric, e.g. "123456789")
        domain: domain to exclude, e.g. "paypal.com"
    """
    from google.analytics.admin_v1alpha import AnalyticsAdminServiceClient
    from google.analytics.admin_v1alpha.types import (
        CreateReferralExclusionRequest,
        ReferralExclusion,
    )

    client = AnalyticsAdminServiceClient(credentials=credentials)

    exclusion = ReferralExclusion(condition=domain)
    response = client.create_referral_exclusion(
        parent=f"properties/{property_id}",
        referral_exclusion=exclusion,
    )

    return {
        "success": True,
        "name": response.name,
        "condition": response.condition,
        "message": f"Referral exclusion for '{domain}' created on property {property_id}",
    }


def create_conversion_event(
    credentials: Credentials,
    property_id: str,
    event_name: str,
) -> dict[str, Any]:
    """
    Mark a GA4 event as a conversion event.

    Args:
        property_id: GA4 property ID
        event_name: name of the event to mark as conversion (e.g. "purchase", "form_submit")
    """
    from google.analytics.admin_v1alpha import AnalyticsAdminServiceClient
    from google.analytics.admin_v1alpha.types import ConversionEvent

    client = AnalyticsAdminServiceClient(credentials=credentials)

    conversion = ConversionEvent(event_name=event_name)
    response = client.create_conversion_event(
        parent=f"properties/{property_id}",
        conversion_event=conversion,
    )

    return {
        "success": True,
        "name": response.name,
        "event_name": response.event_name,
        "is_deletable": response.deletable,
        "counting_method": response.counting_method.name if response.counting_method else None,
        "message": f"Conversion event '{event_name}' created on property {property_id}",
    }


def create_audience(
    credentials: Credentials,
    property_id: str,
    display_name: str,
    description: str,
    membership_duration_days: int,
    filter_clauses: list[dict],
) -> dict[str, Any]:
    """
    Create a GA4 Audience.

    Args:
        property_id: GA4 property ID
        display_name: audience name shown in GA4
        description: audience description
        membership_duration_days: how long users stay in audience (1-540)
        filter_clauses: list of audience filter clause dicts
            Example: [{"clauseType": "INCLUDE", "simpleFilter": {...}}]

    Returns:
        dict with created audience details
    """
    from google.analytics.admin_v1alpha import AnalyticsAdminServiceClient
    from google.analytics.admin_v1alpha.types import (
        Audience,
        AudienceFilterClause,
        AudienceSimpleFilter,
        AudienceFilterExpression,
        AudienceDimensionOrMetricFilter,
        AudienceFilterScope,
    )
    from google.protobuf import json_format
    import json

    client = AnalyticsAdminServiceClient(credentials=credentials)

    # Build audience from dict — accept raw proto-compatible dicts
    audience_dict = {
        "display_name": display_name,
        "description": description,
        "membership_duration_days": membership_duration_days,
        "filter_clauses": filter_clauses,
    }

    audience = json_format.ParseDict(audience_dict, Audience())
    response = client.create_audience(
        parent=f"properties/{property_id}",
        audience=audience,
    )

    return {
        "success": True,
        "name": response.name,
        "display_name": response.display_name,
        "description": response.description,
        "membership_duration_days": response.membership_duration_days,
        "message": f"Audience '{display_name}' created on property {property_id}",
    }


def update_property_settings(
    credentials: Credentials,
    property_id: str,
    display_name: Optional[str] = None,
    industry_category: Optional[str] = None,
    time_zone: Optional[str] = None,
    currency_code: Optional[str] = None,
) -> dict[str, Any]:
    """
    Update GA4 property settings.

    Args:
        property_id: GA4 property ID
        display_name: new display name (optional)
        industry_category: e.g. "TECHNOLOGY", "RETAIL", "FINANCE" (optional)
        time_zone: IANA time zone e.g. "Europe/Berlin" (optional)
        currency_code: ISO 4217 e.g. "EUR", "USD" (optional)

    Returns:
        dict with updated property details
    """
    from google.analytics.admin_v1alpha import AnalyticsAdminServiceClient
    from google.analytics.admin_v1alpha.types import Property, IndustryCategory
    from google.protobuf import field_mask_pb2

    client = AnalyticsAdminServiceClient(credentials=credentials)

    # Fetch current property first
    current = client.get_property(name=f"properties/{property_id}")

    update_fields = []
    if display_name is not None:
        current.display_name = display_name
        update_fields.append("display_name")
    if industry_category is not None:
        current.industry_category = IndustryCategory[industry_category]
        update_fields.append("industry_category")
    if time_zone is not None:
        current.time_zone = time_zone
        update_fields.append("time_zone")
    if currency_code is not None:
        current.currency_code = currency_code
        update_fields.append("currency_code")

    if not update_fields:
        return {"success": False, "message": "No fields to update provided"}

    mask = field_mask_pb2.FieldMask(paths=update_fields)
    response = client.update_property(property=current, update_mask=mask)

    return {
        "success": True,
        "name": response.name,
        "display_name": response.display_name,
        "time_zone": response.time_zone,
        "currency_code": response.currency_code,
        "industry_category": response.industry_category.name,
        "updated_fields": update_fields,
        "message": f"Property {property_id} updated: {', '.join(update_fields)}",
    }
