"""
Google Analytics tools — ported from github.com/googleanalytics/google-analytics-mcp.
All functions are async and accept a google.oauth2.credentials.Credentials object.
Read-only (analytics.readonly scope).
"""

from typing import Any, Dict, List, Optional

from google.analytics import admin_v1beta, admin_v1alpha, data_v1beta
from google.api_core.gapic_v1.client_info import ClientInfo
import proto

_CLIENT_INFO = ClientInfo(user_agent="google-analytics-mcp/2.0")


def _admin(creds) -> admin_v1beta.AnalyticsAdminServiceAsyncClient:
    return admin_v1beta.AnalyticsAdminServiceAsyncClient(
        credentials=creds, client_info=_CLIENT_INFO
    )


def _admin_alpha(creds) -> admin_v1alpha.AnalyticsAdminServiceAsyncClient:
    return admin_v1alpha.AnalyticsAdminServiceAsyncClient(
        credentials=creds, client_info=_CLIENT_INFO
    )


def _data(creds) -> data_v1beta.BetaAnalyticsDataAsyncClient:
    return data_v1beta.BetaAnalyticsDataAsyncClient(
        credentials=creds, client_info=_CLIENT_INFO
    )


def _prop(property_id) -> str:
    """Normalize property_id to 'properties/NNN' resource name."""
    if isinstance(property_id, int):
        return f"properties/{property_id}"
    s = str(property_id).strip()
    if s.isdigit():
        return f"properties/{s}"
    if s.startswith("properties/") and s.split("/")[-1].isdigit():
        return s
    raise ValueError(
        f"Invalid property_id: {property_id!r}. "
        "Use a number or 'properties/<number>'."
    )


def _to_dict(obj: proto.Message) -> Dict[str, Any]:
    return type(obj).to_dict(obj, use_integers_for_enums=False, preserving_proto_field_name=True)


# ─── Admin tools ──────────────────────────────────────────────────────────────

async def get_account_summaries(credentials) -> List[Dict[str, Any]]:
    """Retrieves all GA4 accounts and properties the user has access to."""
    pager = await _admin(credentials).list_account_summaries()
    return [_to_dict(page) async for page in pager]


async def get_property_details(credentials, property_id) -> Dict[str, Any]:
    """Returns full details for a specific GA4 property."""
    resp = await _admin(credentials).get_property(
        request=admin_v1beta.GetPropertyRequest(name=_prop(property_id))
    )
    return _to_dict(resp)


async def list_google_ads_links(credentials, property_id) -> List[Dict[str, Any]]:
    """Lists Google Ads account links for a GA4 property."""
    pager = await _admin(credentials).list_google_ads_links(
        request=admin_v1beta.ListGoogleAdsLinksRequest(parent=_prop(property_id))
    )
    return [_to_dict(page) async for page in pager]


async def list_property_annotations(credentials, property_id) -> List[Dict[str, Any]]:
    """Returns date annotations for a GA4 property (release notes, campaign launches, etc.)."""
    pager = await _admin_alpha(credentials).list_reporting_data_annotations(
        request=admin_v1alpha.ListReportingDataAnnotationsRequest(parent=_prop(property_id))
    )
    return [_to_dict(page) async for page in pager]


# ─── Reporting tools ──────────────────────────────────────────────────────────

async def run_report(
    credentials,
    property_id,
    date_ranges: List[Dict[str, Any]],
    dimensions: List[str],
    metrics: List[str],
    dimension_filter: Optional[Dict[str, Any]] = None,
    metric_filter: Optional[Dict[str, Any]] = None,
    order_bys: Optional[List[Dict[str, Any]]] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    currency_code: Optional[str] = None,
    return_property_quota: bool = False,
) -> Dict[str, Any]:
    """
    Runs a GA4 Data API report.

    date_ranges: list of {start_date, end_date} dicts.
      Relative dates: '7daysAgo', '30daysAgo', 'yesterday', 'today'.
      Absolute dates: 'YYYY-MM-DD'.
    dimensions: e.g. ['pagePath', 'country', 'sessionSource']
    metrics: e.g. ['sessions', 'screenPageViews', 'conversions', 'totalRevenue']
    """
    request = data_v1beta.RunReportRequest(
        property=_prop(property_id),
        dimensions=[data_v1beta.Dimension(name=d) for d in dimensions],
        metrics=[data_v1beta.Metric(name=m) for m in metrics],
        date_ranges=[data_v1beta.DateRange(dr) for dr in date_ranges],
        return_property_quota=return_property_quota,
    )
    if dimension_filter:
        request.dimension_filter = data_v1beta.FilterExpression(dimension_filter)
    if metric_filter:
        request.metric_filter = data_v1beta.FilterExpression(metric_filter)
    if order_bys:
        request.order_bys = [data_v1beta.OrderBy(ob) for ob in order_bys]
    if limit is not None:
        request.limit = limit
    if offset is not None:
        request.offset = offset
    if currency_code:
        request.currency_code = currency_code

    resp = await _data(credentials).run_report(request)
    return _to_dict(resp)


async def run_realtime_report(
    credentials,
    property_id,
    dimensions: List[str],
    metrics: List[str],
    dimension_filter: Optional[Dict[str, Any]] = None,
    metric_filter: Optional[Dict[str, Any]] = None,
    order_bys: Optional[List[Dict[str, Any]]] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    return_property_quota: bool = False,
) -> Dict[str, Any]:
    """
    Runs a GA4 realtime report (live active users).
    Use realtime dimensions/metrics from the realtime API schema.
    """
    request = data_v1beta.RunRealtimeReportRequest(
        property=_prop(property_id),
        dimensions=[data_v1beta.Dimension(name=d) for d in dimensions],
        metrics=[data_v1beta.Metric(name=m) for m in metrics],
        return_property_quota=return_property_quota,
    )
    if dimension_filter:
        request.dimension_filter = data_v1beta.FilterExpression(dimension_filter)
    if metric_filter:
        request.metric_filter = data_v1beta.FilterExpression(metric_filter)
    if order_bys:
        request.order_bys = [data_v1beta.OrderBy(ob) for ob in order_bys]
    if limit is not None:
        request.limit = limit
    if offset is not None:
        request.offset = offset

    resp = await _data(credentials).run_realtime_report(request)
    return _to_dict(resp)


async def get_custom_dimensions_and_metrics(
    credentials, property_id
) -> Dict[str, List[Dict[str, Any]]]:
    """Returns the property's custom dimensions and metrics."""
    metadata = await _data(credentials).get_metadata(
        name=f"{_prop(property_id)}/metadata"
    )
    return {
        "custom_dimensions": [
            _to_dict(d) for d in metadata.dimensions if d.custom_definition
        ],
        "custom_metrics": [
            _to_dict(m) for m in metadata.metrics if m.custom_definition
        ],
    }
