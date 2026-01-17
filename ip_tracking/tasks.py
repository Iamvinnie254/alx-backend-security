from celery import shared_task
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from .models import RequestLog, SuspiciousIP


@shared_task
def detect_anomalous_ips():
    """
    Flags IPs that:
    - exceed 100 requests/hour
    - access sensitive paths like /admin or /login
    """

    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. Detect high request volume
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in high_volume_ips:
        SuspiciousIP.objects.create(
            ip_address=entry['ip_address'],
            reason=f"Exceeded 100 requests/hour ({entry['request_count']})"
        )

    # 2. Detect access to sensitive paths
    sensitive_paths = ['/admin', '/login']

    sensitive_access_ips = (
        RequestLog.objects
        .filter(
            timestamp__gte=one_hour_ago,
            path__in=sensitive_paths
        )
        .values_list('ip_address', flat=True)
        .distinct()
    )

    for ip in sensitive_access_ips:
        SuspiciousIP.objects.create(
            ip_address=ip,
            reason="Accessed sensitive endpoint"
        )
