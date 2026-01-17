from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP address has been blocked.")

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
