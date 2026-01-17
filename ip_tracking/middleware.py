from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import IpGeolocationAPI
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo_api = IpGeolocationAPI()

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP address has been blocked.")

        country, city = self.get_geolocation(ip_address)

        # Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            country=country,
            city=city
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

    def get_geolocation(self, ip_address):
        cache_key = f"geo:{ip_address}"
        cached_data = cache.get(cache_key)

        if cached_data:
            return cached_data['country'], cached_data['city']

        try:
            geo_data = self.geo_api.get(ip_address)
            country = geo_data.get('country_name')
            city = geo_data.get('city')
        except Exception:
            country = None
            city = None

        cache.set(
            cache_key,
            {'country': country, 'city': city},
            timeout=self.CACHE_TIMEOUT
        )

        return country, city
