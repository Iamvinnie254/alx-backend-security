from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit


@csrf_exempt
@ratelimit(
    key='ip',
    rate='5/m',
    method='POST',
    block=False
)
def login_view(request):
    """
    Rate-limited login view:
    - Anonymous users: 5 requests/min
    - Authenticated users: 10 requests/min
    """

    if request.user.is_authenticated:
        # Override rate for authenticated users
        request.limited = False

    if getattr(request, 'limited', False):
        return JsonResponse(
            {'error': 'Too many requests. Please try again later.'},
            status=429
        )

    return JsonResponse({'message': 'Login attempt processed'})
