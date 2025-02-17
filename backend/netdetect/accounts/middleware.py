from django.shortcuts import redirect, render
from django.http import HttpResponse

class CustomErrorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Check for a 404 status code
        if response.status_code == 404:
            # Render a custom 404 template or redirect to a specific page
            return render(request, 'error.html', status=404)
        
        return response
