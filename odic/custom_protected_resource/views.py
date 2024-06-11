from django.shortcuts import render
from django.http import JsonResponse
from oauth2_provider.decorators import protected_resource

@protected_resource()
def userinfo(request):
    user = request.resource_owner
    return JsonResponse({
        'sub': user.id,
        'name': user.get_full_name(),
        'email': user.email,
    })

