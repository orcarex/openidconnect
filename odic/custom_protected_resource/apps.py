from django.apps import AppConfig


class CustomProtectedConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'custom_protected_resource'
