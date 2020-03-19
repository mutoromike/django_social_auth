from django.contrib import admin
from django.urls import path, include
from rest_framework_swagger.views import get_swagger_view

from .pages.general import GeneralRoutes

schema_view = get_swagger_view(title='Social Login Documentation')

urlpatterns = [
    path('', schema_view, name="main-view"),
    path('admin/', admin.site.urls),
    path('api/', include('django_login.apps.authentication.urls')),
    path('oauth/', include('social_django.urls', namespace='social')),
    path('home', GeneralRoutes.home, name="home")

]
