from django.shortcuts import render


class GeneralRoutes:
    @staticmethod
    def home(request):
        return render(request, 'home.html')

    @staticmethod
    def privacy(request):
        return render(request, 'privacy.html')
