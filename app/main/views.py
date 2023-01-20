from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required(login_url='/account/login/')
def index(request):
    return render(request, 'main/index.html', {'user': request.user})
