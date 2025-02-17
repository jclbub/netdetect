from django.shortcuts import render
from requests import Response
from .models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from .serializers import *
# Create your views here.

# class session views_______________________________________________________________________________
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def CreateClassSessionView(request):
    data = request.data

    subject_details = classSession.objects.create(
        name=data['name'],
    )
    serializer = ClassSessionerializer(subject_details, many=False)
    return Response(serializer.data)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def UpdateClassSessionView(request, pk):

    subject_details = classSession.objects.get(id=pk)
    serializer = ClassSessionerializer(subject_details, data=request.data)

    if serializer.is_valid():
        serializer.save()
        # print(request.data)
    return Response(serializer.data)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def DeleteClassSessionView(request, pk):
    subject_details = classSession.objects.get(id=pk)
    subject_details.delete()
    return Response('Que has been deleted')