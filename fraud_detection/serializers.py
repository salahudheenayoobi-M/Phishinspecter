from rest_framework import serializers
from .models import UPIID

class UPIIDSerializer(serializers.ModelSerializer):

    class Meta:
        model = UPIID
        fields = '__all__'