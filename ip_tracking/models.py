from django.db import models


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    path = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.path}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
