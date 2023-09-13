from django.utils import timezone
from django.core.management.base import BaseCommand
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

class Command(BaseCommand):
    help = '만료된 모든 아웃스탠딩과 블랙리스트 토큰을 삭제합니다.'

    def handle(self, *args, **kwargs):
        OutstandingToken.objects.filter(expires_at__lt=timezone.now()).delete()
        self.stdout.write('만료된 아웃스탠딩 토큰이 성공적으로 삭제되었습니다.')
        
        BlacklistedToken.objects.filter(blacklisted_at__lt=timezone.now()).delete()
        self.stdout.write('만료된 블랙리스트 토큰이 성공적으로 삭제되었습니다.')
