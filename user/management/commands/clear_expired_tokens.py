from django.utils import timezone
from datetime import timedelta
from django.core.management.base import BaseCommand
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

class Command(BaseCommand):
    help = '모든 만료된 아웃스탠딩 토큰과 30일 이상 된 블랙리스트 토큰을 삭제합니다.'

    def handle(self, *args, **kwargs):
        OutstandingToken.objects.filter(expires_at__lt=timezone.now()).delete()
        self.stdout.write('만료된 아웃스탠딩 토큰이 성공적으로 삭제되었습니다.')
        
        limit = timezone.now() - timedelta(days=30)
        BlacklistedToken.objects.filter(blacklisted_at__lt=limit).delete()
        self.stdout.write('생성된 지 30일이 넘은 블랙리스트 토큰들이 성공적으로 삭제되었습니다.')
