# python
import random
import string
from datetime import timedelta


# django
from django.contrib.auth.models import AbstractBaseUser
from django.db import models
from django.urls import reverse
from django.utils import timezone

# rest_framework
from rest_framework.authtoken.models import Token

# internal app
from user.validators import validate_password
from user.tasks import send_email_task
from user.manager import UserManager


STATUS_CHOICE = (
    ("0", "활성화"),
    ("1", "비활성화"),
    ("2", "강제중지"),
    ("3", "삭제"),
)


class User(AbstractBaseUser):
    email = models.EmailField("이메일 주소", max_length=100, unique=True, error_messages={"unique":"이미 존재하는 이메일입니다."})
    password = models.CharField("비밀 번호", max_length=128, validators=[validate_password])
    join_date = models.DateTimeField("가입일", auto_now_add=True)
    is_active = models.BooleanField("활성 여부", default=True)
    is_admin = models.BooleanField("어드민 여부", default=False)

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return f"[{self.id}]{self.email}"

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class CheckEmail(models.Model):
    email = models.EmailField("인증용 이메일", max_length=100)
    code = models.CharField("확인용 코드", null=True, max_length=6, unique=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField(null=True)
    is_verified = models.BooleanField("인증 유무", default=False)

    def __str__(self):
        return f"[{self.id}]{self.email}"

    def update_is_verified(self, *args, **kwargs):
        self.is_verified = True
        super().save(*args, **kwargs)
        
    def send_email(self, *args, **kwargs):
        self.expired_at = timezone.now() + timedelta(minutes=5)
        self.code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        super().save(*args, **kwargs)

        subject = "[우리들의 해방일지] 인증 코드를 확인해주세요!"
        body = f"이메일 확인 코드: {self.code}"
        sent_email = send_email_task.delay(self.email, subject, body)


class UserGroup(models.Model):
    members = models.ManyToManyField("user.User", verbose_name="멤버", related_name="user_group", blank=True)
    master = models.ForeignKey("user.User", on_delete=models.PROTECT, verbose_name="그룹장", related_name="master_group")
    name = models.CharField("그룹 이름", max_length=255)
    created_at = models.DateTimeField("생성일", auto_now_add=True)
    updated_at = models.DateTimeField("업데이트", auto_now=True)
    status = models.CharField("상태", choices=STATUS_CHOICE, max_length=1, default="0")
    is_subscribe = models.BooleanField("결제 여부", default=False)

    def __str__(self):
        return f"[{self.id}]{self.name}"

    def get_absolute_url(self, category="note"):
        if category == "note":
            return reverse("note_detail", kwargs={"group_id": self.id})
        elif category == "group":
            return reverse("group_detail", kwargs={"group_id": self.id})
