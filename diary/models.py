from django.db import models
from django.urls import reverse

from user.models import User, UserGroup

status_choice = (
    ("0", "활성화"),
    ("1", "비활성화"),
    ("2", "강제중지"),
    ("3", "삭제"),
)


# 예지
class Note(models.Model):
    class Meta:
        db_table = "note"

    note_covers = (
        ("1", "코랄핑크표지"),
        ("2", "브라운표지"),
        ("3", "노랑표지"),
        ("4", "초록표지"),
        ("5", "파랑표지"),
        ("6", "보라표지"),
        ("7", "그라데이션-블루퍼플"),
        ("8", "검정표지"),
        ("9", "그레이블루표지"),
        ("10", "그라데이션-블루옐로"),
        ("11", "그라데이션-보라그레이"),
        ("12", "그라데이션-핑크베이지"),
    )

    group = models.ForeignKey(UserGroup, on_delete=models.CASCADE)
    name = models.CharField("노트이름", max_length=30)
    category = models.CharField("노트표지", choices=note_covers, max_length=10, default=1)
    created_at = models.DateTimeField("생성일", auto_now_add=True)
    status = models.CharField("상태", choices=status_choice, max_length=10, default=0)


# 미영
class PlanPage(models.Model):
    diary = models.ForeignKey("Note", on_delete=models.CASCADE)
    start = models.DateField()
    title = models.CharField(max_length=100)
    location = models.CharField(max_length=255, null=True, blank=True)
    time = models.CharField(max_length=255, null=True, blank=True)
    memo = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(choices=status_choice, max_length=100, default=0)


# 제건
class PhotoPage(models.Model):
    diary = models.ForeignKey("Note", on_delete=models.CASCADE)
    image = models.ImageField(null=True, blank=True)  # 배포 후엔 null X
    location = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    memo = models.CharField(null=True, max_length=100)
    status = models.CharField(choices=status_choice, max_length=100, default=0)

    def __str__(self):
        return self.location


class Comment(models.Model):
    photo = models.ForeignKey(PhotoPage, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(choices=status_choice, max_length=100, default=0)

    def __str__(self):
        return self.name


# 예린
class Stamp(models.Model):
    pass


class Todo(models.Model):
    pass
