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

    def __str__(self):
        return self.name

    def get_absolute_url(self, category="note"):
        if category == "note":
            return reverse("detail_note", kwargs={"note_id": self.id})
        elif category == "plan":
            return reverse("plan_page", kwargs={"note_id": self.id})


# 미영
class PlanPage(models.Model):
    diary = models.ForeignKey("Note", on_delete=models.CASCADE)
    start = models.DateField()
    title = models.CharField(max_length=100)
    location = models.CharField(max_length=255, null=True, blank=True)
    category = models.CharField(max_length=100, null=True, blank=True)
    time = models.CharField(max_length=255, null=True, blank=True)
    memo = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(choices=status_choice, max_length=100, default=0)
    location_x = models.CharField(max_length=255, null=True, blank=True)
    location_y = models.CharField(max_length=255, null=True, blank=True)

    def get_absolute_url(self):
        return reverse("detail_plan_page", kwargs={"plan_id": self.id})


# 제건
class PhotoPage(models.Model):
    diary = models.ForeignKey("Note", on_delete=models.CASCADE)  # 소속된 앨범 객체
    image = models.ImageField(upload_to="%y/%m")
    name = models.CharField(max_length=50)
    title = models.CharField(max_length=100)
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    memo = models.CharField(null=True, max_length=100)
    status = models.CharField(choices=status_choice, max_length=100, default=0)
    location_x = models.CharField(max_length=100, default=0)  # 위도
    location_y = models.CharField(max_length=100, default=0)  # 경도
    start = models.DateField(null=True, blank=True)

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
        return self.comment


# 예린
class Stamp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    photo = models.ForeignKey(PhotoPage, on_delete=models.CASCADE)
    status = models.CharField(choices=status_choice, max_length=100, default=0)
