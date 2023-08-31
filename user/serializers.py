from datetime import datetime as dt

from rest_framework import serializers
from rest_framework.serializers import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from user.models import User, UserGroup, CheckEmail

from user.validators import (
    check_words,
    check_password, 
    validate_email,
)

class SignUpSerializer(serializers.ModelSerializer):
    code = serializers.CharField(write_only=True)
    repassword = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = "__all__"

    def validate(self, data):       
        email = data.get("email")        
        code = data.get("code")
        password = data.get("password")
        repassword = data.get("repassword")
            
        email_code_obj = (CheckEmail.objects.filter(email=email).last())
        
        if not email_code_obj:
            raise ValidationError({"message": "해당 메일로 보낸 인증 코드가 없습니다."})
              
        if email_code_obj.code != code:
            raise ValidationError({"message": "인증 코드가 유효하지 않습니다."})

        if email_code_obj.expired_at < dt.now():
            raise ValidationError({"message": "인증 코드 유효 기간이 지났습니다."})

        if check_password(password):
            raise ValidationError({"message": "8자 이상의 영문 대/소문자, 숫자, 특수문자 조합이어야 합니다!"})
        
        if password != repassword:
            raise ValidationError({"message": "비밀번호와 비밀번호 확인이 일치하지 않습니다."})
        
        email_code_obj.update_is_verified()

        return data

    def create(self, validated_data):
        email = validated_data["email"]
        password = validated_data["password"]
        user = User(
            email=email,
            password=password,
        )
        user.set_password(validated_data["password"])
        user.save()

        user_group_name = email.split("@")[0]
        new_user = User.objects.get(email=email)
        new_group = UserGroup(name=user_group_name, master=new_user)
        new_group.save()
        new_group.members.add(new_user)
        return user


class LoginSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = user.email
        token["is_admin"] = user.is_admin

        return token


class UserViewSerializer(serializers.ModelSerializer):
    join_date = serializers.SerializerMethodField()

    def get_join_date(self, obj):
        return obj.join_date.strftime("%Y년 %m월 %d일 %p %I:%M")

    class Meta:
        model = User
        exclude = ("password",)


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("password", "email")

    def update(self, instance, validated_data):
        # 새로운 비밀번호로 설정
        password = validated_data.get("new_password")
        if password:
            instance.set_password(password)

        instance.save()
        return instance


class GroupSerializer(serializers.ModelSerializer):
    master = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()
    updated_at = serializers.SerializerMethodField()

    def get_master(self, obj):
        return obj.master.email

    def get_members(self, obj):
        return ", ".join(
            obj.members.values_list("email", flat=True)
        )  # values_list는 member 필드의 값을 리스트로 반환, flat을 쓰지 않으면 튜플로 반환

    def get_status(self, obj):
        if obj.status == "0":
            return "활성화"
        elif obj.status == "1":
            return "비활성화"
        elif obj.status == "2":
            return "강제중지"
        elif obj.status == "3":
            return "삭제"

    def get_created_at(self, obj):
        return obj.created_at.strftime("%Y년 %m월 %d일 %p %I:%M")

    def get_updated_at(self, obj):
        return obj.updated_at.strftime("%Y년 %m월 %d일 %p %I:%M")

    class Meta:
        model = UserGroup
        fields = "__all__"


class GroupCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGroup
        fields = ("name", "members", "master", "status")
        read_only_fields = ("master",)

    def validate(self, attrs):
        if check_words(attrs["name"]):
            raise ValidationError("비속어 사용이 불가합니다!")

        name = attrs["name"]
        if len(name) < 2 or len(name) > 15:
            raise ValidationError("제한 글자수는 2~15자 입니다!")

        return attrs


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email",)
