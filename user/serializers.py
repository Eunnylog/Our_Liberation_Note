from datetime import datetime as dt

from rest_framework import serializers
from rest_framework.serializers import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from user.models import User, UserGroup, CheckEmail

from user.validators import (
    check_words,
    validate_password, 
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
        
        if email_code_obj.is_verified == True:
            raise serializers.ValidationError("이미 사용한 인증 코드입니다.")
        
        if not email_code_obj:
            raise serializers.ValidationError("해당 메일로 보낸 인증 코드가 없습니다.")
              
        if email_code_obj.code != code:
            raise serializers.ValidationError("인증 코드가 유효하지 않습니다.")

        if email_code_obj.expired_at < dt.now():
            raise serializers.ValidationError("인증 코드 유효 기간이 지났습니다.")

        if validate_password(password):
            raise serializers.ValidationError("8자 이상의 영문 대/소문자, 숫자, 특수문자 조합이어야 합니다!")
        
        if password != repassword:
            raise serializers.ValidationError("비밀번호와 비밀번호 확인이 일치하지 않습니다.")
        
        # email_code_obj.update_is_verified()

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

        email_code_obj = CheckEmail.objects.filter(email=email).last()
        email_code_obj.update_is_verified()
        
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
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    check_new_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ("current_password", "new_password", "check_new_password", "email")
        
    def validate(self, data):
        if data["new_password"] == "" or data["current_password"] == "" or data["check_new_password"] == "":
            raise serializers.ValidationError("빈칸을 입력해주세요.")
        
        if data["new_password"] != data["check_new_password"]:
            raise serializers.ValidationError("새로운 비밀번호가 일치하지 않습니다.")
        
        user = self.context.get('request').user
        if not user.check_password(data['current_password']):
            raise serializers.ValidationError("비밀번호가 일치하지 않습니다.")

        try:
            validate_password(data['new_password'])
        except ValidationError:
            raise serializers.ValidationError("8자 이상의 영문 대/소문자, 숫자, 특수문자 조합이어야 합니다!")
        
        return data
    
    def update(self, instance, validated_data):
        instance.set_password(validated_data["new_password"])
        instance.save()
        return instance
    

class ChangePasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    code = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    check_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ("email", "code", "new_password", "check_password")
        
    def validate(self, data):
        # 가장 최근 인증코드 인스턴스
        self.email_code_obj = (CheckEmail.objects.filter(email=data["email"]).last())

        if self.email_code_obj.is_verified == True:
            raise serializers.ValidationError("이미 사용한 인증 코드입니다.")
        
        if data["new_password"] != data["check_password"]:
            raise serializers.ValidationError("비밀번호가 일치하지 않습니다.")
        
        try:
            validate_password(data['new_password'])
        except ValidationError:
            raise serializers.ValidationError("8자 이상의 영문 대/소문자, 숫자, 특수문자 조합이어야 합니다!")
        
        # 이메일 일치하는지 확인
        try:
            self.user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            raise serializers.ValidationError("이메일이 일치하지 않습니다.")
        
        if self.email_code_obj.code != data["code"]:
            raise serializers.ValidationError("인증 코드가 일치하지 않습니다.")
        
        # 유효 기간 확인
        if self.email_code_obj.expired_at < dt.now():
            raise serializers.ValidationError("인증 코드의 유효기간이 지났습니다.")
        
        return data
    
    def update_user(self):
        self.user.set_password(self.validated_data["new_password"])
        self.user.save()
        
        self.email_code_obj.update_is_verified()
        
        
class GroupSerializer(serializers.ModelSerializer):
    master = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()
    updated_at = serializers.SerializerMethodField()

    def get_master(self, obj):
        return obj.master.email

    def get_members(self, obj):
        return obj.members.values_list("email", flat=True)


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

    def validate(self, data):
        if check_words(data["name"]):
            raise ValidationError("비속어 사용이 불가합니다!")

        name = data["name"]
        
        if name is None:
            raise ValidationError("그룹명을 입력해주세요!")
        
        if len(name) < 2 or len(name) > 15:
            raise ValidationError("제한 글자수는 2~15자 입니다!")

        return data

    def create(self, validated_data):
        master = self.context["request"].user
        
        validated_data['master'] = master
        
        name = validated_data.get("name")
        
        if UserGroup.objects.filter(name=name).exists():
            raise serializers.ValidationError("이미 같은 이름의 그룹이 존재합니다.")
        
        group = super().create(validated_data)
        
        group.members.add(master)
        
        return group
    

class GroupUpdateSerializer(serializers.ModelSerializer):
    members = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True)
    
    class Meta:
        model = UserGroup
        fields = ("name", "members")
        read_only_fields = ("master",)
        
    def validate(self, data):
        name = data.get("name")
        
        if name:
            if check_words(data["name"]):
                raise ValidationError("비속어 사용이 불가합니다!")
            
            if len(name) < 2 or len(name) > 15:
                raise ValidationError("제한 글자수는 2~15자 입니다!")

        return data
        
    def validate_name(self, name) :
        if name and self.instance.name != name and UserGroup.objects.filter(name=name).exclude(id=self.instance.id).exists():
            raise ValidationError("같은 이름의 그룹이 이미 존재합니다.")
        
        return name
    
    def update(self, instance, validated_data):
        instance.name = validated_data.get("name", instance.name)
        
        members = validated_data.get('members')
        
        if members is not None:
            instance.members.clear()
            
            for user in members:
                instance.members.add(user)
        
        instance.members.add(instance.master)
        instance.save()
        
        return instance

class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email",)
