# python
import os
import requests

# django
from django.db.models import Q
from django.shortcuts import get_object_or_404

# rest_framework
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework.views import APIView

# rest_framework_simplejwt
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

# internal apps
from diary.models import Comment, Note, PhotoPage, PlanPage, Stamp
from diary.serializers import MarkerSerializer
from user.models import CheckEmail, User, UserGroup
from user.serializers import (
    GroupCreateSerializer, 
    GroupSerializer,
    GroupUpdateSerializer,
    LoginSerializer, 
    SignUpSerializer,
    UserUpdateSerializer, 
    UserViewSerializer,
    ChangePasswordSerializer
)
from user.validators import (
    validate_password, 
    validate_email,
)
  

class SignUpAPI(APIView):
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            context = {
                "message":"가입 완료!",
                "user": serializer.data,
            }
            return Response(context, status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SignInAPI(TokenObtainPairView):
    serializer_class = LoginSerializer


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try: 
            refresh_token = request.data["refresh_token"] 
            token = RefreshToken(refresh_token) 
            token.blacklist() 

            return Response({"message": "로그아웃 되었습니다!"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception: 
            return Response({"message": "로그아웃 처리 중 오류가 발생했습니다!"}, status=status.HTTP_400_BAD_REQUEST)

class SendEmailAPI(APIView):
    def post(self, request):
        email = request.data.get("email")
        if validate_email(email):
            raise APIException("잘못된 이메일입니다.")

        code = CheckEmail.objects.create(email=email)
        code.send_email()
        context = {
            "message": "이메일을 전송했습니다. 메일함을 확인하세요.",
            "code": code.id
        }
        return Response(context, status=status.HTTP_200_OK)



class UserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        context = {
            "user": UserViewSerializer(request.user).data
        }
        return Response(context, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, context={"request":request}, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
        return Response({"message":"수정 완료"}, status=status.HTTP_200_OK)

    # 회원 삭제
    def delete(self, request):
        user = request.user
        user.is_active = False
        user.save()
        return Response({"message": "계정 삭제 완료!"}, status=status.HTTP_204_NO_CONTENT)


# 비밀번호 새로 만들기
class ChangePassword(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update_user()
        return Response({"message": "비밀번호 변경 완료!"}, status=status.HTTP_200_OK)


class GroupView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        groups = UserGroup.objects.filter(members=request.user, status="0").order_by("-created_at")
        serializer = GroupSerializer(groups, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 그룹 만들기
    def post(self, request):
        serializer = GroupCreateSerializer(data=request.data, context={"request":request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # 그룹 삭제하기
    def delete(self, request):
        group_ids = request.data.get("group_ids")

        for id in group_ids:
            # 비활성 불러오기
            group = get_object_or_404(
                UserGroup.objects.filter(
                    id=id, master_id=request.user.id, status__in=["1"]
                )
            )
            # 본인이 생성한 그룹이 맞다면
            if request.user == group.master:
                group.status = "3"
                group.save()

                # 그룹에 속한 노트, 계획, 사진첩, 댓글, 스탬프 상태 변경
                notes = Note.objects.filter(group=group)
                notes.update(status="3")

                plan_pages = PlanPage.objects.filter(diary__in=notes)
                plan_pages.update(status="3")

                photo_pages = PhotoPage.objects.filter(diary__in=notes)
                photo_pages.update(status="3")

                comments = Comment.objects.filter(photo__in=photo_pages)
                comments.update(status="3")

                stamps = Stamp.objects.filter(photo__in=photo_pages)
                stamps.update(status="3")

                status_code = status.HTTP_204_NO_CONTENT
                message = "그룹이 삭제되었습니다."

            # 본인이 생성한 그룹이 아니라면
            else:
                status_code = status.HTTP_403_FORBIDDEN
                message = "권한이 없습니다."

        return Response({"message": message}, status=status_code)


class GroupDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    # 그룹 상세보기
    def get(self, request, group_id):
        group = get_object_or_404(
            UserGroup.objects.filter(id=group_id, members=request.user, status="0")
        )
        serializer = GroupSerializer(group)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 그룹 수정하기
    def patch(self, request, group_id):
        group = get_object_or_404(
            UserGroup.objects.filter(id=group_id, master_id=request.user.id, status="0")
        )
        # 본인이 생성한 그룹이 맞다면
        if request.user.id == group.master_id:
            serializer = GroupUpdateSerializer(group, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # 본인이 생성한 그룹이 아니라면
        else:
            return Response({"message": "권한이 없습니다."}, status=status.HTTP_403_FORBIDDEN)


# 소셜 로그인
URI = "https://liberation-note.com"


# OAuth 인증 url
class SocialUrlView(APIView):
    def post(self, request):
        social = request.data.get("social", None)
        code = request.data.get("code", None)

        # 소셜 로그인 확인 여부
        if social is None:
            return Response(
                {"error": "소셜로그인이 아닙니다"}, status=status.HTTP_400_BAD_REQUEST
            )
        # 카카오
        elif social == "kakao":
            url = (
                "https://kauth.kakao.com/oauth/authorize?client_id="
                + os.environ.get("KAKAO_REST_API_KEY")
                + "&redirect_uri="
                + URI
                + "&response_type=code&prompt=login"
            )
            return Response({"url": url}, status=status.HTTP_200_OK)
        # 네이버
        elif social == "naver":
            url = (
                "https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id="
                + os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
                + "&redirect_uri="
                + URI
                + "&state="
                + os.environ.get("STATE")
            )
            return Response({"url": url}, status=status.HTTP_200_OK)
        # 구글
        elif social == "google":
            client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
            redirect_uri = URI

            url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=email%20profile"

            return Response({"url": url}, status=status.HTTP_200_OK)


# 카카오 소셜 로그인
class KakaoLoginView(APIView):
    def post(self, request):
        code = request.data.get("code")  # 카카오에서 인증 후 얻은 code

        # 카카오 API로 액세스 토큰 요청
        access_token = requests.post(
            "https://kauth.kakao.com/" + "oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "client_id": os.environ.get("KAKAO_REST_API_KEY"),
                "redirect_uri": URI,
                "code": code,  # 인증 후 얻은 코드
            },
        )

        # 발급 받은 토큰에서 access token만 추출
        access_token = access_token.json().get("access_token")

        # 카카오 API로 사용자 정보 요청
        user_data_request = requests.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            },
        )
        user_datajson = user_data_request.json()
        user_data = user_datajson["kakao_account"]
        email = user_data["email"]

        try:
            # 사용자가 이미 존재하는 경우 (회원가입이 되어 있는 경우)
            user = User.objects.get(email=email)

            # 탈퇴 계정인지 확인
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                refresh["email"] = user.email
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "탈퇴한 사용자는 로그인할 수 없습니다!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except:
            # 사용자가 존재하지 않는 경우 회원 가입 진행
            user = User.objects.create_user(email=email)
            user.set_unusable_password()  # 비밀번호 생성 X
            user.save()

            # 그룹 이름
            group_name = email.split("@")[0]

            # 회원가입 시 개인 그룹 생성
            new_group = UserGroup(name=group_name, master=user)
            new_group.save()
            new_group.members.add(user)

            refresh = RefreshToken.for_user(user)
            refresh["email"] = user.email
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )


# 네이버 소셜 로그인
class NaverLoginView(APIView):
    def post(self, request):
        code = request.data.get("code")
        client_id = os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
        client_secret = os.environ.get("SOCIAL_AUTH_NAVER_SECRET")
        redirect_uri = URI

        # 네이버 API로 액세스 토큰 요청
        access_token_request = requests.post(
            "https://nid.naver.com/oauth2.0/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code": code,
            },
        )

        access_token_json = access_token_request.json()
        # 발급 받은 토큰에서 access token만 추출
        access_token = access_token_json.get("access_token")

        # 네이버 API로 사용자 정보 요청
        user_data_request = requests.get(
            "https://openapi.naver.com/v1/nid/me",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        user_data_json = user_data_request.json()
        user_data = user_data_json.get("response")
        email = user_data.get("email")

        try:
            # 사용자가 이미 존재하는 경우 (회원가입이 되어 있는 경우)
            user = User.objects.get(email=email)

            # 탈퇴 계정인지 확인
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                refresh["email"] = user.email
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "탈퇴한 사용자는 로그인할 수 없습니다!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except:
            # 사용자가 존재하지 않는 경우 회원 가입 진행
            user = User.objects.create_user(email=email)
            user.set_unusable_password()  # 비밀번호 생성 X
            user.save()

            # 그룹 이름
            group_name = email.split("@")[0]

            # 회원가입 시 개인 그룹 생성
            new_group = UserGroup(name=group_name, master=user)
            new_group.save()
            new_group.members.add(user)

            refresh = RefreshToken.for_user(user)
            refresh["email"] = user.email
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )


# 구글 소셜 로그인
class GoogleLoginView(APIView):
    def post(self, request):
        code = request.data.get("code")
        client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
        client_secret = os.environ.get("SOCIAL_AUTH_GOOGLE_SECRET")
        redirect_uri = URI

        # 구글 API로 액세스 토큰 요청
        access_token_request = requests.post(
            "https://oauth2.googleapis.com/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "scope": "email",
            },
        )
        access_token_json = access_token_request.json()
        access_token = access_token_json.get("access_token")

        # 구글 API로 사용자 정보 요청
        user_data_request = requests.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_data_json = user_data_request.json()
        email = user_data_json.get("email")

        try:
            # 사용자가 이미 존재하는 경우 (회원가입이 되어 있는 경우)
            user = User.objects.get(email=email)

            # 탈퇴 계정인지 확인
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                refresh["email"] = user.email
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "탈퇴한 사용자는 로그인할 수 없습니다!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except:
            # 사용자가 존재하지 않는 경우 회원 가입 진행
            user = User.objects.create_user(email=email)
            user.set_unusable_password()  # 비밀번호 생성 X
            user.save()

            # 그룹 이름
            group_name = email.split("@")[0]

            # 회원가입 시 개인 그룹 생성
            new_group = UserGroup(name=group_name, master=user)
            new_group.save()
            new_group.members.add(user)

            refresh = RefreshToken.for_user(user)
            refresh["email"] = user.email
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )


class MyPageView(APIView):
    def get(self, request):
        profile = get_object_or_404(User, id=request.user.id)
        stamp = Stamp.objects.filter(user=request.user.id)
        group = UserGroup.objects.filter(members=request.user.id, status=0)
        profileserializer = UserViewSerializer(profile)
        stampserializer = MarkerSerializer(stamp, many=True)
        groupserializer = GroupSerializer(group, many=True)
        data = {
            "profile": profileserializer.data,
            "stamps": stampserializer.data,
            "groups": groupserializer.data,
        }
        return Response(data, status=status.HTTP_200_OK)


# 유저 리스트
class UserListView(generics.ListAPIView):
    serializer_class = UserViewSerializer

    def get_queryset(self):
        usersearch = self.request.query_params.get("usersearch", None)  # 유저 검색어 가져오기
        queryset = User.objects.all()

        # 이메일 필드에서 검색어가 포함된 사용자 찾기
        if usersearch is not None:
            queryset = queryset.filter(Q(email__icontains=usersearch)).distinct()

        return queryset.distinct()  # 중복 제거하여 반환
