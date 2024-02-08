import base64
import json
import os

import jwt
import requests
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from diary.models import Note
from diary.serializers import NoteSerializer
from user.models import User, UserGroup
from user.serializers import UserViewSerializer

from .models import Payment, Subscribe
from .serializers import SubscribeSerializer


class check_subscription(APIView):
    def get(self, request, note_id):
        note = Note.objects.get(id=note_id)
        group_id = NoteSerializer(note).data["group"]
        group = UserGroup.objects.get(id=group_id)
        print(group_id)
        if group.is_subscribe:
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class Success(APIView):
    def get(self, request):
        print(request.user)
        access_token = request.META.get("HTTP_AUTHORIZATION_TOKEN")
        orderId = request.GET.get("orderId")
        amount = request.GET.get("amount")
        paymentKey = request.GET.get("paymentKey")
        note_id = request.GET.get("note_id")
        print(access_token, orderId, amount, paymentKey, note_id)

        url = "https://api.tosspayments.com/v1/payments/confirm"
        secret_key = settings.TOSS_SECRET_KEY
        django_secret_key = settings.SECRET_KEY
        print(secret_key, django_secret_key)
        try:
            token_data = jwt.decode(
                access_token, key=django_secret_key, algorithms=["HS256"]
            )  # jwt 복호화
            print(token_data)
            user_id = token_data.get("user_id")
            # 사용자 ID로 DB에서 user_id 가져오기
            user = User.objects.get(id=user_id)
            user_serializer = UserViewSerializer(user)
            # user.is_subscribe = True
            # user.save()

            note = Note.objects.get(id=note_id)
            group_id = NoteSerializer(note).data["group"]
            group = UserGroup.objects.get(id=group_id)
            group.is_subscribe = True
            group.save()

            userpass = secret_key + ":"
            encoded_u = base64.b64encode(userpass.encode()).decode()

            headers = {
                "Authorization": "Basic %s" % encoded_u,
                "Content-Type": "application/json",
            }
            params = {
                "orderId": orderId,
                "amount": amount,
                "paymentKey": paymentKey,
            }

            res = requests.post(url, data=json.dumps(params), headers=headers)
            resjson = res.json()
            pretty = json.dumps(resjson, indent=4)
            respaymentKey = resjson["paymentKey"]
            resorderId = resjson["orderId"]
            suppliedAmount = resjson["suppliedAmount"]
            totalAmount = resjson["totalAmount"]
            vat = resjson["vat"]
            requestedAt = resjson["requestedAt"]
            orderName = resjson["orderName"]

            # DB에 객체 저장
            subscribe = Subscribe.objects.create(
                group=group, price=totalAmount, is_subscribe=True, type=orderName
            )
            end_date = subscribe.calculate_end_date()
            subscribe.save()
            payment = Payment.objects.create(
                user=user,
                group=group,
                amount=totalAmount,
                supplied_amount=suppliedAmount,
            )
            payment.save()
            print(80, payment)

            subscribe_serializer = SubscribeSerializer(subscribe)
            print(subscribe_serializer.data)

            response_data = {
                "res": pretty,
                "respaymentKey": respaymentKey,
                "resorderId": resorderId,
                "totalAmount": totalAmount,
                "suppliedAmount": suppliedAmount,
                "vat": vat,
                "requestedAt": requestedAt,
                "orderName": orderName,
                "user": user_serializer.data["email"],
                "duration": subscribe_serializer.data["duration"],
                "start_subscribe_at": subscribe_serializer.data["start_subscribe_at"],
                "end_date": subscribe_serializer.data["end_date"],
            }

            # JSON 응답생성
            return HttpResponse(
                json.dumps(response_data), content_type="application/json", status=200
            )
        except jwt.DecodeError:
            # 잘못된 토큰 처리
            return HttpResponse(status=401)


def fail(request):
    code = request.GET.get("code")
    message = request.GET.get("message")

    print(message)

    return render(
        request,
        "payments/fail.html",
        {
            "code": code,
            "message": message,
        },
    )
