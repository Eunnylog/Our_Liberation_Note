from celery import shared_task
from django.core.mail import EmailMessage



@shared_task
def send_email_task(user_email, subject, body):
    email = EmailMessage(subject, body, to=[user_email])
    email.send()

