from django.core.mail import EmailMessage
from celery import shared_task
from django.core.management import call_command


@shared_task
def send_email_task(user_email, subject, body):
    email = EmailMessage(subject, body, to=[user_email])
    email.send()
    
    
@shared_task
def clear_expired_tokens():
    call_command('clear_expired_tokens')
