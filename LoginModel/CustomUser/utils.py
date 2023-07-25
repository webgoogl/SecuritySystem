from django.core.mail import EmailMessage
from rest_framework.response import Response
from django.conf import settings
import os

class Util:
    
    def send_email(data):
        try:
            email=EmailMessage(
                subject=data['subject'],
                body=data['body'],
                from_email=os.environ.get('EMAIL_FROM') ,
                to=[data['to_email']]
            )
            email.send()
            return True
        
        except :
            return False