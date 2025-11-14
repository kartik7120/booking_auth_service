# filepath: /home/kartik7120/booking_auth_service/auth_service.dockerfile
FROM alpine:latest

WORKDIR /app

COPY .env /app/.env

COPY authApp /app/authApp

RUN chmod +x authApp

CMD [ "./authApp" ]