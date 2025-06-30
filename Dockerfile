# Dockerfile

FROM nginx:1.25-alpine-slim

RUN apk add --no-cache bash gettext

COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 7860

# کاربر را به root تغییر می‌دهیم تا Nginx با مجوزهای کافی اجرا شود
# و بتواند فایل PID را در /tmp بنویسد و به پورت‌های پایین‌تر (اگر نیاز بود) دسترسی داشته باشد.
# برای پورت 7860 معمولاً root لازم نیست، اما برای سازگاری با تنظیمات  نگه داشته شده.
USER root

ENTRYPOINT ["/entrypoint.sh"]
