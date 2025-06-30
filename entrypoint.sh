#!/bin/sh

set -e

if [ -z "${TARGET_HF_SPACE_URL}" ]; then
  echo "ERROR: The environment variable TARGET_HF_SPACE_URL is not set." >&2
  echo "Please set this secret in your Hugging Face Space settings." >&2
  exit 1
fi

# استخراج هاست‌نیم از URL هدف (مثال: https://user-space.hf.space/something -> user-space.hf.space)
# این روش نسبت به sed برای استخراج بخش سوم URL (هاست‌نیم) معمولا پایدارتر است.
export TARGET_HOSTNAME_NO_SCHEME=$(echo "${TARGET_HF_SPACE_URL}" | awk -F/ '{print $3}')

if [ -z "${TARGET_HOSTNAME_NO_SCHEME}" ]; then
  echo "ERROR: Could not extract hostname from TARGET_HF_SPACE_URL: ${TARGET_HF_SPACE_URL}" >&2
  exit 1
fi

echo "Target URL (from secret): ${TARGET_HF_SPACE_URL}"
echo "Extracted Target Hostname (for Nginx): ${TARGET_HOSTNAME_NO_SCHEME}"

CONFIG_FILE_PATH="/tmp/nginx.conf"
PID_FILE_PATH="/tmp/nginx.pid"

# جایگزینی متغیر محیطی در فایل template و ایجاد فایل کانفیگ نهایی
envsubst '$TARGET_HOSTNAME_NO_SCHEME' < /etc/nginx/nginx.conf.template > "${CONFIG_FILE_PATH}"

echo "Nginx configuration generated at: ${CONFIG_FILE_PATH}"
echo "Nginx PID file will be at: ${PID_FILE_PATH}"
echo "Starting Nginx..."

# اجرای Nginx در foreground و با فایل کانفیگ مشخص شده
# daemon off; باعث می‌شود Nginx در foreground اجرا شود که برای کانتینرها مناسب است.
# pid ${PID_FILE_PATH}; مسیر فایل PID را مشخص می‌کند.
exec nginx -g "daemon off; pid ${PID_FILE_PATH};" -c "${CONFIG_FILE_PATH}"
