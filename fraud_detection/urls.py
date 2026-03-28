from django.urls import path
from . import views

app_name = "fraud_detection"

urlpatterns = [
    # HTML pages
    path("check-upi/",          views.check_page,     name="check_page"),
    path("upi-database/",       views.upi_database,   name="upi_database"),

    # JSON APIs
    path("api/check-upi/",      views.check_upi,      name="api_check_upi"),
    path("api/report-upi/",     views.report_upi,     name="api_report_upi"),
    path("api/history/",        views.fraud_history,  name="api_fraud_history"),
    path("api/analytics/",      views.analytics_api,  name="api_analytics"),
]
