from  django.urls import path
from . import views
from django.urls import path, include

urlpatterns = [
    path('',views.index,name='index'),
    path('register/',views.register,name='register'),
    path('login/',views.login,name='login'),
    path('profile/',views.profile,name='profile'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path('admin_dashboard/',views.admin_dashboard,name='admin_dashboard'),
    path('admin_login/',views.admin_login,name='admin_login'),
    path('user_list/',views.user_list,name='user_list'),
    path('upload/<int:user_id>/',views.upload_and_scan,name='upload_file'),
    path('deleteuser/<int:id>/',views.deleteuser,name='deleteuser'),
    path('deletefile/<int:id>/',views.deletefile,name='deletefile'),
    path('admin_file_list/', views.admin_file_list, name='admin_file_list'),
    path('deletefile/<int:id>/', views.deletefile, name='deletefile'),
    path('editprofile/', views.editprofile, name='editprofile'),
    path('logout/', views.logout, name='logout'),
    path('urlscanner/',views.urlscanner,name='urlscanner'),
    path('reports/',views.reports,name='reports'),
    path('app_scan/<int:user_id>/',views.upload_and_scan,name='application_scan'),
    path('submit_feedback/', views.submit_feedback, name='submit_feedback'),
    path('feedback_list/', views.feedback_list, name='feedback_list'),
]



