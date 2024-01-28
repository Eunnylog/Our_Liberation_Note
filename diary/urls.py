from django.urls import path

from diary import views


urlpatterns = [
    # 노트 생성, 삭제
    path("", views.NoteView.as_view(), name="note_post"),
    # 노트 그룹별 전체 조회
    path("<int:group_id>", views.NoteView.as_view(), name="note_detail"),
    # 노트 상세 조회, 수정, 삭제
    path(
        "note-detail/<int:note_id>",
        views.DetailNoteView.as_view(),
        name="detail_note",
    ),
    # 사진첩 전체 조회
    path(
        "photo/<int:note_id>/<int:offset>",
        views.PhotoPageView.as_view(),
        name="photo_page_get",
    ),
    # 사진첩 저장
    path("photo/<int:note_id>", views.PhotoPageView.as_view(), name="photo_page_post"),
    # 사진첩 삭제
    path("photo", views.DetailPhotoPageView.as_view(), name="photo_page_delete"),
    # 계획 전체 조회, 생성
    path("plan/<int:note_id>", views.PlanPageView.as_view(), name="plan_page"),
    # 사진첩 상세 조회, 수정, 댓글 저장
    path(
        "photo-detail/<int:photo_id>",
        views.DetailPhotoPageView.as_view(),
        name="detail_photo_page",
    ),
    # 계획 상세 조회, 수정. 삭제
    path(
        "plan-detail/<int:plan_id>",
        views.DetailPlanPageView.as_view(),
        name="detail_plan_page",
    ),
    # 댓글 상세 조회, 수정. 삭제
    path(
        "comment/<int:comment_id>",
        views.CommentView.as_view(),
        name="comment",
    ),
    # 휴지통 조회, 임시 삭제 & 복원
    path("trash", views.Trash.as_view(), name="trash"),
    # 스탬프 저장, 수정
    path("stamp/<int:photo_id>", views.StampView.as_view(), name="stamp"),
    # 스탬프 위치별 조회
    path(
        "markerstamps/<str:photo_location>",
        views.MarkerStampsView.as_view(),
        name="markerstamps",
    ),
    # ai 검색
    path("search", views.SearchDestination.as_view(), name="search"),
    # 계획표 전송
    path("email/<int:note_id>", views.EmailView.as_view(), name="email"),
]
