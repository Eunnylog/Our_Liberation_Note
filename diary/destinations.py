from datetime import datetime

import openai
import requests
from bardapi import Bard
from bs4 import BeautifulSoup as bs
from haversine import haversine

from django.conf import settings

openai.api_key = settings.OPEN_AI

# 주어진 경로의 총 거리를 계산하는 함수.
# 경로는 좌표 목록으로 주어지며, 각 좌표는 경도와 위도의 한쌍
# 이 함수는 haversine 함수를 사용해 각 점 사이의 거리를 계산하고 총합을 반환
def total_distance(path):
    return sum(haversine(path[i], path[i + 1], unit="km") for i in range(len(path) - 1))


#  완전탐색 ->  그리디와 비슷한 가장 가까운 이웃(Nearest Neighbor) 알고리즘사용 -> openai을 사용하기 때문에 시간절약을 위해 변경
# 검색 함수는 데이터를 받아서 가장 효율적인 경로를 찾아내고, 다른 정보와 함께 결과를 반환
def search(data):
    start = datetime.now()  # 시작 시간을 기록
    title_li = []  # 위치의 이름을 저장하는 리스트
    x_y_li = []  # 각 위치의 좌표를 저장하는 리스트
    location_li = []  # 위치의 상세 주소를 저장하는 리스트

    # 데이터를 순회하며 정보를 추출해 각 리스트에 추가
    for item in data:
        title_li.append(item["title"])
        x_y_li.append((float(item["y"]), float(item["x"])))
        location_li.append((item["location"]))

    ordered_destinations = []  # 정렬된 목적지를 저장하는 리스트
    remaining_points = list(range(len(x_y_li)))  # 아직 방문하지 않은 점들의 인덱스를 저장하는 리스트

    # "역" 또는 "터미널"이 포함된 위치가 있다면 그 위치를 가장 처음에 배치
    for idx, item in enumerate(data):
        if "역" == item["title"][-1] or "터미널" in item["title"]:
            ordered_destinations.append(x_y_li[idx])
            remaining_points.remove(idx)

    # 첫 번째 좌표를 시작으로 가장 가까운 좌표 순서로 돌아다님
    current_point = remaining_points.pop(0)
    ordered_destinations.append(x_y_li[current_point])

    # 남은 점들을 순회하며 현재 위치에서 가장 가까운 점을 찾아서 ordered_destinations에 추가
    while remaining_points:
        closest_point = None
        closest_distance = float("inf")
        for point in remaining_points:
            distance = haversine(x_y_li[current_point], x_y_li[point])
            if distance < closest_distance:
                closest_distance = distance
                closest_point = point
        ordered_destinations.append(x_y_li[closest_point])
        current_point = closest_point
        remaining_points.remove(closest_point)

    # 목적지 리스트를 만듦
    answer_li = [title_li[x_y_li.index(item)] for item in ordered_destinations]

    # 최종 경로의 총 거리를 계산
    total_km = total_distance(ordered_destinations)

    openai_data = []

    # OpenAI에 전달할 데이터를 만듦
    for i in answer_li:
        idx = title_li.index(i)
        openai_data.append((i, location_li[idx]))

    data = {
        "title_list": answer_li,
        "total_km": total_km,
        "x_y_list": ordered_destinations,
    }

    # AI 추천 데이터를 가져옴
    recommend = open_ai(openai_data)

    # 웹 크롤링 데이터를 가져옴
    crawling = crawling_data(answer_li)

    data["answer"] = recommend
    data["crawling"] = crawling
    end = datetime.now()  # 종료 시간을 기록.
    print("all", end - start)  # 전체 실행 시간을 출력
    return data


def open_ai(location_li):
    # 회원 정보 기준으로 role 추가?
    start = datetime.now()

    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "추천해주세요!"},
    ]

    answer_li = []

    q_str = ""

    for idx, location in enumerate(location_li):
        q_str += (
            f"{location[1]}에 위치한 {location[0]} 주변에 추천 할 만한 장소 1곳 알려 주세요! 설명과 이동시간을 같이요!"
            f'이것에 대한 답변은 반드시 "{idx}번:" 형식을 붙여서 답변 해주세요!'
        )

    if location_li:
        messages.append(
            {
                "role": "user",
                "content": f"내가 이전에 했던 말은 잊고, 대답도 하지 말아줘!! 정보만 주면 됩니다. {q_str}",
            }
        )

    response = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=messages)
    answer_li.append(response.choices[0].message.content)

    end = datetime.now()

    li = []

    for string in answer_li[0].split("\n"):
        if ": " in string:
            li.append(string.split(": ", 1)[1])

    return li


def crawling_data(answer_li):
    start = datetime.now()
    data_li = []

    for i in answer_li:
        # 검색 결과의 URL을 저장
        url = "https://search.naver.com/search.naver?where=view&sm=tab_jum&query=" + i

        # requests 패키지를 이용해 URL의 HTML 문서를 가져옴
        response = requests.get(url)
        html_text = response.text

        # HTML을 파싱하고, 'soup' 변수에 저장
        soup = bs(html_text, "html.parser")

        # 첫 번째 링크
        link = soup.select_one(".title_link")

        # href 속성을 가져와 data_li에 추가
        if link:
            href = link.get("href")
            data_li.append(href)
        else:
            data_li.append("X")

    end = datetime.now()
    print("crawling", end - start)
    print(data_li)
    return data_li
