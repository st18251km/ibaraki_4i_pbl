import requests

response = requests.post('http://localhost:5000/add_student', data={'name': 'ほげ太郎', 'data': '2021-11-11'})
print(response.status_code)    # HTTPのステータスコード取得
print(response.text)    # レスポンスのHTMLを文字列で取得