import requests
r = requests.get('http://192.168.27.131:5000/api/CloseFireWallPort', auth=('Brandon', 'python'))
r.text
