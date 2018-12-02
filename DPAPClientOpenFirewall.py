import requests
r = requests.get('http://192.168.27.131:5000/api/OpenFireWallPort', auth=('Brandon', 'python'))
r.text
