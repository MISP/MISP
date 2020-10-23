import urllib.request
import urllib.error
import os

for first_part in [hex(i)[2:] for i in range(0x1F1E6, 0x1F1FF + 1)]:
    for second_part in [hex(i)[2:] for i in range(0x1F1E6, 0x1F1FF + 1)]:
        file_name = "../app/webroot/img/flags/{}-{}.svg".format(first_part, second_part)
        if os.path.exists(file_name):
            continue

        url = "https://raw.githubusercontent.com/twitter/twemoji/master/assets/svg/{}-{}.svg".format(first_part, second_part)
        file_name = "../app/webroot/img/flags/{}-{}.svg".format(first_part, second_part)
        try:
            urllib.request.urlretrieve(url, file_name)
            print("Downloaded flag {}-{}".format(first_part, second_part))
        except urllib.error.HTTPError:
            pass
