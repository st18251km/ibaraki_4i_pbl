# 必要なライブラリのインストール

```
$ pip3 install -r requirements.txt
```

# 環境変数の設定

### Macの人

`$ ~/.bash_profile` 

に以下の設定を行わないといけない。開発環境なので適当な文字列

```
export FLASK_SECRET=hogehoge
export FLASK_AES_SECRET=hogehoge
export LINE_CHANNEL_ACCESS_TOKEN=hogehoge
export LINE_CHANNEL_SECRET=hogehoge
```

### Windowsの人

システム環境変数の設定から頑張って

# DB初期化方法

```
$ python3

>> from main import db
>> db.create_all()
```

